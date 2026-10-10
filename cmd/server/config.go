package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
)

// ClientRule 描述一条"协议+端口段"分流规则。
type ClientRule struct {
	Proto     string `json:"proto"`      // tcp / udp / icmp / all
	PortStart int    `json:"port_start"` // 1..65535（icmp 忽略）
	PortEnd   int    `json:"port_end"`
}

// ClientDef 是一个被授权客户端（Web 控制台可增删改）。
type ClientDef struct {
	Name    string       `json:"name"`
	Token   string       `json:"token"`
	Landing string       `json:"landing"` // 隧道落地地址，如 10.66.0.2
	Enabled bool         `json:"enabled"`
	Rules   []ClientRule `json:"rules"`
}

// NodeConfig 是数据面 + 控制面共用的节点配置。
type NodeConfig struct {
	mu sync.RWMutex `json:"-"`

	TunServerIP string      `json:"tun_server_ip"` // TUN 服务端地址，如 10.66.0.1
	TunPrefix   int         `json:"tun_prefix"`    // 客户端落地网段前缀，如 24
	TunnelPort  int         `json:"tunnel_port"`
	Clients     []ClientDef `json:"clients"`
}

func LoadNodeConfig(path string) (*NodeConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c NodeConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *NodeConfig) Validate() error {
	if c.TunServerIP == "" {
		c.TunServerIP = "10.66.0.1"
	}
	if c.TunPrefix == 0 {
		c.TunPrefix = 24
	}
	if net.ParseIP(c.TunServerIP).To4() == nil {
		return fmt.Errorf("bad tun_server_ip %q", c.TunServerIP)
	}
	seenToken := map[string]bool{}
	seenLanding := map[string]bool{}
	for i := range c.Clients {
		cl := &c.Clients[i]
		if cl.Name == "" || cl.Token == "" || cl.Landing == "" {
			return fmt.Errorf("client[%d] name/token/landing required", i)
		}
		if net.ParseIP(cl.Landing).To4() == nil {
			return fmt.Errorf("client %s bad landing %q", cl.Name, cl.Landing)
		}
		if seenToken[cl.Token] {
			return fmt.Errorf("duplicate token: %s", cl.Token)
		}
		if seenLanding[cl.Landing] {
			return fmt.Errorf("duplicate landing: %s", cl.Landing)
		}
		seenToken[cl.Token] = true
		seenLanding[cl.Landing] = true
		for _, r := range cl.Rules {
			if r.Proto == "icmp" {
				continue
			}
			if r.PortStart < 1 || r.PortEnd > 65535 || r.PortStart > r.PortEnd {
				return fmt.Errorf("客户端 %s 端口段非法：%d-%d", cl.Name, r.PortStart, r.PortEnd)
			}
		}
	}
	// 同一协议下端口段不得跨客户端重叠（iptables 首条命中会导致分流歧义）
	type seg struct{ name, proto string; lo, hi int }
	var segs []seg
	for i := range c.Clients {
		cl := &c.Clients[i]
		if !cl.Enabled {
			continue
		}
		for _, r := range cl.Rules {
			protos := []string{}
			switch r.Proto {
			case "tcp":
				protos = append(protos, "tcp")
			case "udp":
				protos = append(protos, "udp")
			case "all":
				protos = append(protos, "tcp", "udp")
			case "icmp":
				continue
			}
			for _, p := range protos {
				segs = append(segs, seg{cl.Name, p, r.PortStart, r.PortEnd})
			}
		}
	}
	for i := 0; i < len(segs); i++ {
		for j := i + 1; j < len(segs); j++ {
			a, b := segs[i], segs[j]
			if a.proto == b.proto && a.lo <= b.hi && b.lo <= a.hi {
				lo, hi := maxInt(a.lo, b.lo), minInt(a.hi, b.hi)
				return fmt.Errorf("端口段冲突：%s/%s 与 %s/%s 在 %d-%d 重叠",
					a.name, a.proto, b.name, b.proto, lo, hi)
			}
		}
	}
	return nil
}

func maxInt(a, b int) int { if a > b { return a }; return b }
func minInt(a, b int) int { if a < b { return a }; return b }

func (c *NodeConfig) Snapshot() []ClientDef {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]ClientDef, len(c.Clients))
	copy(out, c.Clients)
	return out
}

// FindByToken 在启用列表中按 token 查找客户端。
func (c *NodeConfig) FindByToken(token string) *ClientDef {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i := range c.Clients {
		if c.Clients[i].Enabled && c.Clients[i].Token == token {
			return &c.Clients[i]
		}
	}
	return nil
}

// DefaultClient 返回承接无端口协议（ICMP 等）的第一个启用客户端。
func (c *NodeConfig) DefaultClient() *ClientDef {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i := range c.Clients {
		for _, r := range c.Clients[i].Rules {
			if r.Proto == "icmp" || r.Proto == "all" {
				return &c.Clients[i]
			}
		}
	}
	for i := range c.Clients {
		if c.Clients[i].Enabled {
			return &c.Clients[i]
		}
	}
	return nil
}

// Replace 热更新（供 Web API 调用）：整体替换并校验。
func (c *NodeConfig) Replace(next NodeConfig) error {
	if err := next.Validate(); err != nil {
		return err
	}
	c.mu.Lock()
	c.TunServerIP = next.TunServerIP
	c.TunPrefix = next.TunPrefix
	c.Clients = next.Clients
	c.mu.Unlock()
	return nil
}
