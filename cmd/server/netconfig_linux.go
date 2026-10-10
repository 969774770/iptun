//go:build linux

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

const natChain = "IPTUN_DNAT"

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runQuiet(name string, args ...string) { _ = run(name, args...) }

// wanInfo 为服务器主网卡信息。
type wanInfo struct {
	Dev     string
	IP      string
	Prefix  string
	Gateway string
}

func detectWAN() (*wanInfo, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return nil, err
	}
	w := &wanInfo{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "default" {
			continue
		}
		for i := 0; i < len(fields)-1; i++ {
			switch fields[i] {
			case "via":
				w.Gateway = fields[i+1]
			case "dev":
				w.Dev = fields[i+1]
			}
		}
		if w.Dev != "" {
			break
		}
	}
	if w.Dev == "" {
		return nil, fmt.Errorf("cannot detect default WAN device")
	}
	aout, err := exec.Command("ip", "-4", "-o", "addr", "show", "dev", w.Dev).Output()
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(aout), "\n") {
		for _, f := range strings.Fields(line) {
			if strings.Contains(f, "/") {
				parts := strings.SplitN(f, "/", 2)
				if parts[0] != "" && !strings.HasPrefix(parts[0], "169.254") {
					w.IP = parts[0]
					w.Prefix = parts[1]
					return w, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("cannot detect WAN address on %s", w.Dev)
}

func ipt(args ...string) error { return run("iptables", args...) }

func ruleExists(table string, args []string) bool {
	check := make([]string, 0, len(args)+2)
	check = append(check, "-t", table)
	for _, a := range args {
		if a == "-A" {
			check = append(check, "-C")
		} else {
			check = append(check, a)
		}
	}
	return exec.Command("iptables", check...).Run() == nil
}

// setupTunAddress 给 TUN 配置服务端地址，使整个落地网段 on-link 指向 TUN。
func setupTunAddress(tunName, serverIP string, prefix int) error {
	// 先删后加，幂等
	_ = run("ip", "addr", "del", fmt.Sprintf("%s/%d", serverIP, prefix), "dev", tunName)
	return run("ip", "addr", "add", fmt.Sprintf("%s/%d", serverIP, prefix), "dev", tunName)
}

// setupNetworking 依据客户端列表生成"端口段 -> 落地地址"的 DNAT 规则。
// 支持热更新：整体清空重建自定义链（原子性由 iptables-restore 更好，此处规模小可接受）。
// webPort 是本机 Web 控制台端口，必须在端口段分流之前 RETURN，否则会被自己的规则劫持进隧道。
func setupNetworking(w *wanInfo, tunName string, tunnelPort, webPort, mss int, cfg *NodeConfig) error {
	runQuiet("sysctl", "-w", "net.ipv4.ip_forward=1")
	runQuiet("sysctl", "-w", "net.ipv4.conf.all.rp_filter=2")
	runQuiet("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", w.Dev))
	runQuiet("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", tunName))

	if err := setupTunAddress(tunName, cfg.TunServerIP, cfg.TunPrefix); err != nil {
		return err
	}

	// nat 链重建
	_ = ipt("-t", "nat", "-F", natChain)
	if err := ipt("-t", "nat", "-N", natChain); err != nil && !strings.Contains(err.Error(), "Chain already exists") {
		return err
	}

	// 规则顺序决定哪些入站流量留在本机、哪些进隧道：
	//
	//  1) 动态强制保留 3 个端口（值全部来自实时配置，不写死数字）：
	//       SSH(22)、Web 面板(webPort)、隧道(tunnelPort/UDP)
	//  2) -m socket：凡是本机【当前有监听 socket】的端口一律留本地。
	//       这自动覆盖 DNS(53)/DHCP(67,68)/chrony(323) 等所有系统服务——
	//       无需也不应把它们写进清单；转发这些会导致服务器失联/解析失败。
	//  3) 其余一切才按客户端端口段 DNAT 进隧道。
	mustKeep := [][]string{
		{"-p", "tcp", "--dport", "22", "-j", "RETURN"},
		{"-p", "tcp", "--dport", fmt.Sprint(webPort), "-j", "RETURN"},
		{"-p", "udp", "--dport", fmt.Sprint(tunnelPort), "-j", "RETURN"},
	}
	headRules := [][]string{
		{"-m", "socket", "-j", "RETURN"},
	}
	headRules = append(headRules, mustKeep...)
	for _, r := range headRules {
		if err := ipt(append([]string{"-t", "nat", "-A", natChain}, r...)...); err != nil {
			return err
		}
	}

	// 每个客户端的端口段规则
	icmpDone := false
	for _, cl := range cfg.Clients {
		if !cl.Enabled {
			continue
		}
		for _, r := range cl.Rules {
			portRange := fmt.Sprintf("%d:%d", r.PortStart, r.PortEnd)
			switch r.Proto {
			case "tcp":
				if err := addDNAT("tcp", portRange, cl.Landing); err != nil {
					return err
				}
			case "udp":
				if err := addDNAT("udp", portRange, cl.Landing); err != nil {
					return err
				}
			case "icmp":
				if !icmpDone {
					if err := ipt("-t", "nat", "-A", natChain, "-p", "icmp", "-j", "DNAT", "--to-destination", cl.Landing); err != nil {
						return err
					}
					icmpDone = true
				}
			case "all":
				if err := addDNAT("tcp", portRange, cl.Landing); err != nil {
					return err
				}
				if err := addDNAT("udp", portRange, cl.Landing); err != nil {
					return err
				}
				if !icmpDone {
					_ = ipt("-t", "nat", "-A", natChain, "-p", "icmp", "-j", "DNAT", "--to-destination", cl.Landing)
					icmpDone = true
				}
			}
		}
	}

	jump := []string{"-A", "PREROUTING", "-i", w.Dev, "-d", w.IP, "-j", natChain}
	if !ruleExists("nat", jump) {
		if err := ipt(append([]string{"-t", "nat"}, jump...)...); err != nil {
			return err
		}
	}

	runQuiet("iptables", "-P", "FORWARD", "ACCEPT")
	mssRules := [][]string{
		{"-A", "FORWARD", "-o", tunName, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", fmt.Sprint(mss)},
		{"-A", "FORWARD", "-i", tunName, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", fmt.Sprint(mss)},
	}
	for _, r := range mssRules {
		if !ruleExists("mangle", r) {
			_ = ipt(append([]string{"-t", "mangle"}, r...)...)
		}
	}
	return nil
}

func addDNAT(proto, portRange, landing string) error {
	return ipt("-t", "nat", "-A", natChain, "-p", proto, "--dport", portRange,
		"-j", "DNAT", "--to-destination", landing)
}

func cleanupNetworking(w *wanInfo, tunName string) {
	_ = ipt("-t", "nat", "-D", "PREROUTING", "-i", w.Dev, "-d", w.IP, "-j", natChain)
	_ = ipt("-t", "nat", "-F", natChain)
	_ = ipt("-t", "nat", "-X", natChain)
	_ = ipt("-t", "mangle", "-D", "FORWARD", "-o", tunName, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", "1320")
	_ = ipt("-t", "mangle", "-D", "FORWARD", "-i", tunName, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", "1320")
}
