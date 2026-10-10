//go:build linux

package main

import (
	"os/exec"
	"strconv"
	"strings"
)

// ListenPort 表示服务器本机正在监听的端口（用于后台检测端口是否被本机服务占用）。
type ListenPort struct {
	Proto string `json:"proto"` // tcp / udp
	Port  int    `json:"port"`
	Proc  string `json:"proc"` // 进程名（root 运行时可取到）
}

// listListenPorts 通过 ss 列出本机 TCP/UDP 监听端口。
func listListenPorts() []ListenPort {
	out, err := exec.Command("ss", "-H", "-l", "-t", "-u", "-n", "-p").Output()
	if err != nil {
		// 某些精简环境无 -p 权限或无 ss
		out, err = exec.Command("ss", "-H", "-l", "-t", "-u", "-n").Output()
		if err != nil {
			return nil
		}
	}
	seen := map[string]bool{}
	var result []ListenPort
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := "tcp"
		if strings.HasPrefix(fields[0], "udp") {
			proto = "udp"
		}
		// Local Address:Port 在第 5 列（Netid State Recv-Q Send-Q Local Peer ...）
		local := fields[4]
		idx := strings.LastIndex(local, ":")
		if idx < 0 {
			continue
		}
		portStr := local[idx+1:]
		// 去掉 IPv6 可能的 %scope 等
		portStr = strings.Trim(portStr, "[]")
		port, err := strconv.Atoi(portStr)
		if err != nil || port == 0 {
			continue
		}
		proc := ""
		for _, f := range fields[5:] {
			if i := strings.Index(f, "users:(("); i >= 0 {
				rest := f[i+len("users:((\""):]
				if j := strings.Index(rest, "\""); j > 0 {
					proc = rest[:j]
				}
				break
			}
		}
		key := proto + ":" + strconv.Itoa(port)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, ListenPort{Proto: proto, Port: port, Proc: proc})
	}
	return result
}

// checkPorts 返回给定协议端口段中被本机其他服务占用的端口（最多 limit 个）。
func checkLocalOccupied(proto string, start, end, limit int) []ListenPort {
	if limit <= 0 {
		limit = 50
	}
	all := listListenPorts()
	var hit []ListenPort
	for _, lp := range all {
		if lp.Proto != proto || lp.Port < start || lp.Port > end {
			continue
		}
		hit = append(hit, lp)
		if len(hit) >= limit {
			break
		}
	}
	return hit
}
