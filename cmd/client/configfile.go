package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
)

// FileConfig 是 GUI 设置程序写入、客户端读取的本地配置（与 exe 同目录 config.json）。
type FileConfig struct {
	Server  string `json:"server"`  // 服务器隧道地址 host:port
	Token   string `json:"token"`   // 授权 Token（同时是该客户端的隧道加密根密钥）
	Adapter string `json:"adapter"` // wintun 适配器/实例名
}

// ConfigPath 返回与可执行文件同目录的 config.json。
func ConfigPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "config.json"
	}
	p, _ := filepath.Abs(exe)
	return filepath.Join(filepath.Dir(p), "config.json")
}

func LoadFileConfig() *FileConfig {
	b, err := os.ReadFile(ConfigPath())
	if err != nil {
		return &FileConfig{}
	}
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF}) // 容忍 UTF-8 BOM
	var fc FileConfig
	_ = json.Unmarshal(b, &fc)
	return &fc
}

func SaveFileConfig(fc *FileConfig) error {
	b, err := json.MarshalIndent(fc, "", "  ")
	if err != nil {
		return err
	}
	path := ConfigPath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---------------- 运行状态文件（GUI 读取） ----------------

// StatusInfo 写入 %ProgramData%\iptun\status-<adapter>.json，供 GUI 展示连接状态。
type StatusInfo struct {
	State     string `json:"state"` // connecting / connected / stopped / error
	Server    string `json:"server"`
	Adapter   string `json:"adapter"`
	LandingIP string `json:"landing_ip"`
	MTU       int    `json:"mtu"`
	PID       int    `json:"pid"`
	StartedAt string `json:"started_at"`
	LastSeen  string `json:"last_seen"`
	Message   string `json:"message"`
}

func statusDir() string {
	base := os.Getenv("PROGRAMDATA")
	if base == "" {
		base = filepath.Join(os.Getenv("SystemDrive")+"\\", "ProgramData")
	}
	return filepath.Join(base, "iptun")
}

func statusPath(adapter string) string {
	return filepath.Join(statusDir(), "status-"+sanitizeName(adapter)+".json")
}

func sanitizeName(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == filepath.Separator || r == '/' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' {
			out = append(out, '_')
		} else {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return "default"
	}
	return string(out)
}

func writeStatus(st *StatusInfo) {
	dir := statusDir()
	_ = os.MkdirAll(dir, 0755)
	b, _ := json.MarshalIndent(st, "", "  ")
	path := statusPath(st.Adapter)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err == nil {
		_ = os.Rename(tmp, path)
	}
}
