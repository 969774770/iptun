//go:build linux

package main

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type SysStats struct {
	Hostname   string  `json:"hostname"`
	OS         string  `json:"os"`
	Kernel     string  `json:"kernel"`
	CPUCores   int     `json:"cpu_cores"`
	Load1      float64 `json:"load1"`
	MemTotalMB int     `json:"mem_total_mb"`
	MemUsedMB  int     `json:"mem_used_mb"`
	MemUsedPct float64 `json:"mem_used_pct"`
	UptimeSec  int64   `json:"uptime_sec"`
}

func collectSysStats() SysStats {
	st := SysStats{CPUCores: runtime.NumCPU(), UptimeSec: int64(time.Since(procStart).Seconds())}
	st.Hostname, _ = os.Hostname()
	if b, err := os.ReadFile("/proc/sys/kernel/ostype"); err == nil {
		st.OS = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		st.Kernel = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(b))
		if len(fields) > 0 {
			st.Load1, _ = strconv.ParseFloat(fields[0], 64)
		}
	}
	var si syscall.Sysinfo_t
	if err := syscall.Sysinfo(&si); err == nil {
		unit := int64(si.Unit)
		total := int64(si.Totalram) * unit
		free := int64(si.Freeram) * unit
		st.MemTotalMB = int(total / 1024 / 1024)
		st.MemUsedMB = int((total - free) / 1024 / 1024)
		if total > 0 {
			st.MemUsedPct = float64(total-free) * 100 / float64(total)
		}
	}
	return st
}
