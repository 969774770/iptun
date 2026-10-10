//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const svcBaseName = "IPTunClient"

// serviceName 依据 -adapter 参数派生，支持一机多客户端各装一个服务。
func serviceName() string {
	adapter := "IPTun"
	for i, a := range os.Args[1:] {
		if (a == "-adapter" || a == "--adapter") && i+2 <= len(os.Args[1:]) {
			adapter = os.Args[1:][i+1]
		}
		if strings.HasPrefix(a, "-adapter=") {
			adapter = strings.TrimPrefix(a, "-adapter=")
		}
	}
	return svcBaseName + "_" + strings.ToUpper(strings.TrimSpace(adapter))
}

// installService 注册为自启动 Windows 服务（崩溃自动重启）。
// 用法：iptun-client.exe -install -server X:7000 -token Y -adapter IPTUNA
func installService() {
	name := serviceName()
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("定位程序路径失败: %v", err)
	}
	exe, _ = filepath.Abs(exe)

	// 服务参数 = 当前除 -install 外的所有参数
	args := make([]string, 0, len(os.Args))
	for _, a := range os.Args[1:] {
		if a != "-install" {
			args = append(args, a)
		}
	}

	m, err := mgr.Connect()
	if err != nil {
		log.Fatalf("打开服务管理器失败（请用管理员身份运行）: %v", err)
	}
	defer m.Disconnect()

	if old, err := m.OpenService(name); err == nil {
		old.Delete()
		old.Close()
	}

	cfg := mgr.Config{
		DisplayName:  "iptun 公网IP落地客户端 (" + name + ")",
		Description:  "加密 UDP 三层隧道，将云服务器端口段落地到本机，访问者真实 IP 透传",
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	}
	s, err := m.CreateService(name, exe, cfg, args...)
	if err != nil {
		log.Fatalf("创建服务失败: %v", err)
	}
	defer s.Close()

	// 崩溃 5 秒后自动重启
	recov := []mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5000}}
	if err := s.SetRecoveryActions(recov, 86400); err != nil {
		log.Printf("警告: 设置恢复策略失败: %v", err)
	}

	if err := eventlog.InstallAsEventCreate(name, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			log.Printf("警告: 注册事件日志失败: %v", err)
		}
	}

	fmt.Printf("服务 %s 安装成功（开机自启、崩溃重启）\n", name)
	fmt.Printf("启动: sc start %s\n卸载: \"%s\" -uninstall -adapter %s\n", name, exe, extractAdapter())
}

func extractAdapter() string {
	for i, a := range os.Args[1:] {
		if a == "-adapter" && i+2 <= len(os.Args[1:]) {
			return os.Args[1:][i+1]
		}
	}
	return "IPTun"
}

// uninstallService 删除服务。
func uninstallService() {
	name := serviceName()
	m, err := mgr.Connect()
	if err != nil {
		log.Fatalf("打开服务管理器失败: %v", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		fmt.Printf("服务 %s 不存在，无需卸载\n", name)
		return
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop)
	if err := s.Delete(); err != nil {
		log.Fatalf("删除服务失败: %v", err)
	}
	_ = eventlog.Remove(name)
	fmt.Printf("服务 %s 已卸载\n", name)
}

// runAsService 是 SCM 入口。
func runAsService() {
	name := serviceName()
	if elog, err := eventlog.Open(name); err == nil {
		log.SetOutput(&eventLogWriter{elog: elog})
		defer elog.Close()
	}
	if err := svc.Run(name, &winService{}); err != nil {
		log.Printf("svc.Run: %v", err)
	}
}

// eventLogWriter 把标准日志转发到 Windows 事件查看器。
type eventLogWriter struct{ elog *eventlog.Log }

func (w *eventLogWriter) Write(p []byte) (int, error) {
	_ = w.elog.Info(uint32(os.Getpid()), strings.TrimRight(string(p), "\r\n"))
	return len(p), nil
}

type winService struct{}

func (w *winService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("服务内 panic: %v", rec)
			}
		}()
		run()
	}()

	changes <- svc.Status{State: svc.Running, Accepts: accepts}
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			log.Printf("收到停止信号，退出")
			os.Exit(0)
		}
	}
	return false, 0
}
