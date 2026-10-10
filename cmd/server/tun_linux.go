//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	cIFF_TUN       = 0x0001
	cIFF_NO_PI     = 0x1000
	cTUNSETIFF     = 0x400454ca
	cTUNSETPERSIST = 0x400454cb
)

type ifreqFlags struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	_     [unsafe.Sizeof(unix.Ifreq{}) - unsafe.Sizeof(uint16(0)) - unix.IFNAMSIZ]byte
}

// createTUN 创建/打开一个 TUN 设备（三层，无 packet info），返回 *os.File。
func createTUN(name string, mtu int) (*os.File, string, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", fmt.Errorf("open /dev/net/tun: %w", err)
	}

	var req ifreqFlags
	copy(req.Name[:unix.IFNAMSIZ-1], name)
	req.Flags = cIFF_TUN | cIFF_NO_PI

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(cTUNSETIFF), uintptr(unsafe.Pointer(&req))); errno != 0 {
		unix.Close(fd)
		return nil, "", fmt.Errorf("TUNSETIFF: %w", errno)
	}
	actual := string(bytes.TrimRight(req.Name[:], "\x00"))

	// txqueuelen 加大：默认 500 在突发时会导致写 TUN 阻塞/丢包
	if err := run("ip", "link", "set", "dev", actual, "up", "mtu", fmt.Sprint(mtu), "txqueuelen", "1000"); err != nil {
		unix.Close(fd)
		return nil, "", err
	}
	return os.NewFile(uintptr(fd), "/dev/net/tun"), actual, nil
}
