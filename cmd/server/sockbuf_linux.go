//go:build linux

package main

import (
	"log"
	"net"
	"syscall"
)

// udpSockBuffers 读回 UDP socket 实际生效的接收/发送缓冲区。
// SetReadBuffer/SetWriteBuffer 会被 net.core.rmem_max/wmem_max 静默截断，
// 且内核返回值含簿记开销（约 2 倍请求值），必须读回确认，不能假设设置成功。
func udpSockBuffers(c *net.UDPConn) (rcv, snd int, err error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	ctrlErr := raw.Control(func(fd uintptr) {
		r, e := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		if e != nil {
			err = e
			return
		}
		w, e := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
		if e != nil {
			err = e
			return
		}
		rcv, snd = r, w
	})
	if ctrlErr != nil {
		return 0, 0, ctrlErr
	}
	return
}

func logSockBuffers(c *net.UDPConn, want int) {
	rcv, snd, err := udpSockBuffers(c)
	if err != nil {
		log.Printf("warn: read back udp socket buffers: %v", err)
		return
	}
	log.Printf("udp socket buffers: request=%d actual_rcv=%d actual_snd=%d (内核报含簿记开销, 若远小于请求需提高 rmem_max/wmem_max)",
		want, rcv, snd)
}
