package common

import (
	"sync"
	"time"
)

// Pacer 是 goroutine 安全的令牌桶限速器，用于平滑隧道 UDP 发送。
// 背景：大量家用路由器/运营商会对单条 UDP 流做令牌桶整形（常见阈值约
// 700~1000 pps），突发超桶会被排队甚至整批丢弃，TCP 表现为秒级卡顿。
// 在内核排队之前主动把数据报均匀化，可避免被链路整形。
type Pacer struct {
	mu     sync.Mutex
	rate   float64 // 每秒令牌数（包/秒）
	burst  float64 // 桶容量（允许的瞬时突发包数）
	tokens float64
	last   time.Time
}

func NewPacer(ratePerSec, burst int) *Pacer {
	if ratePerSec <= 0 {
		return &Pacer{rate: 0}
	}
	if burst < 1 {
		burst = 1
	}
	return &Pacer{rate: float64(ratePerSec), burst: float64(burst)}
}

// Enabled 返回是否启用限速。
func (p *Pacer) Enabled() bool { return p.rate > 0 }

// Wait 阻塞到获得一个发送令牌；未启用时立即返回。
func (p *Pacer) Wait() {
	if p.rate <= 0 {
		return
	}
	for {
		p.mu.Lock()
		now := time.Now()
		if p.last.IsZero() {
			p.last = now
			p.tokens = p.burst
		}
		p.tokens += now.Sub(p.last).Seconds() * p.rate
		if p.tokens > p.burst {
			p.tokens = p.burst
		}
		p.last = now
		if p.tokens >= 1 {
			p.tokens--
			p.mu.Unlock()
			return
		}
		wait := time.Duration((1 - p.tokens) / p.rate * float64(time.Second))
		p.mu.Unlock()
		time.Sleep(wait)
	}
}
