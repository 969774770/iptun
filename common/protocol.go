// Package common 定义 iptun 客户端与服务端共用的隧道协议。
//
// 线路：UDP。每个数据报格式：
//
//	[type:1][nonce:12][AES-256-GCM(key, nonce, plaintext) => ciphertext+16B tag]
//
// 每个客户端的 Token 既是身份凭证，也是该客户端独立的加密根密钥：
// 握手前使用引导密钥 bootstrapKey = SHA256(Token)；
// 握手成功后数据信道使用会话密钥 HKDF-SHA256(Token, clientNonce||serverNonce)，
// 重连时随机数更换，会话密钥自动轮换。
package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	TypeHandshake byte = 1 // C->S: clientNonce(16)
	TypeReply     byte = 2 // S->C: serverNonce(16) + ConfigJSON
	TypeData      byte = 3 // 双向: 裸 IP 包
	TypePing      byte = 4 // 心跳
	TypePong      byte = 5 // 心跳应答
)

const (
	HeaderSize = 1 + 12 // type + nonce
	GCMTagSize = 16
	MaxPacket  = 2048
	// 虚拟链路 MTU。封装开销：内层IP包 + 29(type1+nonce12+tag16) + 8(UDP) + 20(外层IP) = 57。
	// 取 1340 => 外层 1397，可在 1400 的低 MTU 路径（PPPoE/IPsec/L2TP 上联、部分移动网络）
	// 上不分片不丢包；禁止调大到 1343 以上，否则满载包会触发分片/PMTU 黑洞，表现为秒级卡顿。
	MTU = 1340
)

// Config 是服务端握手时下发给客户端的虚拟网卡配置。
type Config struct {
	TunIP      string `json:"tun_ip"`    // wintun 上要配置的地址（在 NAT 云环境下是服务器内网 IP）
	Prefix     int    `json:"prefix"`    // 地址前缀长度（客户端按 /32 使用即可）
	ServerIP   string `json:"server_ip"` // 隧道对端公网/直连地址（供客户端添加防环回路由）
	ServerPort int    `json:"server_port"`
	MTU        int    `json:"mtu"`
}

// Frame 表示一帧已解析的隧道消息。
type Frame struct {
	Type byte
	Body []byte
}

// Session 封装一对加解密状态（两端相同结构，方向各自独立 nonce 计数器）。
type Session struct {
	aead cipher.AEAD
	mu   sync.Mutex // 保护 seq；客户端数据与心跳两个 goroutine 会并发 Seal
	seq  uint64
}

// NewBootstrapKey 由客户端 Token 生成握手引导密钥。
func NewBootstrapKey(token []byte) []byte {
	sum := sha256.Sum256(token)
	return sum[:]
}

// DeriveSessionKey 由客户端 Token 与双方随机数派生数据信道会话密钥。
func DeriveSessionKey(token, clientNonce, serverNonce []byte) ([]byte, error) {
	if len(clientNonce) != 16 || len(serverNonce) != 16 {
		return nil, errors.New("nonce length must be 16")
	}
	salt := make([]byte, 0, 32)
	salt = append(salt, clientNonce...)
	salt = append(salt, serverNonce...)
	r := hkdf.New(sha256.New, token, salt, []byte("iptun-v1-data"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func NewSession(key []byte) (*Session, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Session{aead: aead}, nil
}

// nextNonce 生成 12 字节 nonce：4 字节随机前缀 + 8 字节计数器，避免两端 nonce 撞车。
func (s *Session) nextNonce(prefix [4]byte) []byte {
	s.mu.Lock()
	s.seq++
	seq := s.seq
	s.mu.Unlock()
	n := make([]byte, 12)
	copy(n[:4], prefix[:])
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}

// Seal 用会话密钥加密一帧。
func (s *Session) Seal(t byte, plain []byte, prefix [4]byte) []byte {
	n := s.nextNonce(prefix)
	out := make([]byte, 0, HeaderSize+len(plain)+GCMTagSize)
	out = append(out, t)
	out = append(out, n...)
	out = s.aead.Seal(out, n, plain, []byte{t})
	return out
}

// Open 解密并校验一帧。
func (s *Session) Open(raw []byte) (byte, []byte, error) {
	if len(raw) < HeaderSize+GCMTagSize {
		return 0, nil, fmt.Errorf("frame too short: %d", len(raw))
	}
	t := raw[0]
	n := raw[1:HeaderSize]
	ct := raw[HeaderSize:]
	pt, err := s.aead.Open(nil, n, ct, []byte{t})
	if err != nil {
		return 0, nil, err
	}
	return t, pt, nil
}

func RandomNonce16() ([]byte, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	return b, err
}

func RandomPrefix() [4]byte {
	var p [4]byte
	_, _ = rand.Read(p[:])
	return p
}

// EncodeConfig / DecodeConfig
func EncodeConfig(c *Config) []byte {
	b, _ := json.Marshal(c)
	return b
}

func DecodeConfig(b []byte) (*Config, error) {
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Conn 是带加解密的 UDP 会话便捷封装。
type Conn struct {
	conn    *net.UDPConn
	session *Session
	prefix  [4]byte
}

func NewConn(c *net.UDPConn, key []byte) (*Conn, error) {
	s, err := NewSession(key)
	if err != nil {
		return nil, err
	}
	return &Conn{conn: c, session: s, prefix: RandomPrefix()}, nil
}

func (c *Conn) WriteTo(t byte, body []byte, addr *net.UDPAddr) error {
	pkt := c.session.Seal(t, body, c.prefix)
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := c.conn.WriteToUDP(pkt, addr)
	return err
}

func (c *Conn) ReadFrom(buf []byte) (byte, []byte, *net.UDPAddr, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(120 * time.Second))
	n, addr, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, nil, err
	}
	t, body, err := c.session.Open(buf[:n])
	if err != nil {
		return 0, nil, addr, err
	}
	return t, body, addr, nil
}
