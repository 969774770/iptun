// iptun server（多客户端版）：一个公网 IP 可按"协议+端口段"分流给多个在线客户端。
// 数据面：TUN <-> 加密 UDP；控制面（Web）内嵌于同进程（见 web.go）。
package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"iptun/common"
)

var procStart = time.Now()

const passwordAlphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// randomPassword 用密码学随机数生成可读密码（去除易混淆字符）。
func randomPassword(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = passwordAlphabet[int(b[i])%len(passwordAlphabet)]
	}
	return string(b)
}

func main() {
	var (
		port       = flag.Int("port", 7000, "隧道 UDP 端口")
		tunName    = flag.String("tun", "iptun0", "TUN 设备名")
		mtu        = flag.Int("mtu", common.MTU, "TUN MTU")
		configPath = flag.String("config", "/root/iptun/clients.json", "客户端配置文件")
		webAddr    = flag.String("web", ":8443", "Web 管理界面监听地址（HTTPS）")
		webUser    = flag.String("webuser", "admin", "Web 管理员账号")
		webPass    = flag.String("webpass", "", "Web 管理员密码（留空则首次启动随机生成并打印到日志，install.sh 也会注入随机值）")
		certPath   = flag.String("cert", "", "TLS 证书 PEM 路径（留空则在配置目录自动生成自签证书）")
		keyPath    = flag.String("certkey", "", "TLS 私钥 PEM 路径")
	)
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if *webPass == "" {
		*webPass = randomPassword(16)
		log.Printf("未设置 -webpass，本次随机生成 Web 管理员密码: %s（账号 %s）", *webPass, *webUser)
	}

	cfg, err := LoadNodeConfig(*configPath)
	if err != nil {
		log.Printf("warn: load config %s: %v（使用内置示例配置）", *configPath, err)
		cfg = demoConfig(*port)
	}
	// 隧道端口以配置文件为准（后台可热修改），配置缺失时回退到 -port 参数
	if cfg.TunnelPort == 0 {
		cfg.TunnelPort = *port
	}
	tunnelPort := cfg.TunnelPort
	log.Printf("iptun server starting: udp/:%d tun=%s clients=%d web=%s", tunnelPort, *tunName, len(cfg.Clients), *webAddr)

	// 解析 Web 控制台监听端口（用于在分流规则中放行，避免被自身 DNAT 劫持）
	_, webPortStr, err := net.SplitHostPort(*webAddr)
	if err != nil {
		log.Fatalf("bad -web %q: %v", *webAddr, err)
	}
	webPort, err := strconv.Atoi(webPortStr)
	if err != nil || webPort <= 0 || webPort > 65535 {
		log.Fatalf("bad web port %q", webPortStr)
	}

	wan, err := detectWAN()
	if err != nil {
		log.Fatalf("detect WAN: %v", err)
	}
	log.Printf("WAN: dev=%s ip=%s/%s gw=%s", wan.Dev, wan.IP, wan.Prefix, wan.Gateway)

	tunFile, actualTun, err := createTUN(*tunName, *mtu)
	if err != nil {
		log.Fatalf("create tun: %v", err)
	}
	defer tunFile.Close()
	if err := setupNetworking(wan, actualTun, tunnelPort, webPort, *mtu-80, cfg); err != nil {
		log.Fatalf("setup networking: %v", err)
	}
	defer cleanupNetworking(wan, actualTun)
	log.Printf("policy routing installed for %d client(s)", len(cfg.Clients))

	addr, _ := net.ResolveUDPAddr("udp4", fmt.Sprintf(":%d", tunnelPort))
	udpConn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		log.Fatalf("listen udp: %v", err)
	}
	_ = udpConn.SetReadBuffer(8 * 1024 * 1024)
	_ = udpConn.SetWriteBuffer(8 * 1024 * 1024)

	srv := &server{
		udp:        udpConn,
		tun:        tunFile,
		tunName:    actualTun,
		wan:        wan,
		mtu:        *mtu,
		webPort:    webPort,
		cfg:        cfg,
		configPath: *configPath,
		byLanding:  map[uint32]*clientSession{},
		byAddr:     map[string]*clientSession{},
	}
	// 准备 Web TLS 证书（首次自动生成自签证书，SAN 包含公网 IP / WAN 内网 IP）
	certFile, keyFile := *certPath, *keyPath
	if certFile == "" || keyFile == "" {
		certFile = filepath.Join(filepath.Dir(*configPath), "cert.pem")
		keyFile = filepath.Join(filepath.Dir(*configPath), "key.pem")
	}
	pubIP := detectPublicIPQuick()
	sanIPs := []string{wan.IP}
	if pubIP != "" {
		sanIPs = append(sanIPs, pubIP)
	}
	if err := ensureCert(certFile, keyFile, sanIPs...); err != nil {
		log.Printf("warn: prepare TLS cert: %v（Web 将无法启动）", err)
	} else {
		log.Printf("TLS ready: %s (SAN: %v)", certFile, sanIPs)
	}

	// 后台改过的 Web 管理员账号密码（持久化文件），覆盖启动参数
	webUserFinal, webPassFinal := loadWebCreds(filepath.Dir(*configPath), *webUser, *webPass)

	go srv.readTunnel()
	go srv.readUDP()
	go srv.gcLoop()
	go srv.serveWeb(*webAddr, webUserFinal, webPassFinal, certFile, keyFile, pubIP)

	log.Printf("all systems running")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down")
}

// demoConfig 仅在 clients.json 缺失时兜底：默认不带任何已启用客户端，
// 请登录 Web 控制台创建（避免内置固定 Token 被公开后形成安全隐患）。
func demoConfig(port int) *NodeConfig {
	return &NodeConfig{
		TunServerIP: "10.66.0.1",
		TunPrefix:   24,
		TunnelPort:  port,
		Clients:     []ClientDef{},
	}
}

// ---------------- 会话注册表 ----------------

type clientSession struct {
	name     string
	landing  uint32
	addr     *net.UDPAddr
	key      *common.Session
	lastSeen atomic.Int64 // unix nano
	rxBytes  atomic.Uint64 // 客户端 -> 公网（出向）
	txBytes  atomic.Uint64 // 公网 -> 客户端（入向）
	pkts     atomic.Uint64
}

type server struct {
	connMu     sync.RWMutex
	udp        *net.UDPConn
	tun        *os.File
	tunName    string
	wan        *wanInfo
	mtu        int
	webPort    int
	cfg        *NodeConfig
	configPath string

	mu        sync.RWMutex
	byLanding map[uint32]*clientSession
	byAddr    map[string]*clientSession
}

// curUDP 返回当前隧道 UDP 连接（隧道端口热切换时会被替换）。
func (s *server) curUDP() *net.UDPConn {
	s.connMu.RLock()
	defer s.connMu.RUnlock()
	return s.udp
}

// rebindTunnel 热切换隧道监听端口：先监听新端口成功，再替换并关闭旧连接。
func (s *server) rebindTunnel(newPort int) error {
	addr, _ := net.ResolveUDPAddr("udp4", fmt.Sprintf(":%d", newPort))
	c, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("端口 %d 无法监听（可能被占用）: %w", newPort, err)
	}
	_ = c.SetReadBuffer(8 * 1024 * 1024)
	_ = c.SetWriteBuffer(8 * 1024 * 1024)

	s.connMu.Lock()
	old := s.udp
	s.udp = c
	s.connMu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	log.Printf("tunnel port switched to udp/%d", newPort)
	return nil
}

func landingKey(ip string) uint32 {
	return binary.BigEndian.Uint32(net.ParseIP(ip).To4())
}

func ipv4Dst(pkt []byte) uint32 {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(pkt[16:20])
}

func (s *server) putSession(sess *clientSession) {
	s.mu.Lock()
	// 顶掉同落地地址的旧会话
	if old := s.byLanding[sess.landing]; old != nil {
		delete(s.byAddr, old.addr.String())
	}
	s.byLanding[sess.landing] = sess
	s.byAddr[sess.addr.String()] = sess
	s.mu.Unlock()
}

func (s *server) getByLanding(k uint32) *clientSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byLanding[k]
}

func (s *server) getByAddr(a string) *clientSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byAddr[a]
}

func (s *server) allSessions() []*clientSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*clientSession, 0, len(s.byLanding))
	seen := map[*clientSession]bool{}
	for _, v := range s.byLanding {
		if !seen[v] {
			out = append(out, v)
			seen[v] = true
		}
	}
	return out
}

func (s *server) gcLoop() {
	for range time.Tick(5 * time.Second) {
		now := time.Now()
		s.mu.Lock()
		for k, v := range s.byLanding {
			if now.UnixNano()-v.lastSeen.Load() > int64(90*time.Second) {
				delete(s.byLanding, k)
				delete(s.byAddr, v.addr.String())
				log.Printf("client %s (%s) offline", v.name, v.addr)
			}
		}
		s.mu.Unlock()
	}
}

// reloadNetworking 配置热更新后重建规则（供 Web 调用）。
func (s *server) reloadNetworking() error {
	return setupNetworking(s.wan, s.tunName, s.cfg.TunnelPort, s.webPort, s.mtu-80, s.cfg)
}

// ---------------- UDP 侧 ----------------

func (s *server) readUDP() {
	buf := make([]byte, common.MaxPacket+64)
	for {
		conn := s.curUDP()
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			// 连接已被热切换（旧 socket 关闭）：换新连接继续读，不退出
			if conn != s.curUDP() {
				continue
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		if len(raw) < common.HeaderSize {
			continue
		}
		if raw[0] == common.TypeHandshake {
			s.handleHandshake(raw, raddr)
			continue
		}
		sess := s.getByAddr(raddr.String())
		if sess == nil {
			continue
		}
		t, body, err := sess.key.Open(raw)
		if err != nil {
			continue
		}
		sess.lastSeen.Store(time.Now().UnixNano())
		switch t {
		case common.TypePing:
			pkt := sess.key.Seal(common.TypePong, nil, common.RandomPrefix())
			_, _ = conn.WriteToUDP(pkt, raddr)
		case common.TypeData:
			if len(body) == 0 {
				continue
			}
			sess.rxBytes.Add(uint64(len(body)))
			if _, err := s.tun.Write(body); err != nil {
				log.Printf("tun write: %v", err)
			}
		}
	}
}

// handleHandshake 处理客户端握手。
// Token 既是身份凭证又是该客户端的传输根密钥：握手帧用 Token 派生的引导密钥加密。
// 服务端不预先知道是哪个客户端，因此遍历启用客户端的 Token 尝试解密，成功者即匹配
// （GCM 认证失败立即返回；客户端数量级下开销可忽略）。
func (s *server) handleHandshake(raw []byte, raddr *net.UDPAddr) {
	var matched *ClientDef
	var clientNonce []byte
	var bootSession *common.Session

	for _, cl := range s.cfg.Snapshot() {
		if !cl.Enabled {
			continue
		}
		boot, err := common.NewSession(common.NewBootstrapKey([]byte(cl.Token)))
		if err != nil {
			continue
		}
		_, body, err := boot.Open(raw)
		if err != nil || len(body) != 16 {
			continue
		}
		matched = &cl
		clientNonce = body
		bootSession = boot
		break
	}
	if matched == nil {
		log.Printf("handshake rejected from %s: no token matched", raddr)
		return
	}

	serverNonce, _ := common.RandomNonce16()
	key, err := common.DeriveSessionKey([]byte(matched.Token), clientNonce, serverNonce)
	if err != nil {
		return
	}
	sess, err := common.NewSession(key)
	if err != nil {
		return
	}
	s.cfg.mu.RLock()
	tunnelPort := s.cfg.TunnelPort
	s.cfg.mu.RUnlock()
	cfgReply := common.Config{
		TunIP:      matched.Landing,
		Prefix:     32,
		MTU:        s.mtu,
		ServerPort: tunnelPort,
	}
	reply := append(append([]byte{}, serverNonce...), common.EncodeConfig(&cfgReply)...)
	pkt := bootSession.Seal(common.TypeReply, reply, common.RandomPrefix())
	if _, err := s.curUDP().WriteToUDP(pkt, raddr); err != nil {
		return
	}

	cs := &clientSession{name: matched.Name, landing: landingKey(matched.Landing), addr: raddr, key: sess}
	cs.lastSeen.Store(time.Now().UnixNano())
	s.putSession(cs)
	log.Printf("client %s online: %s -> landing %s", matched.Name, raddr, matched.Landing)
}

// ---------------- TUN 侧 ----------------

func (s *server) readTunnel() {
	buf := make([]byte, s.mtu+64)
	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("tun read: %v", err)
			}
			return
		}
		dst := ipv4Dst(buf[:n])
		if dst == 0 {
			continue
		}
		sess := s.getByLanding(dst)
		if sess == nil {
			continue
		}
		pkt := sess.key.Seal(common.TypeData, buf[:n], common.RandomPrefix())
		if _, err := s.curUDP().WriteToUDP(pkt, sess.addr); err == nil {
			sess.txBytes.Add(uint64(n))
			sess.pkts.Add(1)
		}
	}
}
