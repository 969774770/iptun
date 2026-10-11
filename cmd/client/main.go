// iptun client（Windows）：通过 wintun 建立三层虚拟网卡，
// 与 Linux 服务端建立加密 UDP 隧道，把服务器公网 IP "落地"到本机。
//
// 关键策略（保证默认上网不变且隧道不环回）：
//  1. wintun 接口 metric 调到最高，默认路由 metric=999，不抢物理网卡；
//  2. 依赖 Windows 强主机发送模型：发给落地 IP 的连接，其应答只从 wintun 出；
//  3. 为服务器 IP 添加 /32 主机路由走物理网关，且隧道 UDP socket 绑定物理网卡 IP。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"iptun/common"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.zx2c4.com/wintun"
)

func main() {
	// 服务安装/卸载子命令（不走 flag.Parse）
	for _, a := range os.Args[1:] {
		switch a {
		case "-install":
			installService()
			return
		case "-uninstall":
			uninstallService()
			return
		}
	}
	// SCM 启动时进入服务模式（与普通控制台模式共用同一套 run 逻辑）
	if isSvc, err := svc.IsWindowsService(); err == nil && isSvc {
		runAsService()
		return
	}
	run()
}

func run() {
	// 配置优先级：命令行参数 > 同目录 config.json（GUI 写入）> 内置默认
	fc := LoadFileConfig()
	var (
		server    = flag.String("server", fc.Server, "服务器隧道地址 host:port（如 1.2.3.4:7000）")
		token     = flag.String("token", fc.Token, "授权 Token（同时是该客户端的隧道加密密钥，在 Web 控制台创建后获得）")
		adapterNm = flag.String("adapter", fc.Adapter, "wintun 适配器名称（一机多客户端时分别指定，如 IPTUNA）")
		pace      = flag.Int("pace", 800, "隧道 UDP 发送速率上限（包/秒），平滑突发避免被运营商整形，0=关闭")
	)
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if *server == "" {
		*server = "YOUR_SERVER_IP:7000"
	}
	if *adapterNm == "" {
		*adapterNm = "IPTun"
	}
	startedAt := time.Now().Format("2006-01-02 15:04:05")
	writeStatus(&StatusInfo{State: "connecting", Server: *server, Adapter: *adapterNm,
		PID: os.Getpid(), StartedAt: startedAt, LastSeen: startedAt, Message: "正在连接服务器"})
	defer func() {
		writeStatus(&StatusInfo{State: "stopped", Server: *server, Adapter: *adapterNm,
			PID: os.Getpid(), StartedAt: startedAt, LastSeen: time.Now().Format("2006-01-02 15:04:05"),
			Message: "客户端已停止"})
	}()

	serverHost, _, err := net.SplitHostPort(*server)
	if err != nil {
		log.Fatalf("bad -server: %v", err)
	}
	serverIP := net.ParseIP(serverHost).To4()
	if serverIP == nil {
		log.Fatalf("server must be an IPv4 address: %s", serverHost)
	}

	// 物理网卡（索引/网关/IP）在传输重连循环内动态发现：
	// 换网、DHCP 换 IP、网卡抖动后重连可自动适配，无需重启服务。

	// 1) 创建 wintun 适配器（仅需管理员/驱动，与网络无关，失败直接退出）
	adapter, err := wintun.CreateAdapter(*adapterNm, "iptun", nil)
	if err != nil {
		log.Fatalf("create wintun adapter: %v（确认 wintun.dll 与程序同目录且以管理员运行）", err)
	}
	defer adapter.Close()

	tunIdx := adapterIndex(*adapterNm)
	log.Printf("wintun adapter %s ready, ifIndex=%s", *adapterNm, tunIdx)

	session, err := adapter.StartSession(0x400000) // 4 MiB ring
	if err != nil {
		log.Fatalf("start wintun session: %v", err)
	}
	defer session.End()

	bootSess, _ := common.NewSession(common.NewBootstrapKey([]byte(*token)))
	// 初始握手使用独立 boot 实例（nonce 计数器从 1 起）；推进该实例计数避免 nonce 区间重叠
	for i := 0; i < 1024; i++ {
		bootSess.Seal(common.TypePing, nil, common.RandomPrefix())
	}
	c := &client{
		session:   session,
		boot:      bootSess,
		token:     *token,
		mtu:       common.MTU,
		server:    *server,
		adapter:   *adapterNm,
		tunIdx:    tunIdx,
		serverIP:  serverIP.String(),
		startedAt: startedAt,
		pacer:     common.NewPacer(*pace, 256),
	}

	// 传输层（拨号/握手/读取）独立重连；wintun 侧收发与心跳常驻
	go c.transportLoop()
	c.run()
}

type client struct {
	udp       *net.UDPConn
	connMu    sync.RWMutex
	session   wintun.Session
	mu        sync.Mutex
	data      *common.Session
	pending   []byte // 重连中的 clientNonce
	boot      *common.Session
	token     string
	mtu       int
	server    string
	adapter   string
	tunIdx    string
	serverIP  string
	landing   string
	startedAt string
	pacer     *common.Pacer
	activity  atomic.Int64
}

func (c *client) curUDP() *net.UDPConn {
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	return c.udp
}

func (c *client) run() {
	go c.wintunToServer()
	go c.heartbeat()
	select {}
}

func (c *client) currentKey() *common.Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data
}

// transportLoop 持续维护"拨号 → 握手 → 配置网络 → 读取"的传输生命周期：
// 读取返回错误（断网/NAT 失效/物理网卡变化）或握手失败时，退避后整体重来。
// wintun 适配器与会话保持不变，业务无需重启服务即可自愈。
func (c *client) transportLoop() {
	backoff := time.Second
	for {
		phys, err := detectPhysicalAdapter()
		if err != nil {
			log.Printf("waiting for physical network: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}

		laddr, _ := net.ResolveUDPAddr("udp4", net.JoinHostPort(phys.IP, "0"))
		raddr, _ := net.ResolveUDPAddr("udp4", c.server)
		conn, err := net.DialUDP("udp4", laddr, raddr)
		if err != nil {
			log.Printf("dial server: %v", err)
			time.Sleep(backoff)
			if backoff < 10*time.Second {
				backoff *= 2
			}
			continue
		}
		_ = conn.SetReadBuffer(8 * 1024 * 1024)
		_ = conn.SetWriteBuffer(8 * 1024 * 1024)

		cfg, sess, err := handshake(conn, c.token)
		if err != nil {
			_ = conn.Close()
			log.Printf("handshake: %v", err)
			time.Sleep(backoff)
			if backoff < 10*time.Second {
				backoff *= 2
			}
			continue
		}
		_ = conn.SetReadDeadline(time.Time{})
		_ = conn.SetWriteDeadline(time.Time{})

		if err := configureNetworking(c.adapter, c.tunIdx, cfg, phys, c.serverIP); err != nil {
			_ = conn.Close()
			log.Printf("configure networking: %v", err)
			time.Sleep(backoff)
			continue
		}

		c.mu.Lock()
		c.data = sess
		c.pending = nil
		c.mtu = cfg.MTU
		c.landing = cfg.TunIP
		c.mu.Unlock()
		c.connMu.Lock()
		old := c.udp
		c.udp = conn
		c.connMu.Unlock()
		if old != nil {
			_ = old.Close()
		}
		backoff = time.Second
		c.touchActivity()
		writeStatus(&StatusInfo{State: "connected", Server: c.server, Adapter: c.adapter,
			LandingIP: cfg.TunIP, MTU: cfg.MTU, PID: os.Getpid(),
			StartedAt: c.startedAt, LastSeen: time.Now().Format("2006-01-02 15:04:05"),
			Message: "已连接，公网端口落地中"})
		log.Printf("tunnel established: landing=%s mtu=%d via %s", cfg.TunIP, cfg.MTU, phys.IP)

		// 阻塞在读循环直到连接失效
		c.readServerLoop(conn)
		_ = conn.Close()
		c.connMu.Lock()
		if c.udp == conn {
			c.udp = nil
		}
		c.connMu.Unlock()
		writeStatus(&StatusInfo{State: "connecting", Server: c.server, Adapter: c.adapter,
			LandingIP: c.landing, MTU: c.mtu, PID: os.Getpid(),
			StartedAt: c.startedAt, LastSeen: time.Now().Format("2006-01-02 15:04:05"),
			Message: "连接中断，正在重连"})
		log.Printf("tunnel transport down, reconnecting...")
	}
}

// beginRehandshake 发送握手请求；Reply 由唯一读循环识别并热切换密钥。
func (c *client) beginRehandshake() {
	nonce, err := common.RandomNonce16()
	if err != nil {
		return
	}
	c.mu.Lock()
	c.pending = nonce
	c.mu.Unlock()
	pkt := c.boot.Seal(common.TypeHandshake, nonce, common.RandomPrefix())
	conn := c.curUDP()
	if conn == nil {
		return
	}
	// 仅为本次握手设置写超时，写完立即复位；否则 deadline 会永久留在共享
	// socket 上，5 秒后所有后续心跳/数据帧写入全部超时（状态却仍显示已连接）。
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(pkt)
	_ = conn.SetWriteDeadline(time.Time{})
	if err != nil {
		log.Printf("re-handshake send: %v", err)
	}
}

// tryHandleReply 用引导密钥尝试解析握手回复，成功则热切换数据密钥。
func (c *client) tryHandleReply(raw []byte) bool {
	t, body, err := c.boot.Open(raw)
	if err != nil || t != common.TypeReply || len(body) < 16 {
		return false
	}
	c.mu.Lock()
	cNonce := c.pending
	c.mu.Unlock()
	if cNonce == nil {
		return false
	}
	key, err := common.DeriveSessionKey([]byte(c.token), cNonce, body[:16])
	if err != nil {
		return false
	}
	sess, err := common.NewSession(key)
	if err != nil {
		return false
	}
	newCfg, err := common.DecodeConfig(body[16:])
	if err != nil {
		return false
	}
	c.mu.Lock()
	c.data = sess
	c.pending = nil
	if newCfg.MTU != 0 {
		c.mtu = newCfg.MTU
	}
	c.landing = newCfg.TunIP
	c.mu.Unlock()
	log.Printf("session re-established, landing ip %s", newCfg.TunIP)
	return true
}

func (c *client) heartbeat() {
	tk := time.NewTicker(5 * time.Second)
	defer tk.Stop()
	for range tk.C {
		_ = c.writeFrame(common.TypePing, nil)
		now := time.Now().Format("2006-01-02 15:04:05")
		state := "connected"
		msg := "已连接，公网端口落地中"
		// 25 秒无任何入向报文（含 Pong）：判定 NAT 映射可能已失效，立即用握手帧重建
		if time.Since(c.lastActivity()) > 25*time.Second {
			log.Printf("no inbound traffic for 25s, sending re-handshake")
			c.beginRehandshake()
			state = "connecting"
			msg = "连接中断，正在重连"
		}
		writeStatus(&StatusInfo{State: state, Server: c.server, Adapter: c.adapter,
			LandingIP: c.landing, MTU: c.mtu, PID: os.Getpid(),
			StartedAt: c.startedAt, LastSeen: now, Message: msg})
	}
}

func (c *client) curMTU() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mtu
}

func (c *client) touchActivity() { c.activity.Store(time.Now().UnixNano()) }
func (c *client) lastActivity() time.Time {
	v := c.activity.Load()
	if v == 0 {
		return time.Now()
	}
	return time.Unix(0, v)
}

func (c *client) writeFrame(t byte, body []byte) error {
	key := c.currentKey()
	conn := c.curUDP()
	if key == nil || conn == nil {
		return fmt.Errorf("transport not ready")
	}
	pkt := key.Seal(t, body, common.RandomPrefix())
	// 数据信道不逐包重置写 deadline（连接建立时已清除为永久阻塞）
	c.pacer.Wait()
	if _, err := conn.Write(pkt); err != nil {
		// 写失败通常意味着 socket 已失效：关闭它让 readServerLoop 退出，
		// 由 transportLoop 重新拨号握手，避免数据面静默死亡。
		log.Printf("udp write failed, forcing reconnect: %v", err)
		c.connMu.Lock()
		if c.udp == conn {
			c.udp = nil
		}
		c.connMu.Unlock()
		_ = conn.Close()
		return err
	}
	return nil
}

// wintunToServer：本机协议栈 -> wintun -> 加密 -> 服务器
func (c *client) wintunToServer() {
	event := c.session.ReadWaitEvent()
	for {
		// 排空接收环
		for {
			packet, err := c.session.ReceivePacket()
			if err != nil {
				break // ERROR_NO_MORE_ITEMS（259）：当前无包
			}
			if len(packet) > 0 {
				_ = c.writeFrame(common.TypeData, packet)
			}
			c.session.ReleaseReceivePacket(packet)
		}
		// 等待新包通知（INFINITE）
		if ev, _ := windows.WaitForSingleObject(event, windows.INFINITE); ev != windows.WAIT_OBJECT_0 && ev != 0 {
			time.Sleep(50 * time.Millisecond) // 会话结束等情况，避免忙等
		}
	}
}

// readServerLoop：服务器 -> 解密 -> wintun -> 本机协议栈（服务看到真实访问者 IP）。
// 读取报错即返回，由 transportLoop 重新拨号握手，本函数不再"静默永久退出"。
func (c *client) readServerLoop(conn *net.UDPConn) {
	buf := make([]byte, common.MaxPacket+64)
	c.touchActivity()
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("udp read: %v", err)
			return
		}
		key := c.currentKey()
		if key == nil {
			continue
		}
		t, body, err := key.Open(buf[:n])
		if err != nil {
			// 数据密钥解不开：可能是重连过程中的握手回复
			if raw := buf[:n]; len(raw) > 0 && raw[0] == common.TypeReply {
				if c.tryHandleReply(raw) {
					c.touchActivity()
				}
			}
			continue
		}
		c.touchActivity() // 数据包/Pong 都证明会话存活
		if t == common.TypePong || len(body) == 0 {
			continue
		}
		if t != common.TypeData || len(body) > c.curMTU() {
			continue
		}
		out, err := c.session.AllocateSendPacket(len(body))
		if err != nil {
			log.Printf("alloc packet: %v", err)
			continue
		}
		copy(out, body)
		c.session.SendPacket(out)
	}
}

// ---------------- 握手 ----------------

// handshake 使用 Token 完成握手。Token 同时是引导加密与数据会话密钥的根密钥。
func handshake(conn *net.UDPConn, token string) (*common.Config, *common.Session, error) {
	if token == "" {
		return nil, nil, fmt.Errorf("缺少 Token 参数")
	}
	tokenBytes := []byte(token)
	boot, err := common.NewSession(common.NewBootstrapKey(tokenBytes))
	if err != nil {
		return nil, nil, err
	}
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		cNonce, _ := common.RandomNonce16()
		// 握手明文仅含客户端随机数；身份由"只有正确 Token 才能加解密"隐式证明
		pkt := boot.Seal(common.TypeHandshake, cNonce, common.RandomPrefix())
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(pkt); err != nil {
			lastErr = err
			time.Sleep(time.Second)
			continue
		}
		rb := make([]byte, common.MaxPacket+64)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(rb)
		if err != nil {
			lastErr = err
			time.Sleep(time.Second)
			continue
		}
		t, body, err := boot.Open(rb[:n])
		if err != nil || t != common.TypeReply || len(body) < 16 {
			lastErr = fmt.Errorf("bad reply")
			time.Sleep(time.Second)
			continue
		}
		sNonce := body[:16]
		cfg, err := common.DecodeConfig(body[16:])
		if err != nil {
			lastErr = err
			continue
		}
		key, err := common.DeriveSessionKey(tokenBytes, cNonce, sNonce)
		if err != nil {
			return nil, nil, err
		}
		sess, err := common.NewSession(key)
		if err != nil {
			return nil, nil, err
		}
		return cfg, sess, nil
	}
	return nil, nil, fmt.Errorf("handshake failed after retries: %v", lastErr)
}

// ---------------- 物理网卡发现 ----------------

type physAdapter struct {
	Idx     string
	IP      string
	Gateway string
}

func psOutput(script string) (string, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func detectPhysicalAdapter() (*physAdapter, error) {
	// 取有效 metric 最低、且有真实网关的 IPv4 默认路由接口
	script := `Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
 Where-Object { $_.NextHop -ne '0.0.0.0' } |
 Sort-Object { $_.RouteMetric + $_.InterfaceMetric } |
 Select-Object -First 1 |
 ForEach-Object { "$($_.ifIndex)|$($_.NextHop)" }`
	out, err := psOutput(script)
	if err != nil || !strings.Contains(out, "|") {
		return nil, fmt.Errorf("no default route: %v %s", err, out)
	}
	parts := strings.SplitN(strings.Split(out, "\n")[0], "|", 2)
	p := &physAdapter{Idx: parts[0], Gateway: parts[1]}

	ipScript := fmt.Sprintf(`(Get-NetIPAddress -InterfaceIndex %s -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -notlike '169.254*' } | Select-Object -First 1).IPAddress`, p.Idx)
	ip, err := psOutput(ipScript)
	if err != nil || net.ParseIP(strings.TrimSpace(ip)) == nil {
		return nil, fmt.Errorf("no ipv4 on ifIndex %s: %v %s", p.Idx, err, ip)
	}
	p.IP = strings.TrimSpace(strings.Split(ip, "\n")[0])
	return p, nil
}

func adapterIndex(name string) string {
	for i := 0; i < 20; i++ {
		out, err := psOutput(fmt.Sprintf(`(Get-NetAdapter -Name '%s' -ErrorAction Stop).ifIndex`, name))
		if err == nil && out != "" {
			return strings.TrimSpace(strings.Split(out, "\n")[0])
		}
		time.Sleep(200 * time.Millisecond)
	}
	return ""
}

// ---------------- IP / 路由配置 ----------------

// routeExists 检查 IPv4 路由表中是否已有到 dst 的主机路由（经 gw）。
func routeExists(dst, gw string) bool {
	out, err := exec.Command("route", "print", "-4", dst).Output()
	if err != nil {
		return false
	}
	s := string(out)
	return strings.Contains(s, dst) && strings.Contains(s, gw)
}

func runCmd(bin string, args ...string) error {
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w %s", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func configureNetworking(adapterName, tunIdx string, cfg *common.Config, phys *physAdapter, serverIP string) error {
	// 幂等：先尝试清理旧配置
	cleanupNetworking(adapterName, tunIdx, cfg, phys, serverIP)

	mtu := cfg.MTU
	if mtu == 0 {
		mtu = common.MTU
	}
	// 设置 wintun 的 MTU 与接口 metric。
	// 注意：netsh "set interface" 对 wintun 虚拟网卡会静默不生效（MTU 停留 65535），
	// 必须用 Set-NetIPInterface；metric 999 保证不抢占物理网卡默认路由。
	mssScript := fmt.Sprintf(
		"Set-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv4 -NlMtu %d -InterfaceMetric 999 -ErrorAction Stop",
		adapterName, mtu)
	if _, err := psOutput(mssScript); err != nil {
		log.Printf("warn: set wintun mtu/metric: %v", err)
	}

	// wintun 上配置落地地址（/32，避免在本地产生多余 on-link 网段）
	// wintun 适配器 GUID 由名字派生，进程重启后旧地址仍在，"已存在"按成功处理
	if err := runCmd("netsh", "interface", "ipv4", "add", "address",
		fmt.Sprintf("name=%s", adapterName), cfg.TunIP, "255.255.255.255"); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("add address: %w", err)
	}

	// 防环回：服务器 IP/32 强制走物理网关（多实例共享，已存在视为成功）
	if err := runCmd("route", "add", serverIP, "mask", "255.255.255.255",
		phys.Gateway, "metric", "1", "if", phys.Idx); err != nil && !routeExists(serverIP, phys.Gateway) {
		return fmt.Errorf("add host route: %w", err)
	}

	// 高 metric 的 on-link 默认路由：仅承载"发给落地 IP 的连接"的应答（强主机发送）
	if err := runCmd("route", "add", "0.0.0.0", "mask", "0.0.0.0", "0.0.0.0",
		"metric", "999", "if", tunIdx); err != nil {
		// 多实例时可能已存在等价条目
		log.Printf("warn: add default route on %s: %v", adapterName, err)
	}

	// 打印配置供诊断
	data, _ := json.Marshal(cfg)
	log.Printf("network configured: tun=%s/32 on %s, host-route %s via %s, default dev metric 999; cfg=%s",
		cfg.TunIP, adapterName, serverIP, phys.Gateway, string(data))
	return nil
}

func cleanupNetworking(adapterName, tunIdx string, cfg *common.Config, phys *physAdapter, serverIP string) {
	// 必须带 if/网关限定，避免误删物理网卡自身的默认路由
	if phys != nil {
		_ = exec.Command("route", "delete", serverIP, "mask", "255.255.255.255", phys.Gateway).Run()
	}
	_ = exec.Command("route", "delete", "0.0.0.0", "mask", "0.0.0.0", "0.0.0.0", "if", tunIdx).Run()
	if cfg != nil {
		_ = exec.Command("netsh", "interface", "ipv4", "delete", "address",
			fmt.Sprintf("name=%s", adapterName), cfg.TunIP).Run()
	}
}
