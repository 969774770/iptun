package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type webAuth struct {
	mu       sync.RWMutex
	user     string
	pass     string
	credFile string
	tokens   map[string]int64 // token -> 过期 unix
	startAt  time.Time
	publicIP atomic.Value // string
}

type webServer struct {
	s *server
	a *webAuth
}

func (s *server) serveWeb(addr, user, pass, certFile, keyFile, initialPublicIP string) {
	a := &webAuth{
		user:     user,
		pass:     pass,
		credFile: filepath.Join(filepath.Dir(s.configPath), "web.json"),
		tokens:   map[string]int64{},
		startAt:  time.Now(),
	}
	if initialPublicIP != "" {
		a.publicIP.Store(initialPublicIP)
	}
	go a.fetchPublicIP(s.wan)
	w := &webServer{s: s, a: a}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", w.handleLogin)
	mux.HandleFunc("/api/logout", w.handleLogout)
	mux.HandleFunc("/api/summary", w.auth(w.handleSummary))
	mux.HandleFunc("/api/sysinfo", w.auth(w.handleSysInfo))
	mux.HandleFunc("/api/clients", w.auth(w.handleClients))
	mux.HandleFunc("/api/listenports", w.auth(w.handleListenPorts))
	mux.HandleFunc("/api/portcheck", w.auth(w.handlePortCheck))
	mux.HandleFunc("/api/settings/tunnel", w.auth(w.handleTunnelSetting))
	mux.HandleFunc("/api/settings/password", w.auth(w.handlePassword))
	// 本地内嵌前端（Bootstrap/页面）
	mux.Handle("/static/", http.StripPrefix("/static/", staticHandler()))
	mux.HandleFunc("/", w.handleIndex)

	srv := &http.Server{Addr: addr, Handler: withSecurityHeaders(mux), ReadTimeout: 15 * time.Second}
	log.Printf("Web 控制台: https://<服务器IP>%s （账号 %s，自签证书浏览器需选择继续访问）", addr, user)
	if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil {
		log.Printf("web server: %v", err)
	}
}

func withSecurityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// ---------------- Web 账号凭据持久化 ----------------

type webCreds struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

func loadWebCreds(dir, defUser, defPass string) (string, string) {
	b, err := os.ReadFile(filepath.Join(dir, "web.json"))
	if err != nil {
		return defUser, defPass
	}
	var c webCreds
	if json.Unmarshal(b, &c) != nil || c.User == "" || c.Pass == "" {
		return defUser, defPass
	}
	return c.User, c.Pass
}

func (a *webAuth) saveCreds() error {
	b, _ := json.MarshalIndent(webCreds{User: a.user, Pass: a.pass}, "", "  ")
	tmp := a.credFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, a.credFile)
}

func (a *webAuth) fetchPublicIP(_ *wanInfo) {
	candidates := []string{
		"http://metadata.tencentyun.com/latest/meta-data/public-ipv4",
		"http://100.100.100.200/latest/meta-data/eipv4",
		"https://api.ip.sb/ip",
	}
	client := &http.Client{Timeout: 6 * time.Second}
	for {
		for _, u := range candidates {
			resp, err := client.Get(u)
			if err != nil {
				continue
			}
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
			resp.Body.Close()
			ip := string(b)
			if len(ip) >= 7 && len(ip) <= 45 {
				a.publicIP.Store(ip)
				return
			}
		}
		time.Sleep(5 * time.Minute)
	}
}

func (a *webAuth) issue() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	t := hex.EncodeToString(b)
	a.mu.Lock()
	a.tokens[t] = time.Now().Add(12 * time.Hour).Unix()
	a.mu.Unlock()
	return t
}

func (a *webAuth) check(r *http.Request) bool {
	c, err := r.Cookie("iptun_session")
	if err != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.tokens[c.Value]
	if !ok || time.Now().Unix() > exp {
		delete(a.tokens, c.Value)
		return false
	}
	return true
}

func (a *webAuth) revoke(r *http.Request) {
	if c, err := r.Cookie("iptun_session"); err == nil {
		a.mu.Lock()
		delete(a.tokens, c.Value)
		a.mu.Unlock()
	}
}

func (w *webServer) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if !w.a.check(r) {
			writeJSON(rw, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(rw, r)
	}
}

func (w *webServer) handleLogin(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "post only"})
		return
	}
	var in struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 512)).Decode(&in); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	w.a.mu.RLock()
	okUser, okPass := in.User == w.a.user, in.Pass == w.a.pass
	w.a.mu.RUnlock()
	if !okUser || !okPass {
		writeJSON(rw, http.StatusForbidden, map[string]string{"error": "账号或密码错误"})
		return
	}
	token := w.a.issue()
	http.SetCookie(rw, &http.Cookie{Name: "iptun_session", Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 43200})
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true})
}

func (w *webServer) handleLogout(rw http.ResponseWriter, r *http.Request) {
	w.a.revoke(r)
	http.SetCookie(rw, &http.Cookie{Name: "iptun_session", Path: "/", MaxAge: -1})
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true})
}

// ---------------- 视图模型 ----------------

type clientView struct {
	ClientDef
	Online   bool   `json:"online"`
	Address  string `json:"address"`
	RxBytes  uint64 `json:"rx_bytes"`
	TxBytes  uint64 `json:"tx_bytes"`
	RxRate   uint64 `json:"rx_rate"` // 字节/秒（最近两个采样间隔）
	TxRate   uint64 `json:"tx_rate"`
	Packets  uint64 `json:"packets"`
	LastSeen int64  `json:"last_seen"`
}

var rateSample struct {
	sync.Mutex
	prev map[uint32][2]uint64 // landing -> [rx, tx]
	last time.Time
}

func (w *webServer) summary() map[string]any {
	clients := w.s.cfg.Snapshot()
	sessions := map[uint32]*clientSession{}
	for _, sess := range w.s.allSessions() {
		sessions[sess.landing] = sess
	}
	views := make([]clientView, 0, len(clients))

	now := time.Now()
	rateSample.Lock()
	if rateSample.prev == nil {
		rateSample.prev = map[uint32][2]uint64{}
	}
	dt := now.Sub(rateSample.last).Seconds()
	newPrev := map[uint32][2]uint64{}
	rateSample.Unlock()

	for _, c := range clients {
		v := clientView{ClientDef: c}
		if sess := sessions[landingKey(c.Landing)]; sess != nil {
			v.Online = true
			v.Address = sess.addr.String()
			v.RxBytes = sess.rxBytes.Load()
			v.TxBytes = sess.txBytes.Load()
			v.Packets = sess.pkts.Load()
			v.LastSeen = sess.lastSeen.Load()
			if dt > 0.5 {
				rateSample.Lock()
				if p, ok := rateSample.prev[sess.landing]; ok {
					if sess.rxBytes.Load() >= p[0] {
						v.RxRate = uint64(float64(sess.rxBytes.Load()-p[0]) / dt)
					}
					if sess.txBytes.Load() >= p[1] {
						v.TxRate = uint64(float64(sess.txBytes.Load()-p[1]) / dt)
					}
				}
				rateSample.Unlock()
			}
			newPrev[sess.landing] = [2]uint64{sess.rxBytes.Load(), sess.txBytes.Load()}
		}
		views = append(views, v)
	}
	if dt > 0.5 {
		rateSample.Lock()
		rateSample.prev = newPrev
		rateSample.last = now
		rateSample.Unlock()
	}
	return map[string]any{
		"public_ip":   loadStr(&w.a.publicIP),
		"wan_ip":      w.s.wan.IP,
		"tun_server":  w.s.cfg.TunServerIP,
		"tunnel_port": w.s.cfg.TunnelPort,
		"web_port":    w.s.webPort,
		"uptime_sec":  int(time.Since(w.a.startAt).Seconds()),
		"server_time": now.Format("2006-01-02 15:04:05"),
		"clients":     views,
	}
}

func loadStr(v *atomic.Value) string {
	if s, ok := v.Load().(string); ok {
		return s
	}
	return ""
}

func (w *webServer) handleSummary(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "get only"})
		return
	}
	writeJSON(rw, http.StatusOK, w.summary())
}

func (w *webServer) handleSysInfo(rw http.ResponseWriter, r *http.Request) {
	writeJSON(rw, http.StatusOK, collectSysStats())
}

// ---------------- 客户端 CRUD ----------------

func (w *webServer) handleClients(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(rw, http.StatusOK, map[string]any{"clients": w.s.cfg.Snapshot()})
		return
	case http.MethodPost:
		var in struct {
			Clients []ClientDef `json:"clients"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
			writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "bad json"})
			return
		}
		next := *w.s.cfg
		next.Clients = in.Clients
		if err := w.s.cfg.Replace(next); err != nil {
			writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := w.s.persistConfig(); err != nil {
			log.Printf("persist config: %v", err)
		}
		if err := w.s.reloadNetworking(); err != nil {
			writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": "应用规则失败: " + err.Error()})
			return
		}
		writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "count": len(in.Clients)})
	default:
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method"})
	}
}

// ---------------- 端口占用检测 ----------------

func (w *webServer) handleListenPorts(rw http.ResponseWriter, r *http.Request) {
	writeJSON(rw, http.StatusOK, map[string]any{"ports": listListenPorts()})
}

type portConflict struct {
	Type   string `json:"type"` // local / client / reserved
	Proto  string `json:"proto"`
	Port   int    `json:"port,omitempty"`
	Start  int    `json:"start,omitempty"`
	End    int    `json:"end,omitempty"`
	Detail string `json:"detail"` // 占用进程 / 客户端名
}

func (w *webServer) handlePortCheck(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "post only"})
		return
	}
	var in struct {
		Proto       string `json:"proto"` // tcp / udp
		Start       int    `json:"start"`
		End         int    `json:"end"`
		ExcludeName string `json:"exclude_name"` // 编辑中的客户端名（不算它自己冲突）
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 256)).Decode(&in); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if in.Proto != "tcp" && in.Proto != "udp" {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "proto 只能是 tcp/udp"})
		return
	}
	if in.Start < 1 || in.End > 65535 || in.Start > in.End {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "端口范围非法(1-65535)"})
		return
	}

	var conflicts []portConflict
	var warnings []portConflict

	// 1) 动态强制保留 3 端口（值取实时配置，不写死）：SSH / Web 面板 / 隧道
	reserved := []portConflict{
		{Type: "reserved", Proto: "tcp", Port: 22, Detail: "SSH 管理"},
		{Type: "reserved", Proto: "tcp", Port: w.s.webPort, Detail: fmt.Sprintf("Web 面板(%d)", w.s.webPort)},
		{Type: "reserved", Proto: "udp", Port: w.s.cfg.TunnelPort, Detail: fmt.Sprintf("隧道端口(%d)", w.s.cfg.TunnelPort)},
	}
	for _, r := range reserved {
		if r.Proto == in.Proto && r.Port >= in.Start && r.Port <= in.End {
			conflicts = append(conflicts, r)
		}
	}

	// 2) 本机实际监听（不含上面 3 个强制保留口）：属于【警告】而非冲突。
	//    数据面有 -m socket 兜底，这些端口即使写进规则也会自动留在本机（自动例外），
	//    用户无需手动避让——这里只提示它们不会被转发。
	for _, lp := range checkLocalOccupied(in.Proto, in.Start, in.End, 100) {
		isReserved := false
		for _, r := range reserved {
			if r.Proto == lp.Proto && r.Port == lp.Port {
				isReserved = true
				break
			}
		}
		if isReserved {
			continue
		}
		warnings = append(warnings, portConflict{Type: "local", Proto: lp.Proto, Port: lp.Port, Detail: lp.Proc})
	}

	// 3) 与其他客户端已配置规则重叠
	for _, cl := range w.s.cfg.Snapshot() {
		if !cl.Enabled || cl.Name == in.ExcludeName {
			continue
		}
		for _, rule := range cl.Rules {
			for _, p := range protoExpand(rule.Proto) {
				if p != in.Proto {
					continue
				}
				if rule.Proto == "icmp" {
					continue
				}
				lo, hi := maxInt(in.Start, rule.PortStart), minInt(in.End, rule.PortEnd)
				if lo <= hi {
					conflicts = append(conflicts, portConflict{
						Type: "client", Proto: in.Proto, Start: lo, End: hi,
						Detail: "客户端 " + cl.Name,
					})
				}
			}
		}
	}

	writeJSON(rw, http.StatusOK, map[string]any{
		"ok":        len(conflicts) == 0, // 仅 3 保留口/客户端重叠算硬冲突；本机占用是警告
		"conflicts": conflicts,
		"warnings":  warnings,
	})
}

func protoExpand(proto string) []string {
	switch proto {
	case "tcp":
		return []string{"tcp"}
	case "udp":
		return []string{"udp"}
	case "all":
		return []string{"tcp", "udp"}
	}
	return nil
}

// ---------------- 节点设置 ----------------

func (w *webServer) handleTunnelSetting(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(rw, http.StatusOK, map[string]any{"tunnel_port": w.s.cfg.TunnelPort})
		return
	case http.MethodPost:
		var in struct {
			Port int `json:"port"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 128)).Decode(&in); err != nil {
			writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "bad json"})
			return
		}
		if in.Port < 1 || in.Port > 65535 {
			writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "端口范围 1-65535"})
			return
		}
		if in.Port == w.s.webPort {
			writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "不能与 Web 控制台端口相同"})
			return
		}
		// 端口是否被本机其他服务占用
		for _, lp := range listListenPorts() {
			if lp.Proto == "udp" && lp.Port == in.Port && lp.Proc != "iptun-server" {
				writeJSON(rw, http.StatusConflict, map[string]string{"error": fmt.Sprintf("UDP %d 已被 %s 占用", in.Port, lp.Proc)})
				return
			}
		}

		// 先尝试在新端口监听（失败则一切不变）
		if err := w.s.rebindTunnel(in.Port); err != nil {
			writeJSON(rw, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		// 更新配置、重建 DNAT 例外、持久化
		w.s.cfg.mu.Lock()
		w.s.cfg.TunnelPort = in.Port
		w.s.cfg.mu.Unlock()
		if err := w.s.persistConfig(); err != nil {
			log.Printf("persist tunnel port: %v", err)
		}
		if err := w.s.reloadNetworking(); err != nil {
			log.Printf("reload networking after port switch: %v", err)
			writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": "端口已切换但规则重建失败: " + err.Error()})
			return
		}
		// 已连接客户端将在旧端口失联并超时下线；提示用户更新客户端 -server 地址
		writeJSON(rw, http.StatusOK, map[string]any{
			"ok":      true,
			"port":    in.Port,
			"warning": "隧道端口已切换。所有客户端需把服务器地址端口改为新端口后重连；同时在云安全组放行新 UDP 端口。",
		})
	default:
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method"})
	}
}

func (w *webServer) handlePassword(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "post only"})
		return
	}
	var in struct {
		Old  string `json:"old"`
		New  string `json:"new"`
		User string `json:"user"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 256)).Decode(&in); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if len(in.New) < 8 {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "新密码至少 8 位"})
		return
	}
	w.a.mu.Lock()
	if in.Old != w.a.pass || (in.User != "" && in.User != w.a.user) {
		w.a.mu.Unlock()
		writeJSON(rw, http.StatusForbidden, map[string]string{"error": "原密码（或账号）不正确"})
		return
	}
	if in.User != "" {
		w.a.user = in.User
	}
	w.a.pass = in.New
	err := w.a.saveCreds()
	w.a.mu.Unlock()
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": "保存失败: " + err.Error()})
		return
	}
	// 密码修改后所有会话失效，强制重新登录
	w.a.mu.Lock()
	w.a.tokens = map[string]int64{}
	w.a.mu.Unlock()
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true})
}

func (w *webServer) handleIndex(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(rw, r)
		return
	}
	staticHandler().ServeHTTP(rw, r)
}

func writeJSON(rw http.ResponseWriter, code int, v any) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(code)
	_ = json.NewEncoder(rw).Encode(v)
}

func (s *server) persistConfig() error {
	if s.configPath == "" {
		return nil
	}
	s.cfg.mu.RLock()
	b, err := json.MarshalIndent(s.cfg, "", "  ")
	s.cfg.mu.RUnlock()
	if err != nil {
		return err
	}
	tmp := s.configPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.configPath)
}
