package main

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

//go:embed admin.html
var adminAssets embed.FS

const (
	// 登录限速。管理面能改白名单，改成 "*" 就等于把这台机器变成公网开放代理，
	// 所以这个口令端点的价值对攻击者很高。公网上的口令端点会在几小时内被扫到，
	// 限速不是可选项。
	maxLoginFailures = 5
	lockoutDuration  = 5 * time.Minute
)

// AdminServer 是管理面。**独立监听一个端口**，不与代理端口复用。
//
// 复用代理端口是不行的：那边靠首字节嗅探分流（0x05 走 SOCKS5，其余走
// CONNECT 处理器），在上面挂 HTTP 面会让未认证的请求进入已认证的代理路径。
type AdminServer struct {
	proxy    *Server
	password string
	envFile  string

	limiter  *rateLimiter
	listener net.Listener
}

func NewAdminServer(proxy *Server, password, envFile string) *AdminServer {
	return &AdminServer{
		proxy:    proxy,
		password: password,
		envFile:  envFile,
		limiter:  newRateLimiter(),
	}
}

func (a *AdminServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.handleIndex)
	mux.HandleFunc("POST /api/login", a.handleLogin)
	mux.HandleFunc("GET /api/status", a.requireAuth(a.handleStatus))
	mux.HandleFunc("GET /api/config", a.requireAuth(a.handleGetConfig))
	mux.HandleFunc("PUT /api/config", a.requireAuth(a.handlePutConfig))
	return mux
}

func (a *AdminServer) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("管理面监听 %s 失败: %w", addr, err)
	}
	a.listener = ln
	log.Printf("管理面 http://%s", ln.Addr())
	return a.Serve(ln)
}

// Serve 与 ListenAndServe 分开，让测试能先拿到已绑定的 listener
// （端口 0 要绑定后才知道实际端口）。与 Server.serveLoop 的拆分同理。
func (a *AdminServer) Serve(ln net.Listener) error {
	srv := &http.Server{
		Handler: a.Handler(),
		// 管理面在公网上，给读写都设上超时，避免慢速连接把 fd 占住。
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	return srv.Serve(ln)
}

func (a *AdminServer) Close() error {
	if a.listener != nil {
		return a.listener.Close()
	}
	return nil
}

// requireAuth 包一层鉴权。每个受保护的处理器都要显式套上——
// 与 team-pool 后端 requireAdmin 的写法一致。
func (a *AdminServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.checkAuth(r) {
			writeJSONError(w, http.StatusUnauthorized, "未授权")
			return
		}
		next(w, r)
	}
}

func (a *AdminServer) checkAuth(r *http.Request) bool {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return false
	}
	token := strings.TrimSpace(header[len(prefix):])
	// 定长比较：逐字节短路比较会通过响应时间泄漏口令前缀。
	return subtle.ConstantTimeCompare([]byte(token), []byte(a.password)) == 1
}

func (a *AdminServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	// ServeMux 的 "GET /" 是通配，任何未匹配的路径都会落到这里。
	// 对未知路径回 404 而不是首页，否则 /api/typo 会返回一坨 HTML，
	// 前端拿去 JSON.parse 得到的报错和真实原因毫无关系。
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := adminAssets.ReadFile("admin.html")
	if err != nil {
		http.Error(w, "页面缺失", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (a *AdminServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIPFromRequest(r)
	if locked, until := a.limiter.locked(ip); locked {
		writeJSONError(w, http.StatusTooManyRequests,
			fmt.Sprintf("尝试次数过多，请在 %d 秒后重试", int(time.Until(until).Seconds())+1))
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	if subtle.ConstantTimeCompare([]byte(req.Password), []byte(a.password)) != 1 {
		a.limiter.fail(ip)
		log.Printf("管理面登录失败，来源 %s", ip)
		writeJSONError(w, http.StatusUnauthorized, "口令错误")
		return
	}

	a.limiter.reset(ip)
	// 回显口令当令牌，与 team-pool 的 AuthController.login 同形态：
	// 没有会话状态，前端把它存起来后续每个请求带上。
	writeJSON(w, http.StatusOK, map[string]string{"token": a.password})
}

func (a *AdminServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	snap := a.proxy.stats.Snapshot(a.proxy.active.Load())
	writeJSON(w, http.StatusOK, snap)
}

func (a *AdminServer) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg := a.proxy.Config()
	// 绝不回明文口令。管理面在公网上、走明文 HTTP，
	// 把代理口令放进响应等于每次刷新页面都在链路上广播一次。
	writeJSON(w, http.StatusOK, map[string]any{
		"allowedHosts":   cfg.AllowedHosts,
		"passwordLength": len(cfg.Password),
		"prefix":         a.proxy.resolver.String(),
		"listen":         cfg.Listen,
		"maxConns":       cfg.MaxConns,
		"persistent":     a.envFile != "",
	})
}

func (a *AdminServer) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AllowedHosts []string `json:"allowedHosts"`
		Password     string   `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	old := a.proxy.Config()
	next := *old // 值拷贝：新配置整体替换旧的，绝不原地改
	updates := make(map[string]string)

	if req.AllowedHosts != nil {
		hosts, err := normalizeHosts(req.AllowedHosts)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		next.AllowedHosts = hosts
		updates["PROXY_ALLOWED_HOSTS"] = strings.Join(hosts, ",")
	}

	if req.Password != "" {
		if err := validateProxyPassword(req.Password); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		next.Password = req.Password
		updates["PROXY_PASSWORD"] = req.Password
	}

	if len(updates) == 0 {
		writeJSONError(w, http.StatusBadRequest, "没有要修改的内容")
		return
	}

	// 先落盘再切内存。反过来的话，写盘失败时内存已经改了，
	// 页面显示"成功"，重启后却变回去——这种不一致比直接报错难查得多。
	if a.envFile != "" {
		if err := UpdateEnvFile(a.envFile, updates); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "持久化失败: "+err.Error())
			return
		}
	}

	// 写时复制：构造全新的 Policy 再整体换掉。
	// 原地改 Policy.exact 那个 map 会让正在读它的连接协程撞上
	// concurrent map read and map write，那是 runtime 直接打死进程。
	if req.AllowedHosts != nil {
		newPolicy := NewPolicy(next.AllowedHosts)
		// lookup 必须继承：测试会注入假 DNS，重建时丢掉它整套测试就废了。
		newPolicy.lookup = a.proxy.Policy().lookup
		a.proxy.policy.Store(newPolicy)
	}
	a.proxy.cfg.Store(&next)

	log.Printf("管理面更新配置: %s", strings.Join(sortedKeys(updates), ", "))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"persistent": a.envFile != "",
	})
}

// normalizeHosts 清洗白名单。
func normalizeHosts(raw []string) ([]string, error) {
	var out []string
	for _, h := range raw {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		// 逗号是 env 文件里的分隔符。放进一个条目里会让写出去的配置
		// 在下次启动时被拆成两条，得到和页面上看到的不一样的结果。
		if strings.ContainsAny(h, ", \t\n") {
			return nil, fmt.Errorf("白名单条目不能含逗号或空白: %q", h)
		}
		out = append(out, h)
	}
	if len(out) == 0 {
		// 空白名单会被 LoadConfig 拒绝，服务下次就起不来了。
		return nil, fmt.Errorf("白名单不能为空；不限制请显式填 *")
	}
	return out, nil
}

// validateProxyPassword 校验代理口令。
func validateProxyPassword(pw string) error {
	if len(pw) < 8 {
		return fmt.Errorf("口令至少 8 位")
	}
	// 冒号在 HTTP Basic 里是 user:pass 的分隔符，含冒号的口令
	// 会在 CONNECT 那条路径上被切错位置。
	if strings.ContainsAny(pw, ":\n\r") {
		return fmt.Errorf("口令不能含冒号或换行")
	}
	return nil
}

// rateLimiter 按来源 IP 记登录失败次数。
type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]*limitEntry
}

type limitEntry struct {
	failures int
	until    time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{entries: make(map[string]*limitEntry)}
}

func (l *rateLimiter) locked(ip string) (bool, time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[ip]
	if !ok {
		return false, time.Time{}
	}
	if time.Now().Before(e.until) {
		return true, e.until
	}
	return false, time.Time{}
}

func (l *rateLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[ip]
	if !ok {
		e = &limitEntry{}
		l.entries[ip] = e
	}
	e.failures++
	if e.failures >= maxLoginFailures {
		e.until = time.Now().Add(lockoutDuration)
		e.failures = 0
	}
}

func (l *rateLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}

// clientIPFromRequest 取来源 IP。
//
// 刻意**不看** X-Forwarded-For：那个头是客户端可以随便填的，
// 认它等于让攻击者每次换一个假 IP 来绕过限速。
// 如果将来真放在反向代理后面，要改成只信任已知代理传来的值。
func clientIPFromRequest(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
