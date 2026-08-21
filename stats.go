package main

import (
	"net"
	"strconv"
	"sync"
	"time"
)

// recentCapacity 是最近连接记录的保留条数。
//
// 固定大小的环形缓冲，内存占用有上界（约 200×200B ≈ 40KB）。
// 用无上界的切片会让一个长期运行的服务把内存慢慢吃光——
// 这类"慢性泄漏"在测试里根本看不出来，只会在几周后打爆生产。
const recentCapacity = 200

// ConnRecord 是一条连接记录。
//
// 字段是**结构化**的，不是日志文本。这一点是刻意的：日志里会出现
// 自动生成的口令（main.go 启动时会打印一次），如果状态页展示的是
// 日志行，那条口令就会跟着泄漏到管理面上。
type ConnRecord struct {
	Time     time.Time `json:"time"`
	Protocol string    `json:"protocol"` // socks5 / http
	Client   string    `json:"client"`   // 只留 IP，不含端口
	Target   string    `json:"target"`   // host:port
	Source   string    `json:"source"`   // 出口 IPv6
	Result   string    `json:"result"`   // ok / rejected / failed
	Detail   string    `json:"detail,omitempty"`
}

// Stats 汇总运行期状态，供状态页读取。
//
// 用互斥锁而不是原子量：写入频率是"每连接一次"，锁竞争可以忽略，
// 而环形缓冲的下标推进和数组写入本来就需要成对保护。
type Stats struct {
	startedAt time.Time

	mu       sync.Mutex
	accepted uint64
	rejected uint64
	failed   uint64
	recent   [recentCapacity]ConnRecord
	next     int
	filled   bool
}

func NewStats() *Stats {
	return &Stats{startedAt: time.Now()}
}

func (s *Stats) push(rec ConnRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recent[s.next] = rec
	s.next = (s.next + 1) % recentCapacity
	if s.next == 0 {
		s.filled = true
	}
	switch rec.Result {
	case "ok":
		s.accepted++
	case "rejected":
		s.rejected++
	default:
		s.failed++
	}
}

// RecordConnection 记一条成功建立的连接。
func (s *Stats) RecordConnection(proto string, client net.Addr, host string, port int, source net.IP) {
	s.push(ConnRecord{
		Time:     time.Now(),
		Protocol: proto,
		Client:   clientIP(client),
		Target:   net.JoinHostPort(host, strconv.Itoa(port)),
		Source:   source.String(),
		Result:   "ok",
	})
}

// RecordRejected 记一条被连接数上限挡掉的连接。
func (s *Stats) RecordRejected(client net.Addr, reason string) {
	s.push(ConnRecord{
		Time:   time.Now(),
		Client: clientIP(client),
		Result: "rejected",
		Detail: reason,
	})
}

// RecordFailed 记一条出错结束的连接（认证失败、策略拒绝、拨号失败等）。
func (s *Stats) RecordFailed(client net.Addr, err error) {
	s.push(ConnRecord{
		Time:   time.Now(),
		Client: clientIP(client),
		Result: "failed",
		Detail: err.Error(),
	})
}

// Snapshot 是状态页的数据来源。
type Snapshot struct {
	Version   string       `json:"version"`
	StartedAt time.Time    `json:"startedAt"`
	UptimeSec int64        `json:"uptimeSec"`
	Active    int64        `json:"active"`
	Accepted  uint64       `json:"accepted"`
	Rejected  uint64       `json:"rejected"`
	Failed    uint64       `json:"failed"`
	Recent    []ConnRecord `json:"recent"`
}

// Snapshot 返回当前状态。recent 按时间**倒序**（最新在前），
// 因为页面上人总是先看最近发生了什么。
func (s *Stats) Snapshot(active int64) Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := s.next
	if s.filled {
		n = recentCapacity
	}
	recent := make([]ConnRecord, 0, n)
	for i := 0; i < n; i++ {
		// 从最新一条往回走。next 指向下一个待写位置，所以 next-1 是最新的。
		idx := (s.next - 1 - i + recentCapacity*2) % recentCapacity
		recent = append(recent, s.recent[idx])
	}

	return Snapshot{
		Version:   version,
		StartedAt: s.startedAt,
		UptimeSec: int64(time.Since(s.startedAt).Seconds()),
		Active:    active,
		Accepted:  s.accepted,
		Rejected:  s.rejected,
		Failed:    s.failed,
		Recent:    recent,
	}
}

// clientIP 只保留地址，丢掉端口。
// 端口对排查没有价值，而完整的 host:port 会让页面变得很挤。
func clientIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}
