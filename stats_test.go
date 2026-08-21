package main

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

type fakeAddr string

func (f fakeAddr) Network() string { return "tcp" }
func (f fakeAddr) String() string  { return string(f) }

func TestStats_RingBufferIsBounded(t *testing.T) {
	s := NewStats()
	// 写超过容量，验证内存不会无限增长——这类"慢性泄漏"在短测试里
	// 看不出来，只会在跑了几周的生产上打爆内存。
	for i := 0; i < recentCapacity*3; i++ {
		s.RecordConnection("socks5", fakeAddr(fmt.Sprintf("10.0.0.%d:1", i%256)),
			"example.com", 443, net.ParseIP("2604:2dc0:143:8200::1"))
	}
	snap := s.Snapshot(0)
	if len(snap.Recent) != recentCapacity {
		t.Errorf("保留条数 = %d, 期望 %d", len(snap.Recent), recentCapacity)
	}
	if snap.Accepted != uint64(recentCapacity*3) {
		t.Errorf("累计计数 = %d, 期望 %d（计数不该被环形缓冲截断）",
			snap.Accepted, recentCapacity*3)
	}
}

func TestStats_RecentIsNewestFirst(t *testing.T) {
	s := NewStats()
	for i := 0; i < 5; i++ {
		s.RecordConnection("socks5", fakeAddr("10.0.0.1:1"),
			fmt.Sprintf("host%d.com", i), 443, net.ParseIP("2604:2dc0:143:8200::1"))
	}
	snap := s.Snapshot(0)
	if len(snap.Recent) != 5 {
		t.Fatalf("条数 = %d", len(snap.Recent))
	}
	// 页面上人总是先看最近发生了什么，所以最新的必须在最前面。
	if got := snap.Recent[0].Target; got != "host4.com:443" {
		t.Errorf("第一条 = %s, 期望 host4.com:443（最新在前）", got)
	}
	if got := snap.Recent[4].Target; got != "host0.com:443" {
		t.Errorf("最后一条 = %s, 期望 host0.com:443", got)
	}
}

// 环绕之后顺序仍要正确。下标计算容易在这里写出 off-by-one。
func TestStats_OrderCorrectAfterWrap(t *testing.T) {
	s := NewStats()
	for i := 0; i < recentCapacity+3; i++ {
		s.RecordConnection("socks5", fakeAddr("10.0.0.1:1"),
			fmt.Sprintf("h%d.com", i), 443, net.ParseIP("2604:2dc0:143:8200::1"))
	}
	snap := s.Snapshot(0)
	want := fmt.Sprintf("h%d.com:443", recentCapacity+2)
	if got := snap.Recent[0].Target; got != want {
		t.Errorf("环绕后第一条 = %s, 期望 %s", got, want)
	}
	// 最老的那条应该是第 3 条（前 3 条已被覆盖）
	if got := snap.Recent[recentCapacity-1].Target; got != "h3.com:443" {
		t.Errorf("环绕后最后一条 = %s, 期望 h3.com:443", got)
	}
}

func TestStats_CountsByResult(t *testing.T) {
	s := NewStats()
	s.RecordConnection("socks5", fakeAddr("1.1.1.1:1"), "a.com", 443, net.ParseIP("2604::1"))
	s.RecordRejected(fakeAddr("2.2.2.2:2"), "超上限")
	s.RecordFailed(fakeAddr("3.3.3.3:3"), fmt.Errorf("口令错误"))
	s.RecordFailed(fakeAddr("4.4.4.4:4"), fmt.Errorf("不在白名单"))

	snap := s.Snapshot(7)
	if snap.Accepted != 1 || snap.Rejected != 1 || snap.Failed != 2 {
		t.Errorf("计数 = 成功%d 超限%d 失败%d, 期望 1/1/2",
			snap.Accepted, snap.Rejected, snap.Failed)
	}
	if snap.Active != 7 {
		t.Errorf("在途 = %d, 期望 7", snap.Active)
	}
}

// 只留 IP 不留端口：端口对排查没价值，还会让页面很挤。
func TestStats_ClientIPStripsPort(t *testing.T) {
	if got := clientIP(fakeAddr("192.168.1.5:54321")); got != "192.168.1.5" {
		t.Errorf("= %q, 期望 192.168.1.5", got)
	}
	if got := clientIP(fakeAddr("[2604:2dc0::1]:443")); got != "2604:2dc0::1" {
		t.Errorf("= %q, 期望 2604:2dc0::1", got)
	}
	if got := clientIP(nil); got != "" {
		t.Errorf("nil 时 = %q, 期望空字符串", got)
	}
}

func TestStats_ConcurrentWritesAreSafe(t *testing.T) {
	s := NewStats()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s.RecordConnection("socks5", fakeAddr("1.1.1.1:1"),
					"a.com", 443, net.ParseIP("2604::1"))
				s.Snapshot(int64(n))
			}
		}(i)
	}
	wg.Wait()
	if snap := s.Snapshot(0); snap.Accepted != 800 {
		t.Errorf("并发写入后计数 = %d, 期望 800", snap.Accepted)
	}
}

// 连上就断、一个字节都没发的连接不该进状态页。
// 端口扫描和健康检查每天能有成千上万条，记下来会把环形缓冲冲干净，
// 真正要排查的记录反而被挤掉。
func TestServer_BareConnectIsNotRecorded(t *testing.T) {
	srv, _ := startTestServer(t, []string{"example.com"})

	for i := 0; i < 5; i++ {
		c, err := net.DialTimeout("tcp", srv.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatalf("连接失败: %v", err)
		}
		_ = c.Close() // 立刻断开，什么都不发
	}

	// 给服务端一点时间处理完这些连接
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.active.Load() == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)

	if snap := srv.stats.Snapshot(0); len(snap.Recent) != 0 {
		t.Errorf("裸连接不该被记录，却有 %d 条:\n%+v", len(snap.Recent), snap.Recent)
	}
}
