package main

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// SOCKS5 协议常量（RFC 1928 / RFC 1929）
const (
	socks5Version = 0x05
	authVersion   = 0x01

	methodUserPass   = 0x02
	methodNoneAccept = 0xFF

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess             = 0x00
	repGeneralFailure      = 0x01
	repNotAllowed          = 0x02
	repHostUnreachable     = 0x04
	repCommandNotSupported = 0x07
)

// handleSocks5 处理一条 SOCKS5 连接。first 是已经被协议嗅探读掉的第一个字节。
func (s *Server) handleSocks5(conn net.Conn, first byte) error {
	// 整条链路只取一次配置快照。中途重新 Load 会让同一个连接
	// 前半段用旧口令校验、后半段用新白名单，出问题时极难复现。
	cfg := s.cfg.Load()
	policy := s.policy.Load()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	if first != socks5Version {
		return fmt.Errorf("不支持的 SOCKS 版本 0x%02x", first)
	}

	// ---- 方法协商 ----
	nmethods, err := readByte(conn)
	if err != nil {
		return err
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	// 只接受用户名/口令认证。哪怕是自用，也不开 NO_AUTH：
	// 监听在 0.0.0.0 上的无认证代理会在几小时内被扫到并被拿去刷流量。
	supported := false
	for _, m := range methods {
		if m == methodUserPass {
			supported = true
			break
		}
	}
	if !supported {
		_, _ = conn.Write([]byte{socks5Version, methodNoneAccept})
		return fmt.Errorf("客户端不支持用户名/口令认证")
	}
	if _, err := conn.Write([]byte{socks5Version, methodUserPass}); err != nil {
		return err
	}

	// ---- 认证（RFC 1929）----
	ver, err := readByte(conn)
	if err != nil {
		return err
	}
	if ver != authVersion {
		return fmt.Errorf("认证子协议版本错误 0x%02x", ver)
	}
	username, err := readLengthPrefixed(conn)
	if err != nil {
		return err
	}
	password, err := readLengthPrefixed(conn)
	if err != nil {
		return err
	}

	source, authErr := s.authenticate(cfg, string(username), string(password))
	if authErr != nil {
		_, _ = conn.Write([]byte{authVersion, 0x01})
		return authErr
	}
	if _, err := conn.Write([]byte{authVersion, 0x00}); err != nil {
		return err
	}

	// ---- CONNECT 请求 ----
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != socks5Version {
		return fmt.Errorf("请求阶段版本错误 0x%02x", header[0])
	}
	if header[1] != cmdConnect {
		writeSocksReply(conn, repCommandNotSupported)
		return fmt.Errorf("只支持 CONNECT，收到 cmd=0x%02x", header[1])
	}

	host, err := readSocksAddr(conn, header[3])
	if err != nil {
		writeSocksReply(conn, repGeneralFailure)
		return err
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return err
	}
	port := int(binary.BigEndian.Uint16(portBuf[:]))

	// ---- 策略校验 + 拨号 ----
	targets, err := policy.CheckTarget(host, port)
	if err != nil {
		writeSocksReply(conn, repNotAllowed)
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
	defer cancel()
	upstream, err := s.dialer.DialFirst(ctx, source, targets, port)
	if err != nil {
		writeSocksReply(conn, repHostUnreachable)
		return err
	}

	if err := writeSocksReply(conn, repSuccess); err != nil {
		_ = upstream.Close()
		return err
	}

	// 握手阶段的 deadline 必须清掉，否则隧道会在 30 秒后被自己掐断。
	_ = conn.SetDeadline(time.Time{})
	s.stats.RecordConnection("socks5", conn.RemoteAddr(), host, port, source)
	s.logf("socks5 %s -> %s:%d (出口 %s)", conn.RemoteAddr(), host, port, source)
	relay(conn, upstream, cfg.IdleTimeout)
	return nil
}

// authenticate 校验口令并把用户名解析成出口地址。
//
// 用户名即出口地址是这个服务的约定：客户端换 IP 只需要换用户名，
// 不需要任何服务端状态或额外接口。
func (s *Server) authenticate(cfg *Config, username, password string) (net.IP, error) {
	// 定长比较防时序侧信道。密码是唯一屏障，逐字节短路比较会泄漏前缀，
	// 让远程爆破从 256^n 降到 256*n 次尝试。
	//
	// 口令**先于**用户名校验，顺序是刻意的：反过来会让未认证的调用方
	// 通过试探用户名来摸清允许的前缀。
	if subtle.ConstantTimeCompare([]byte(password), []byte(cfg.Password)) != 1 {
		// 用户名带冒号说明客户端按第一个冒号把凭据切碎了，
		// 口令必然对不上。不加这句提示，日志只会显示"口令错误"，
		// 排查的人会一直去核对口令本身。
		if strings.Contains(username, ":") {
			return nil, fmt.Errorf("口令错误（用户名 %q 含冒号，凭据已被客户端切碎，请改用破折号形态如 2604-2dc0-143-8200--1）", username)
		}
		return nil, fmt.Errorf("口令错误")
	}
	source, err := s.resolver.Resolve(username)
	if err != nil {
		return nil, fmt.Errorf("用户名（出口地址）无效: %w", err)
	}
	return source, nil
}

func readByte(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

func readLengthPrefixed(r io.Reader) ([]byte, error) {
	n, err := readByte(r)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

func readSocksAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case atypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case atypDomain:
		buf, err := readLengthPrefixed(r)
		if err != nil {
			return "", err
		}
		if len(buf) == 0 {
			return "", fmt.Errorf("域名为空")
		}
		return string(buf), nil
	default:
		return "", fmt.Errorf("不支持的地址类型 0x%02x", atyp)
	}
}

// writeSocksReply 回一个 BND.ADDR 为 0.0.0.0:0 的应答。
// 客户端基本不看这个字段（CONNECT 场景下它只对 BIND 有意义），填零最省事。
func writeSocksReply(w io.Writer, rep byte) error {
	_, err := w.Write([]byte{socks5Version, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
