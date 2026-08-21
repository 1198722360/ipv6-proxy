package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// envFilePath 是配置文件路径，由 PROXY_ENV_FILE 指定。
// 为空表示"不持久化"——在线修改仍然生效，但重启后回到启动时的值。
func envFilePath() string {
	return strings.TrimSpace(os.Getenv("PROXY_ENV_FILE"))
}

// UpdateEnvFile 就地更新 env 文件里的若干个键，其余内容原样保留。
//
// 两个约束决定了这个函数的写法：
//
//  1. **格式必须保持 deploy.sh 能解析的样子**。那边用
//     `sed -n 's/^PROXY_PASSWORD=//p'` 回读，用来在重新部署时保留配置。
//     如果这里写成带引号或多行的形态，一次 ./deploy.sh 就会把在线改的
//     内容静默还原——那种"改了又变回去"的 bug 极难联想到部署脚本头上。
//
//  2. **必须保留未知的键和注释**。用户可能手工加过 PROXY_MAX_CONNS
//     或者写了注释。整份重写会把它们吃掉。
func UpdateEnvFile(path string, updates map[string]string) error {
	if path == "" {
		return fmt.Errorf("未配置 PROXY_ENV_FILE，无法持久化")
	}

	lines, err := readEnvLines(path)
	if err != nil {
		return err
	}

	// 先改已存在的键，记下哪些改过了。
	seen := make(map[string]bool, len(updates))
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		eq := strings.IndexByte(trimmed, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:eq])
		if val, ok := updates[key]; ok && !seen[key] {
			lines[i] = key + "=" + val
			seen[key] = true
		}
	}

	// 文件里没有的键追加到末尾。顺序固定，避免每次写出来的文件都不一样。
	for _, key := range sortedKeys(updates) {
		if !seen[key] {
			lines = append(lines, key+"="+updates[key])
		}
	}

	return writeFileAtomic(path, strings.Join(lines, "\n")+"\n")
}

func readEnvLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // 文件还不存在，当作空文件处理
		}
		return nil, fmt.Errorf("读取 %s 失败: %w", path, err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取 %s 失败: %w", path, err)
	}
	return lines, nil
}

// writeFileAtomic 先写临时文件再 rename。
//
// 不直接截断重写的原因：进程在写到一半时被 kill（OOM、部署、断电），
// 会留下一个残缺的配置文件，而这个服务开机就要读它——
// 结果是"改了个白名单，机器重启后服务起不来了"。
// rename 在同一文件系统内是原子的，要么全新内容，要么完全没变。
func writeFileAtomic(path, content string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".env-*.tmp")
	if err != nil {
		return fmt.Errorf("在 %s 下创建临时文件失败（服务对该目录需有写权限）: %w", dir, err)
	}
	tmpName := tmp.Name()
	// 任何一步失败都要清掉临时文件，否则目录里会越积越多。
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("写入临时文件失败: %w", err)
	}
	// fsync 之后再 rename：否则断电时可能 rename 已落盘而内容还在页缓存里，
	// 得到一个长度正确但内容为空的文件。
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("刷盘失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭临时文件失败: %w", err)
	}
	// 显式 chmod：CreateTemp 建出来是 0600，但这里写死不依赖那个默认值——
	// 文件里有口令，权限错了就是明文泄漏。
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("设置权限失败: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("替换 %s 失败: %w", path, err)
	}
	tmpName = "" // rename 成功，不要再删
	return nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
