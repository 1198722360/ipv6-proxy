package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateEnvFile_PreservesUnknownKeysAndComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env")
	original := `# 顶部注释
PROXY_LISTEN=0.0.0.0:6080
PROXY_PASSWORD=oldpass

# 中间的注释
PROXY_MAX_CONNS=512
`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := UpdateEnvFile(path, map[string]string{"PROXY_PASSWORD": "newpass"}); err != nil {
		t.Fatalf("更新失败: %v", err)
	}

	got := readFile(t, path)
	for _, want := range []string{
		"# 顶部注释", "# 中间的注释",
		"PROXY_LISTEN=0.0.0.0:6080",
		"PROXY_MAX_CONNS=512",
		"PROXY_PASSWORD=newpass",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("丢失了 %q\n实际:\n%s", want, got)
		}
	}
	if strings.Contains(got, "oldpass") {
		t.Errorf("旧值还在:\n%s", got)
	}
}

func TestUpdateEnvFile_AppendsMissingKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(path, []byte("PROXY_LISTEN=0.0.0.0:6080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := UpdateEnvFile(path, map[string]string{
		"PROXY_ALLOWED_HOSTS": "a.com,b.com",
		"PROXY_PASSWORD":      "pw",
	}); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	if !strings.Contains(got, "PROXY_ALLOWED_HOSTS=a.com,b.com") || !strings.Contains(got, "PROXY_PASSWORD=pw") {
		t.Errorf("新键没被追加:\n%s", got)
	}
}

func TestUpdateEnvFile_CreatesFileWhenMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env")
	if err := UpdateEnvFile(path, map[string]string{"PROXY_PASSWORD": "pw"}); err != nil {
		t.Fatalf("文件不存在时应能创建: %v", err)
	}
	if got := readFile(t, path); !strings.Contains(got, "PROXY_PASSWORD=pw") {
		t.Errorf("内容不对:\n%s", got)
	}
}

func TestUpdateEnvFile_Permissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env")
	if err := UpdateEnvFile(path, map[string]string{"PROXY_PASSWORD": "pw"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// 文件里有口令。rename 之后的权限来自临时文件，不会自动继承目标文件的，
	// 所以这里必须显式验证——写错了就是明文泄漏。
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("权限 = %o, 期望 600", perm)
	}
}

func TestUpdateEnvFile_NoTempFilesLeftBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "env")
	for i := 0; i < 5; i++ {
		if err := UpdateEnvFile(path, map[string]string{"PROXY_PASSWORD": "pw"}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("残留临时文件: %s", e.Name())
		}
	}
}

func TestUpdateEnvFile_RejectsEmptyPath(t *testing.T) {
	if err := UpdateEnvFile("", map[string]string{"A": "b"}); err == nil {
		t.Error("路径为空时应报错，而不是静默什么都不做")
	}
}

// 这条是防"改了又变回去"的：deploy.sh 在重新部署时用 sed 回读这个文件
// 来保留配置。写出去的格式一旦和那边的正则对不上，一次 ./deploy.sh
// 就会把在线改的内容静默还原，而且极难联想到是部署脚本干的。
func TestUpdateEnvFile_FormatIsReadableByDeployScript(t *testing.T) {
	if _, err := exec.LookPath("sed"); err != nil {
		t.Skip("没有 sed，跳过")
	}
	path := filepath.Join(t.TempDir(), "env")
	if err := UpdateEnvFile(path, map[string]string{
		"PROXY_PASSWORD":      "p@ss-w0rd_123",
		"PROXY_ALLOWED_HOSTS": "chatgpt.com,*.chatgpt.com,*.openai.com",
	}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ key, want string }{
		{"PROXY_PASSWORD", "p@ss-w0rd_123"},
		{"PROXY_ALLOWED_HOSTS", "chatgpt.com,*.chatgpt.com,*.openai.com"},
	} {
		// 与 deploy.sh 里那一行完全一致的写法。
		out, err := exec.Command("sh", "-c",
			"sed -n 's/^"+tc.key+"=//p' "+path+" | head -1").Output()
		if err != nil {
			t.Fatalf("%s: sed 执行失败: %v", tc.key, err)
		}
		if got := strings.TrimRight(string(out), "\n"); got != tc.want {
			t.Errorf("deploy.sh 读 %s 得到 %q, 期望 %q", tc.key, got, tc.want)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
