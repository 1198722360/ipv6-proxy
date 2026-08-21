#!/usr/bin/env bash
#
# 本地打包并发布到 GitHub Release。
#
# 用法：
#   ./release.sh              # 版本号自动取当天日期，如 v20260821
#   ./release.sh v1.2.0       # 指定版本号
#   ./release.sh --dry-run    # 只编译和打包，不上传
#
# 需要一个有 repo 权限的 GitHub Token：
#   export GITHUB_TOKEN=ghp_xxxx
# 建 token：https://github.com/settings/tokens  （勾 repo 即可）
#
# 发布完之后，服务器上一条命令就能装：
#   curl -fsSL https://github.com/<owner>/<repo>/releases/latest/download/deploy.sh | sudo bash

set -euo pipefail
cd "$(dirname "$0")"

REPO="1198722360/ipv6-proxy"
API="https://api.github.com/repos/$REPO"
UPLOAD="https://uploads.github.com/repos/$REPO"

DRY_RUN=0
TAG=""
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) TAG="$arg" ;;
    esac
done

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
log()  { printf '  %s\n' "$*"; }

# 版本号默认用日期。语义化版本对这个项目没什么意义——
# 它不是被别的代码依赖的库，日期反而更能说明"这是哪天的构建"。
[ -n "$TAG" ] || TAG="v$(date +%Y%m%d)"
case "$TAG" in
    v*) ;;
    *) TAG="v$TAG" ;;
esac

echo
echo "发布 ipv6-proxy $TAG"
echo "════════════════════════════════════════"

# ── 发布前必须通过测试 ──────────────────────────────
# 把没跑过测试的二进制推上去，等于让服务器成为第一个发现问题的地方。
echo
echo "检查"
echo "────────────────────────────────────────"
if command -v go >/dev/null 2>&1; then
    gofmt -l . | grep . && die "有文件未格式化，先跑 gofmt -w ."
    ok "gofmt"
    go vet ./... >/dev/null 2>&1 || die "go vet 未通过"
    ok "go vet"
    # -race 需要 cgo，交叉编译环境下未必有；没有就跑普通测试。
    if go test -count=1 ./... >/dev/null 2>&1; then
        ok "go test"
    else
        die "测试未通过，先修好再发布：go test ./..."
    fi
else
    warn "本机没有 go，跳过测试检查"
fi

# 工作区不干净就发布，意味着 release 里的二进制对应不上任何一个 commit，
# 出问题时无从追溯。
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    warn "工作区有未提交的改动："
    git status --short | sed 's/^/      /'
    printf '  继续发布？未提交的改动会被打进二进制但仓库里查不到 [y/N] '
    read -r reply
    case "$reply" in [yY]*) ;; *) die "已取消" ;; esac
fi

# ── 编译 ────────────────────────────────────────
echo
echo "编译"
echo "────────────────────────────────────────"
rm -rf dist && mkdir -p dist

command -v go >/dev/null 2>&1 || die "找不到 go，无法编译：https://go.dev/dl/"

for ARCH in amd64 arm64; do
    OUT="dist/ipv6-proxy-linux-${ARCH}"
    CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
        go build -trimpath -ldflags "-s -w -X main.version=${TAG}" -o "$OUT" .
    ok "$OUT ($(du -h "$OUT" | cut -f1 | tr -d ' '))"
done

# deploy.sh 也作为 release 资产上传，这样服务器上一条 curl 就够了，
# 不需要先 clone 仓库。
cp deploy.sh dist/deploy.sh
cp .env.example dist/.env.example
ok "dist/deploy.sh"

# 校验和。下载方可以核对文件有没有被改过或传坏。
# macOS 上是 shasum，Linux 上是 sha256sum。
( cd dist && if command -v sha256sum >/dev/null 2>&1; then
      sha256sum ipv6-proxy-linux-* deploy.sh > SHA256SUMS
  else
      shasum -a 256 ipv6-proxy-linux-* deploy.sh > SHA256SUMS
  fi )
ok "dist/SHA256SUMS"

if [ "$DRY_RUN" = 1 ]; then
    echo
    ok "--dry-run：已打包到 dist/，未上传"
    find dist -type f -exec basename {} \; | sort | sed 's/^/      /'
    exit 0
fi

# ── 上传 ────────────────────────────────────────
[ -n "${GITHUB_TOKEN:-}" ] || die "需要 GITHUB_TOKEN。
    建一个（勾 repo 权限）：https://github.com/settings/tokens
    然后：export GITHUB_TOKEN=ghp_xxxx"

command -v curl >/dev/null 2>&1 || die "需要 curl"

echo
echo "发布"
echo "────────────────────────────────────────"

AUTH="Authorization: Bearer $GITHUB_TOKEN"

# 打 tag 并推。已存在就跳过——重复发布同一个版本是常见操作。
if git rev-parse "$TAG" >/dev/null 2>&1; then
    log "tag $TAG 已存在，跳过创建"
else
    git tag -a "$TAG" -m "release $TAG"
    if git push origin "$TAG" >/dev/null 2>&1; then
        ok "已推送 tag $TAG"
    else
        warn "推送 tag 失败（可能已在远端）"
    fi
fi

# 同名 release 已存在就先删掉。GitHub 不允许同一个 tag 有两个 release，
# 而重新发布同一版本（修了个 bug 重打包）是很常见的。
EXISTING="$(curl -sS -H "$AUTH" "$API/releases/tags/$TAG" | \
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("id",""))' 2>/dev/null || true)"
if [ -n "$EXISTING" ]; then
    curl -sS -X DELETE -H "$AUTH" "$API/releases/$EXISTING" >/dev/null
    log "已删除同名的旧 release"
fi

NOTES="$(cat <<NOTE
### 安装

\`\`\`bash
curl -fsSL https://github.com/$REPO/releases/download/$TAG/deploy.sh -o deploy.sh
chmod +x deploy.sh && sudo ./deploy.sh
\`\`\`

deploy.sh 会自动下载对应架构的二进制、配置宿主路由、装好 systemd 并启动。

管理面默认开在 6081 端口，口令部署时会打印。

### 文件

| 文件 | 说明 |
|---|---|
| \`ipv6-proxy-linux-amd64\` | x86_64 静态二进制 |
| \`ipv6-proxy-linux-arm64\` | ARM64 静态二进制 |
| \`deploy.sh\` | 一键部署脚本 |
| \`SHA256SUMS\` | 校验和 |
NOTE
)"

RELEASE_ID="$(python3 -c '
import json, os, sys, urllib.request
data = json.dumps({
    "tag_name": sys.argv[1],
    "name": sys.argv[1],
    "body": sys.argv[2],
}).encode()
req = urllib.request.Request(sys.argv[3] + "/releases", data=data, method="POST")
req.add_header("Authorization", "Bearer " + os.environ["GITHUB_TOKEN"])
req.add_header("Accept", "application/vnd.github+json")
try:
    with urllib.request.urlopen(req) as r:
        print(json.load(r)["id"])
except urllib.error.HTTPError as e:
    sys.stderr.write(e.read().decode() + "\n")
    sys.exit(1)
' "$TAG" "$NOTES" "$API")" || die "创建 release 失败"

ok "已创建 release $TAG"

for F in dist/ipv6-proxy-linux-amd64 dist/ipv6-proxy-linux-arm64 dist/deploy.sh dist/SHA256SUMS dist/.env.example; do
    NAME="$(basename "$F")"
    curl -sS -X POST \
        -H "$AUTH" \
        -H "Content-Type: application/octet-stream" \
        --data-binary "@$F" \
        "$UPLOAD/releases/$RELEASE_ID/assets?name=$NAME" >/dev/null \
        || die "上传 $NAME 失败"
    ok "已上传 $NAME"
done

echo
echo "════════════════════════════════════════"
ok "发布完成"
echo
log "release 页面："
log "  https://github.com/$REPO/releases/tag/$TAG"
echo
log "服务器上安装："
log "  curl -fsSL https://github.com/$REPO/releases/latest/download/deploy.sh -o deploy.sh"
log "  chmod +x deploy.sh && sudo ./deploy.sh"
echo
