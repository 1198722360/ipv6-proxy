#!/usr/bin/env bash
#
# ipv6-proxy 一键部署（Ubuntu / Debian，root 执行）
#
# 做完这些事：
#   1. 探测（或采用你指定的）IPv6 前缀
#   2. 加 local 路由并做成开机自启 —— 这是唯一无法省略的宿主配置
#   3. 下载（或使用同目录的）二进制并安装到 /usr/local/bin/ipv6-proxy
#   4. 生成 /etc/ipv6-proxy.env（口令留空则自动生成强口令并回显）
#   5. 装 systemd unit、启用开机自启、启动
#   6. 自检：进程活着、端口在听、真的能从代理出去
#
# 用法：
#   sudo ./deploy.sh                                   # 二进制取同目录，前缀自动探测
#   sudo ./deploy.sh --binary ./ipv6-proxy-linux-amd64
#   sudo ./deploy.sh --prefix 2604:2dc0:143:8200::/56
#   sudo ./deploy.sh --password '强口令' --port 6080
#   sudo ./deploy.sh --hosts '*'                       # 关掉域名白名单（不推荐）
#   sudo ./deploy.sh --admin-listen 127.0.0.1          # 管理面只听本地，走 SSH 隧道
#   sudo ./deploy.sh --no-admin                        # 不要管理面
#   sudo ./deploy.sh --release v20260821               # 装指定版本（默认最新）
#   sudo ./deploy.sh --check                           # 只体检，不改任何东西
#   sudo ./deploy.sh --uninstall                       # 卸干净
#
# 幂等：重复执行不会报错、不会重复写入。

set -euo pipefail

BIN_DST=/usr/local/bin/ipv6-proxy
# 配置放在专属目录而不是单个文件。原因是管理面要能原子替换它：
# rename(2) 需要**目录**的写权限，只给文件写权限做不到原子替换，
# 而非原子的写法在进程被 kill 时会留下残缺配置，下次开机就起不来。
# 二进制从这个仓库的 Release 下载。仓库是公开的，不需要任何凭据。
REPO="1198722360/ipv6-proxy"
RELEASE_TAG=""   # 空 = 用 latest

CONF_DIR=/etc/ipv6-proxy
ENV_FILE="$CONF_DIR/env"
LEGACY_ENV_FILE=/etc/ipv6-proxy.env
SVC_USER=ipv6proxy
UNIT_FILE=/etc/systemd/system/ipv6-proxy.service
ROUTE_UNIT_FILE=/etc/systemd/system/ipv6-proxy-route.service
UNIT=ipv6-proxy.service
ROUTE_UNIT=ipv6-proxy-route.service

# 默认白名单。全开放的代理一旦口令泄漏，别人就能拿你的 IP 访问任意目标，
# 溯源指向你。限定之后即便泄漏，滥用价值也接近零。
DEFAULT_HOSTS='chatgpt.com,*.chatgpt.com,*.openai.com'

# 参数解析中的 shift 会把 $* 清空，而重试提示里要原样回显用户传的参数。
ORIG_ARGS="$*"

BINARY=""
PREFIX=""
PASSWORD=""
PORT=6080
HOSTS=""
MAX_CONNS=""
LISTEN_ADDR="0.0.0.0"
# 管理面默认开启，与二进制的默认值保持一致。
# 两边不一致的话会出现"deploy.sh 说没开、服务却在听 6081"这种矛盾状态。
ADMIN_ENABLED=1
ADMIN_PORT=6081
ADMIN_LISTEN="0.0.0.0"
ADMIN_PASSWORD=""
CHECK_ONLY=0
UNINSTALL=0

log()  { printf '  %s\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
head_() { printf '\n%s\n────────────────────────────────────────\n' "$*"; }

usage() { sed -n '2,31p' "$0"; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        --binary)    BINARY="${2:?--binary 需要一个路径}"; shift 2 ;;
        --prefix)    PREFIX="${2:?--prefix 需要一个 CIDR}"; shift 2 ;;
        --password)  PASSWORD="${2:?--password 需要一个值}"; shift 2 ;;
        --port)      PORT="${2:?--port 需要一个值}"; shift 2 ;;
        --listen)    LISTEN_ADDR="${2:?--listen 需要一个地址}"; shift 2 ;;
        --hosts)     HOSTS="${2:?--hosts 需要一个值}"; shift 2 ;;
        --max-conns) MAX_CONNS="${2:?--max-conns 需要一个值}"; shift 2 ;;
        --release)   RELEASE_TAG="${2:?--release 需要一个 tag，如 v20260821}"; shift 2 ;;
        --no-admin)  ADMIN_ENABLED=0; shift ;;
        --admin)     ADMIN_ENABLED=1; shift ;;
        --admin-port)     ADMIN_ENABLED=1; ADMIN_PORT="${2:?--admin-port 需要一个值}"; shift 2 ;;
        --admin-listen)   ADMIN_ENABLED=1; ADMIN_LISTEN="${2:?--admin-listen 需要一个地址}"; shift 2 ;;
        --admin-password) ADMIN_ENABLED=1; ADMIN_PASSWORD="${2:?--admin-password 需要一个值}"; shift 2 ;;
        --check)     CHECK_ONLY=1; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help)   usage ;;
        *) die "未知参数：$1（--help 看用法）" ;;
    esac
done

echo
echo "ipv6-proxy 部署"
echo "════════════════════════════════════════"

# ───────────────────────── 卸载 ─────────────────────────
if [ "$UNINSTALL" = 1 ]; then
    [ "$(id -u)" = 0 ] || die "需要 root：sudo $0 --uninstall"
    head_ "卸载"
    if systemctl disable --now "$UNIT" 2>/dev/null; then ok "已停止并禁用 $UNIT"; else log "$UNIT 未在运行"; fi
    if systemctl disable --now "$ROUTE_UNIT" 2>/dev/null; then ok "已停止并禁用 $ROUTE_UNIT"; else log "$ROUTE_UNIT 未在运行"; fi
    rm -f "$UNIT_FILE" "$ROUTE_UNIT_FILE" "$BIN_DST"
    systemctl daemon-reload
    ok "已删除 unit 与二进制"
    # 口令文件留着不删：里面可能是你手写的口令，删掉就找不回来了。
    # 真要清干净请手动 rm。
    if [ -f "$ENV_FILE" ]; then
        warn "保留 $ENV_FILE（含口令）。确认不需要了再手动删除：rm -rf $CONF_DIR"
    fi
    # 服务用户同理不动：配置目录还归它所有，删了用户会留下一堆无主文件。
    if id "$SVC_USER" >/dev/null 2>&1; then
        log "保留服务用户 $SVC_USER（配置目录仍归它所有）。要删：userdel $SVC_USER"
    fi
    warn "local 路由未撤销（可能有别的服务在用）。要撤：ip -6 route del local <前缀> dev lo"
    echo
    exit 0
fi

# root 检查放在最前面。它是最容易撞上、也最容易修的失败原因，
# 排在后面会让非 root 用户先看到"找不到二进制"之类的无关报错。
# --check 是只读的，不需要 root。
if [ "$CHECK_ONLY" != 1 ]; then
    [ "$(id -u)" = 0 ] || die "需要 root：sudo $0 $ORIG_ARGS"
fi

# 这个脚本以 systemd 管理服务。没有 systemctl 说明不是 systemd 系统
# （容器、WSL1、Alpine 等），继续跑下去后面每一步判断都没有意义。
if ! command -v systemctl >/dev/null 2>&1; then
    if [ "$CHECK_ONLY" = 1 ]; then
        warn "本机没有 systemctl，服务相关检查将跳过"
        NO_SYSTEMD=1
    else
        die "本机没有 systemctl。本脚本用 systemd 管理服务，需要在真实的
    Ubuntu / Debian 主机上运行（容器和 WSL1 不适用）。
    只想手工跑的话：PROXY_IPV6_PREFIX=... PROXY_PASSWORD=... $BIN_DST"
    fi
else
    NO_SYSTEMD=0
fi

# ───────────────────── 前缀探测 ─────────────────────
# 从路由表挑：全局单播（2/3 开头）、带前缀长度、长度在 32..120。
# 取最短的那个——它是路由给本机的最大地址块，也就是能自由取址的范围。
# fe80::/64 不以 2/3 开头，天然排除。
detect_prefix() {
    ip -6 route show 2>/dev/null | awk '
        $1 ~ /^[23][0-9a-fA-F]*:/ && $1 ~ /\// {
            split($1, p, "/")
            if (p[2] >= 32 && p[2] <= 120) print p[2], $1
        }' | sort -n | head -1 | awk '{print $2}'
}

head_ "IPv6 前缀"
if [ -z "$PREFIX" ]; then
    PREFIX="$(detect_prefix || true)"
    [ -n "$PREFIX" ] || die "未探测到可用的全局 IPv6 前缀。
    确认服务商已把一段 IPv6 路由到本机（ip -6 route show 应能看到 2xxx::/56 之类），
    或手工指定：sudo $0 --prefix 2604:2dc0:143:8200::/56"
    ok "自动探测：$PREFIX"
else
    ok "使用指定值：$PREFIX"
fi

case "$PREFIX" in
    *:*/*) ;;
    *) die "前缀格式不对，应形如 2604:2dc0:143:8200::/56，实际：$PREFIX" ;;
esac
PREFIX_LEN="${PREFIX##*/}"
if [ "$PREFIX_LEN" -lt 32 ] || [ "$PREFIX_LEN" -gt 120 ]; then
    die "前缀长度 /$PREFIX_LEN 超出可用范围（32..120）。/128 只有一个地址，本服务无从发挥。"
fi

# ─────────────────── 定位并校验二进制 ───────────────────
head_ "二进制"
# 架构在下载分支里也要用，所以无条件先算。
ARCH_SUFFIX="$(uname -m)"
case "$ARCH_SUFFIX" in
    x86_64)  ARCH_SUFFIX=amd64 ;;
    aarch64|arm64) ARCH_SUFFIX=arm64 ;;
    *) die "不支持的架构：$ARCH_SUFFIX（只提供 amd64 / arm64）" ;;
esac

if [ -z "$BINARY" ]; then
    # 先找本地的，省得每次都要联网。
    HERE="$(cd "$(dirname "$0")" && pwd)"
    for candidate in \
        "$HERE/ipv6-proxy-linux-$ARCH_SUFFIX" \
        "$HERE/dist/ipv6-proxy-linux-$ARCH_SUFFIX" \
        "$HERE/ipv6-proxy" \
        "$BIN_DST"
    do
        if [ -f "$candidate" ]; then BINARY="$candidate"; break; fi
    done
fi

# 本地没有就从 GitHub Release 下载。这样服务器上只要有 deploy.sh 一个文件，
# 不需要装 Go、不需要 clone 仓库、不需要先 scp 二进制上来。
if [ -z "$BINARY" ] && [ "$CHECK_ONLY" != 1 ]; then
    ASSET="ipv6-proxy-linux-${ARCH_SUFFIX}"
    URL="https://github.com/$REPO/releases/${RELEASE_TAG:-latest/download}/$ASSET"
    [ -n "${RELEASE_TAG:-}" ] && URL="https://github.com/$REPO/releases/download/$RELEASE_TAG/$ASSET"

    command -v curl >/dev/null 2>&1 || die "找不到二进制，也没有 curl 可供下载。
    装一个：apt install curl
    或手工把二进制传上来后指定：sudo $0 --binary /path/to/$ASSET"

    log "本地没有二进制，从 GitHub 下载 $ASSET ..."
    DOWNLOADED="/tmp/$ASSET.$$"
    # -f 让 HTTP 错误（404 等）返回非零，否则会把一个 HTML 错误页当成二进制存下来，
    # 直到执行时才报"格式错误"，那时已经很难联想到是下载失败。
    if curl -fsSL --connect-timeout 15 --max-time 300 "$URL" -o "$DOWNLOADED"; then
        BINARY="$DOWNLOADED"
        # shellcheck disable=SC2064
        trap "rm -f '$DOWNLOADED'" EXIT
        ok "已下载（$(du -h "$DOWNLOADED" | cut -f1 | tr -d ' ')）"
    else
        rm -f "$DOWNLOADED"
        die "下载失败：$URL
    检查网络，或手工下载后指定：
      curl -fLO $URL
      sudo $0 --binary ./$ASSET"
    fi
fi

if [ -z "$BINARY" ] || [ ! -f "$BINARY" ]; then
    # 体检模式下没有二进制不是致命错误——上面会如实报告"未安装"。
    if [ "$CHECK_ONLY" = 1 ]; then
        BINARY=""
        warn "找不到二进制，部分检查将跳过"
    else
        die "找不到二进制${BINARY:+：$BINARY}"
    fi
else
    chmod +x "$BINARY" 2>/dev/null || true
    # 直接跑一次 --version：这同时验证了架构对不对、文件没传坏、依赖能满足。
    # 比 file(1) 可靠——那个命令在精简系统上未必装了。
    BIN_VERSION="$("$BINARY" --version 2>&1)" || die "二进制无法执行：$BIN_VERSION
    多半是架构不匹配。本机是 $(uname -m)，请编译对应架构后重传。"
    ok "$BINARY  版本 $BIN_VERSION"
fi

# ───────────────────── 自检地址 ─────────────────────
# 自检和示例都用这个地址，由二进制算——不在 shell 里拼字符串。
#
# 原因：形如 "${PREFIX%::*}::7ea3:1" 的拼法对 /56 恰好正确，但对 /120
# 这类窄前缀会算出前缀外的地址，服务端以"不在允许的前缀内"拒绝，
# 于是一套配置完全正常的部署会显示成自检失败。让二进制用它自己的
# 掩码逻辑算，两边就不可能有偏差。
head_ "自检地址"
PROBE=""
PROBE_USER=""
if [ -n "$BINARY" ]; then
    # probe-addr 输出两行：冒号形态（给 ip route get）、破折号形态（给 --proxy-user）。
    if PROBE_OUT="$(PROXY_IPV6_PREFIX="$PREFIX" "$BINARY" probe-addr 2>&1)"; then
        PROBE="$(printf '%s\n' "$PROBE_OUT" | sed -n 1p)"
        PROBE_USER="$(printf '%s\n' "$PROBE_OUT" | sed -n 2p)"
        ok "$PROBE  （用户名形态 $PROBE_USER）"
    else
        die "无法为前缀 $PREFIX 计算自检地址：
$PROBE_OUT"
    fi
else
    warn "无二进制，跳过自检地址计算"
fi

# ───────────────────────── 体检 ─────────────────────────
if [ "$CHECK_ONLY" = 1 ]; then
    head_ "体检（只读，不改动任何配置）"
    if [ -x "$BIN_DST" ]; then
        ok "二进制已安装：$BIN_DST（版本 $("$BIN_DST" --version 2>/dev/null || echo '?')）"
    else
        warn "二进制未安装：$BIN_DST"
    fi
    if [ -f "$ENV_FILE" ]; then ok "配置存在：$ENV_FILE"; else warn "配置缺失：$ENV_FILE"; fi

    if [ -z "$PROBE" ]; then
        warn "无自检地址，跳过 local 路由检查"
    elif ip -6 route get "$PROBE" 2>/dev/null | grep -qE '^local |dev lo'; then
        ok "local 路由已生效（内核视 $PROBE 为本机地址）"
    else
        warn "local 路由缺失 —— 回程包收不下来，代理会连得上但没响应"
    fi

    if [ -f "$ENV_FILE" ] && grep -q '^PROXY_ADMIN_LISTEN=' "$ENV_FILE"; then
        CUR_ADMIN="$(sed -n 's/^PROXY_ADMIN_LISTEN=//p' "$ENV_FILE" | head -1)"
        ok "管理面已配置：$CUR_ADMIN"
        case "$CUR_ADMIN" in
            127.0.0.1:*|localhost:*|\[::1\]:*) ;;
            *) warn "管理面公网可达且走明文 HTTP，口令在链路上可被嗅探" ;;
        esac
    else
        log "管理面未开启（--admin 可开启）"
    fi

    if [ "$NO_SYSTEMD" = 1 ]; then
        echo
        exit 0
    fi
    if systemctl is-enabled "$UNIT" >/dev/null 2>&1; then ok "开机自启已启用"; else warn "开机自启未配置"; fi
    if systemctl is-active --quiet "$UNIT"; then
        ok "服务运行中"
        CUR_PORT="$(grep -oP 'PROXY_LISTEN=\S*:\K\d+' "$ENV_FILE" 2>/dev/null || echo "$PORT")"
        if ss -lntp 2>/dev/null | grep -q ":${CUR_PORT}\b"; then
            ok "端口 $CUR_PORT 在监听"
        else
            warn "端口 $CUR_PORT 没在监听"
        fi
    else
        warn "服务未运行（journalctl -u $UNIT -n 50 看原因）"
    fi
    echo
    exit 0
fi


# ─────────────── local 路由（唯一必须的宿主配置）───────────────
head_ "宿主网络配置"

# 只此一项无法省略：上游回包的目的地址是 /56 里的某个地址，
# 内核必须知道"这是我的"才会收下并交给本进程，否则包被丢弃或转发走。
#
# 而绑定源地址那一半**不需要** net.ipv6.ip_nonlocal_bind：
# 程序用的是 IPV6_FREEBIND（per-socket 选项，零特权，Linux 4.15+）。
# 老内核（< 4.15）才需要那条 sysctl，下面按内核版本决定要不要加。
cat > "$ROUTE_UNIT_FILE" <<EOF
[Unit]
Description=Local route for ipv6-proxy outbound prefix
After=network.target
Wants=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ip -6 route replace local $PREFIX dev lo

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$ROUTE_UNIT" >/dev/null 2>&1
systemctl restart "$ROUTE_UNIT"
ok "local 路由已配置并设为开机自启（$PREFIX -> lo）"

# 老内核兜底。4.15 以下没有 IPV6_FREEBIND，得靠 sysctl。
KVER="$(uname -r | cut -d- -f1)"
KMAJ="${KVER%%.*}"; KREST="${KVER#*.}"; KMIN="${KREST%%.*}"
if [ "${KMAJ:-0}" -lt 4 ] || { [ "${KMAJ:-0}" -eq 4 ] && [ "${KMIN:-0}" -lt 15 ]; }; then
    warn "内核 $KVER < 4.15，无 IPV6_FREEBIND，改用 ip_nonlocal_bind"
    cat > /etc/sysctl.d/99-ipv6-proxy.conf <<'EOF'
net.ipv6.ip_nonlocal_bind = 1
EOF
    sysctl -p /etc/sysctl.d/99-ipv6-proxy.conf >/dev/null
    ok "已开启 net.ipv6.ip_nonlocal_bind"
else
    ok "内核 $KVER 支持 IPV6_FREEBIND，无需 ip_nonlocal_bind sysctl"
fi

# ───────────────────────── 安装 ─────────────────────────
head_ "安装"

# 先装到临时名再 mv：mv 在同一文件系统上是原子的。
# 直接 cp 覆盖一个正在运行的二进制会得到 ETXTBSY，
# 或者更糟——写到一半时服务崩了，留下个半截文件。
install -m 0755 "$BINARY" "$BIN_DST.new"
mv -f "$BIN_DST.new" "$BIN_DST"
ok "已安装 $BIN_DST"

# 专用系统用户。原先用的是 DynamicUser=yes（每次启动分配一个临时 UID），
# 那样最干净，但动态 UID 无法拥有 /etc 下的文件，管理面就写不了配置。
# 实测过：DynamicUser 即使配上 ReadWritePaths 也写不进去。
# 换成固定的 nologin 用户，其余加固项（ProtectSystem、NoNewPrivileges…）全保留。
# 服务本身仍然不需要任何 capability：FREEBIND 是 per-socket 选项。
if id "$SVC_USER" >/dev/null 2>&1; then
    ok "服务用户已存在：$SVC_USER"
else
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
    ok "已创建服务用户：$SVC_USER"
fi

mkdir -p "$CONF_DIR"

# 从旧版本升级：配置原先是 /etc/ipv6-proxy.env 这个单文件。
if [ -f "$LEGACY_ENV_FILE" ] && [ ! -f "$ENV_FILE" ]; then
    mv "$LEGACY_ENV_FILE" "$ENV_FILE"
    ok "已迁移旧配置 $LEGACY_ENV_FILE -> $ENV_FILE"
fi

# ── 配置文件 ──
if [ -z "$HOSTS" ]; then
    if [ -f "$ENV_FILE" ] && grep -q '^PROXY_ALLOWED_HOSTS=' "$ENV_FILE"; then
        HOSTS="$(sed -n 's/^PROXY_ALLOWED_HOSTS=//p' "$ENV_FILE" | head -1)"
        log "沿用已有白名单：$HOSTS"
    else
        HOSTS="$DEFAULT_HOSTS"
    fi
fi

GENERATED_PASSWORD=0
if [ -z "$PASSWORD" ]; then
    if [ -f "$ENV_FILE" ] && grep -q '^PROXY_PASSWORD=.' "$ENV_FILE"; then
        # 沿用旧口令。重新生成会让所有已配好的客户端在毫无提示的情况下失效。
        PASSWORD="$(sed -n 's/^PROXY_PASSWORD=//p' "$ENV_FILE" | head -1)"
        log "沿用 $ENV_FILE 中的现有口令（要换请加 --password）"
    else
        PASSWORD="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 24)"
        GENERATED_PASSWORD=1
    fi
fi

# 口令不能含冒号：SOCKS5 的 RFC 1929 本身允许，但 HTTP Basic
# 按第一个冒号拆 user:pass，含冒号的口令在 HTTP CONNECT 那条路径上会错位。
case "$PASSWORD" in
    *:*) die "口令不能含冒号（HTTP Basic 按第一个冒号拆分 user:pass，会错位）" ;;
esac

# ── 管理口令（与代理口令相互独立）──
GENERATED_ADMIN_PASSWORD=0
if [ "$ADMIN_ENABLED" = 1 ]; then
    if [ -z "$ADMIN_PASSWORD" ]; then
        if [ -f "$ENV_FILE" ] && grep -q '^PROXY_ADMIN_PASSWORD=.' "$ENV_FILE"; then
            ADMIN_PASSWORD="$(sed -n 's/^PROXY_ADMIN_PASSWORD=//p' "$ENV_FILE" | head -1)"
            log "沿用已有的管理口令（要换请加 --admin-password）"
        else
            ADMIN_PASSWORD="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 24)"
            GENERATED_ADMIN_PASSWORD=1
        fi
    fi
    # 两个口令必须不同：共用的话，在管理面上改代理口令的那一刻
    # 自己的会话就失效了，改到一半会把自己锁在外面。
    if [ "$ADMIN_PASSWORD" = "$PASSWORD" ]; then
        die "管理口令不能与代理口令相同（在管理面改代理口令会把自己踢下线）"
    fi
fi

# 先写成 0600 再落盘，避免"创建时 0644、chmod 之前被读走"的窗口。
umask 077
cat > "$ENV_FILE" <<EOF
# ipv6-proxy 配置。由 deploy.sh 生成，可手工编辑，改完 systemctl restart $UNIT。
# 开启管理面后，这个文件也会被服务自己改写（保留注释与未知键）。
PROXY_LISTEN=$LISTEN_ADDR:$PORT
PROXY_IPV6_PREFIX=$PREFIX
PROXY_PASSWORD=$PASSWORD
PROXY_ALLOWED_HOSTS=$HOSTS
EOF
if [ -n "$MAX_CONNS" ]; then echo "PROXY_MAX_CONNS=$MAX_CONNS" >> "$ENV_FILE"; fi
if [ "$ADMIN_ENABLED" = 1 ]; then
    cat >> "$ENV_FILE" <<EOF
PROXY_ADMIN_LISTEN=$ADMIN_LISTEN:$ADMIN_PORT
PROXY_ADMIN_PASSWORD=$ADMIN_PASSWORD
# 指向本文件自身：管理面靠它持久化在线修改。
PROXY_ENV_FILE=$ENV_FILE
EOF
else
    # 必须显式写 off，不能靠"不写这一行"。
    # 二进制的默认值是开启，键缺失会被当成"用默认"，
    # 于是 --no-admin 部署完 6081 照样在听——那正是这里踩过的坑。
    cat >> "$ENV_FILE" <<EOF
PROXY_ADMIN_LISTEN=off
EOF
fi
umask 022

# 目录 700、文件 600，属主都是服务用户——管理面要能在这个目录里
# 创建临时文件并 rename。
chown -R "$SVC_USER:$SVC_USER" "$CONF_DIR"
chmod 700 "$CONF_DIR"
chmod 600 "$ENV_FILE"
ok "已写入 $ENV_FILE（权限 600，属主 $SVC_USER）"

# ── systemd unit ──
# 不用 EnvironmentFile 之外的 Environment= 行：unit 文件对所有用户可读，
# 口令写进去等于公开。全部配置集中在 0600 的 env 文件里。
cat > "$UNIT_FILE" <<EOF
[Unit]
Description=IPv6 outbound proxy (SOCKS5 + HTTP CONNECT)
After=network-online.target $ROUTE_UNIT
Wants=network-online.target
Requires=$ROUTE_UNIT

[Service]
Type=simple
ExecStart=$BIN_DST
EnvironmentFile=$ENV_FILE
Restart=always
RestartSec=3

# 不需要任何特权：绑定非本机地址靠 IPV6_FREEBIND（per-socket 选项），
# 回程靠上面那条 local 路由。
#
# 这里用固定的系统用户而不是 DynamicUser=yes——后者更干净，但动态 UID
# 无法拥有 /etc 下的文件，管理面就写不了配置（实测过，配上 ReadWritePaths
# 也不行）。ReadWritePaths 只开放配置目录这一处，其余仍是只读。
User=$SVC_USER
Group=$SVC_USER
ReadWritePaths=$CONF_DIR
NoNewPrivileges=yes
# DynamicUser=yes 会隐式带上一批加固项；换成固定用户后这些要显式写出来，
# 否则等于在悄悄降低安全性。空的 CapabilityBoundingSet 表示一个都不给——
# 本服务确实一个都不需要（FREEBIND 是 per-socket 选项，不是 capability）。
CapabilityBoundingSet=
AmbientCapabilities=
RestrictSUIDSGID=yes
RemoveIPC=yes
LockPersonality=yes
RestrictRealtime=yes
PrivateDevices=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$UNIT" >/dev/null 2>&1
systemctl restart "$UNIT"
ok "已启用开机自启并启动 $UNIT"

# ───────────────────────── 自检 ─────────────────────────
head_ "自检"

# 给它一点时间：起不来的话 Restart=always 会让 is-active 在崩溃间隙
# 短暂显示 activating，立刻检查容易得到假阳性。
sleep 2
if systemctl is-active --quiet "$UNIT"; then
    ok "服务运行中（版本 $("$BIN_DST" --version)）"
else
    echo
    journalctl -u "$UNIT" -n 30 --no-pager | sed 's/^/      /'
    die "服务未能启动，日志见上"
fi

if ss -lntp 2>/dev/null | grep -q ":${PORT}\b"; then
    ok "端口 $PORT 在监听"
else
    warn "端口 $PORT 没在监听 —— 检查 journalctl -u $UNIT"
fi

if [ "$ADMIN_ENABLED" = 1 ]; then
    if ss -lntp 2>/dev/null | grep -q ":${ADMIN_PORT}\b"; then
        ok "管理面端口 $ADMIN_PORT 在监听"
    else
        warn "管理面端口 $ADMIN_PORT 没在监听 —— 检查 journalctl -u $UNIT"
    fi
    # 真的登录一次。端口在听不等于能用——口令写错、配置文件权限不对，
    # 都会让服务起来了但登录不了。
    if command -v curl >/dev/null 2>&1; then
        CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
            -X POST "http://127.0.0.1:$ADMIN_PORT/api/login" \
            -H 'Content-Type: application/json' \
            -d "{\"password\":\"$ADMIN_PASSWORD\"}" 2>/dev/null || echo 000)"
        if [ "$CODE" = 200 ]; then
            ok "管理面登录验证通过"
        else
            warn "管理面登录失败（HTTP $CODE）—— 检查 journalctl -u $UNIT"
        fi
    fi
fi

if [ -n "$PROBE" ] && ip -6 route get "$PROBE" 2>/dev/null | grep -qE '^local |dev lo'; then
    ok "local 路由生效（内核视 $PROBE 为本机地址）"
else
    warn "内核未把 $PROBE 视为本机地址，实际路由："
    ip -6 route get "$PROBE" 2>&1 | sed 's/^/      /'
fi

# 端到端：真的从代理走一趟，看对端报回来的源 IP 是不是我们指定的那个。
# 这一步同时验证了认证、绑定、白名单、回程四件事，比逐项检查更有说服力。
if command -v curl >/dev/null 2>&1; then
    # api64.ipify.org 不在默认白名单里，临时放开跑一次自检。
    # 用独立的端口和进程，不动已经在跑的服务。
    # 端口 0 让内核挑一个空闲端口，不要自己猜。
    # 原来写的是 PORT+1，开启管理面后正好和它撞车（6080 -> 6081），
    # 自检进程起不来、被 wait 带出非零退出码，set -e 直接把脚本掐断在这里。
    # 让内核分配就不会有这类"看起来没人用"的猜测。
    PROXY_LISTEN="127.0.0.1:0" \
    PROXY_IPV6_PREFIX="$PREFIX" \
    PROXY_PASSWORD="$PASSWORD" \
    PROXY_ALLOWED_HOSTS='*.ipify.org' \
        "$BIN_DST" >/tmp/ipv6-proxy-selftest.log 2>&1 &
    SELFTEST_PID=$!

    # 从日志里读回内核实际分配的端口。轮询而不是固定 sleep：
    # 慢的机器上 1 秒未必够，快的机器上又白等。
    SELFTEST_PORT=""
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        SELFTEST_PORT="$(sed -n 's/.*监听 127\.0\.0\.1:\([0-9]*\).*/\1/p' \
            /tmp/ipv6-proxy-selftest.log 2>/dev/null | head -1)"
        [ -n "$SELFTEST_PORT" ] && break
        sleep 0.3
    done

    SEEN=""
    if [ -z "$SELFTEST_PORT" ]; then
        warn "自检进程未能启动，跳过端到端验证（详见 /tmp/ipv6-proxy-selftest.log）"
    else
    SEEN="$(curl -sS --max-time 15 \
        --socks5-hostname "127.0.0.1:$SELFTEST_PORT" \
        --proxy-user "${PROBE_USER}:${PASSWORD}" \
        https://api64.ipify.org 2>/dev/null || true)"
    fi

    kill "$SELFTEST_PID" 2>/dev/null || true
    # wait 会返回被 kill 进程的退出码（143）。在 set -e 下，即便写了
    # `|| true`，某些 shell 里 wait 的失败仍会传播出来——用 if 包住最稳。
    if wait "$SELFTEST_PID" 2>/dev/null; then :; else :; fi

    if [ "$SEEN" = "$PROBE" ]; then
        ok "端到端通过：对端看到的源地址正是 $SEEN"
    elif [ -n "$SEEN" ]; then
        warn "能出站，但对端看到 $SEEN（期望 $PROBE）—— 存在 NAT 或源地址被改写"
    else
        # 日志里有确切原因，直接摆出来。原先这里固定猜"NDP 无人应答"，
        # 但失败可能是解析被拦、绑定失败、上游不可达等好几种，
        # 猜错会把人引到完全无关的方向去查。
        REASON="$(grep -oP '结束: \K.*' /tmp/ipv6-proxy-selftest.log 2>/dev/null | tail -1)"
        if [ -n "$REASON" ]; then
            warn "代理出站失败，服务端给出的原因："
            log "    $REASON"
            case "$REASON" in
                *内网地址*)
                    log "    自检用的 api64.ipify.org 被解析到了内网地址。"
                    log "    多半是本机 DNS（如 Docker 内建 DNS、某些内网 DNS）返回了假地址，"
                    log "    而不是代理本身有问题——这恰好说明内网拦截在正常工作。"
                    log "    换台机器或换个 DNS 再测：sudo $0 --check" ;;
                *cannot\ assign*|*EADDRNOTAVAIL*)
                    log "    绑定源地址失败。检查 local 路由：ip -6 route get $PROBE" ;;
                *)
                    log "    若确认是回程 NDP 无人应答（前缀是 on-link 而非路由到本机）："
                    log "    apt install ndppd，配置 rule $PREFIX { method static; }" ;;
            esac
        else
            warn "代理出站失败，且日志里没有明确原因。
      完整日志：cat /tmp/ipv6-proxy-selftest.log
      常见原因是回程 NDP 无人应答（前缀是 on-link 而非路由到本机）：
      apt install ndppd，配置 rule $PREFIX { method static; }"
        fi
    fi
else
    warn "未装 curl，跳过端到端验证（apt install curl 后可 sudo $0 --check）"
fi

# ───────────────────────── 收尾 ─────────────────────────
PUBIP="$(curl -sS --max-time 5 https://api.ipify.org 2>/dev/null || echo '你的服务器IP')"

echo
echo "════════════════════════════════════════"
ok "部署完成"
echo
log "监听      $LISTEN_ADDR:$PORT   （SOCKS5 与 HTTP CONNECT 共用一个端口）"
log "前缀      $PREFIX"
log "白名单    $HOSTS"
if [ "$GENERATED_PASSWORD" = 1 ]; then
    echo
    printf '  \033[33m代理口令（自动生成，请现在就存下来）：\033[1m%s\033[0m\n' "$PASSWORD"
    log "它也在 $ENV_FILE 里（权限 600）"
fi

if [ "$ADMIN_ENABLED" = 1 ]; then
    echo
    log "管理面    http://$ADMIN_LISTEN:$ADMIN_PORT"
    if [ "$GENERATED_ADMIN_PASSWORD" = 1 ]; then
        printf '  \033[33m管理口令（自动生成，请现在就存下来）：\033[1m%s\033[0m\n' "$ADMIN_PASSWORD"
    fi
    log "管理口令与代理口令是分开的，在管理面改代理口令不会把自己踢下线。"
fi

echo
echo "用法"
echo "────────────────────────────────────────"
log "用户名 = 出口地址，破折号形态（不能带冒号，会被客户端切碎）"
log "  $PROBE  写成  $PROBE_USER"
echo
log "SOCKS5："
log "  curl --socks5-hostname $PUBIP:$PORT \\"
log "       --proxy-user '$PROBE_USER:$PASSWORD' https://chatgpt.com"
echo
log "HTTP CONNECT："
log "  curl -x 'http://$PROBE_USER:$PASSWORD@$PUBIP:$PORT' https://chatgpt.com"
echo
log "换出口 IP 就换用户名，不需要重启、不需要改配置。"

echo
echo "运维"
echo "────────────────────────────────────────"
log "日志    journalctl -u $UNIT -f"
log "重启    systemctl restart $UNIT"
log "体检    sudo $0 --check"
log "改配置  vim $ENV_FILE && systemctl restart $UNIT"
log "卸载    sudo $0 --uninstall"

if [ "$LISTEN_ADDR" = "0.0.0.0" ]; then
    echo
    warn "代理监听在 0.0.0.0，公网可达。口令是唯一屏障 —— 建议再加一层防火墙："
    log "  ufw allow from <你的固定IP> to any port $PORT proto tcp"
    log "  没有固定 IP 的话，改成只听本地走 SSH 隧道：sudo $0 --listen 127.0.0.1"
fi

if [ "$ADMIN_ENABLED" = 1 ] && [ "$ADMIN_LISTEN" = "0.0.0.0" ]; then
    echo
    warn "管理面公网可达，且走的是明文 HTTP。两件事要清楚："
    log "  1. 管理口令在链路上可被嗅探（没有 TLS）"
    log "  2. 管理面能改白名单 —— 改成 * 就等于把这台机器变成公网开放代理，"
    log "     别人拿你的 IP 做什么，溯源都指向你"
    log ""
    log "  强烈建议限定来源："
    log "    ufw allow from <你的固定IP> to any port $ADMIN_PORT proto tcp"
    log "  或者干脆只听本地、用 SSH 隧道访问："
    log "    sudo $0 --admin --admin-listen 127.0.0.1"
    log "    ssh -L $ADMIN_PORT:127.0.0.1:$ADMIN_PORT root@<本机>"
fi
echo
