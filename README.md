# ipv6-proxy

单端口同时提供 SOCKS5 和 HTTP CONNECT 代理，**出口 IPv6 地址由用户名指定**。

给一个 `/56` 前缀，就能得到 7.2×10^16 个可用出口 IP，换 IP 只需要换用户名，
不需要重启、不需要配置文件、不需要任何服务端状态。

## 快速开始

编译好的二进制就在仓库的 `dist/` 里，服务器上不需要装 Go、不需要 Docker。

```bash
# 服务器上只要这两条（deploy.sh 会自动下载对应架构的二进制）
curl -fsSL https://raw.githubusercontent.com/1198722360/ipv6-proxy/main/deploy.sh -o deploy.sh
chmod +x deploy.sh && sudo ./deploy.sh
```

或者 clone 下来跑：

```bash
git clone https://github.com/1198722360/ipv6-proxy.git
cd ipv6-proxy && sudo ./deploy.sh
```

一条命令搞定：探测前缀、配路由、装 systemd、开管理面、自检，全自动。

`deploy.sh` 跑完会打印口令和现成的 curl 命令。之后：

```bash
sudo ./deploy.sh --check      # 体检
sudo ./deploy.sh --uninstall  # 卸载
```

用起来——注意用户名用破折号形态：

```bash
curl --socks5-hostname 服务器IP:6080 \
     --proxy-user "2604-2dc0-143-8200--1:$PROXY_PASSWORD" \
     https://api64.ipify.org
# 换一个用户名就换一个出口 IP
curl --socks5-hostname 服务器IP:6080 \
     --proxy-user "2604-2dc0-143-8200--2:$PROXY_PASSWORD" \
     https://api64.ipify.org
```

### deploy.sh 的参数

| 参数 | 作用 |
|---|---|
| `--binary <路径>` | 指定二进制。默认在脚本同目录按架构自动找 |
| `--prefix <CIDR>` | 指定出口前缀。默认从路由表探测最大的那块 |
| `--password <口令>` | 指定口令。默认沿用已有的；没有则生成一个 |
| `--port <端口>` | 监听端口，默认 6080 |
| `--listen <地址>` | 监听地址，默认 `0.0.0.0`；收敛暴露面用 `127.0.0.1` |
| `--hosts <列表>` | 目标白名单。默认沿用已有的；没有则用 OpenAI 那组 |
| `--no-admin` | 不要管理面（默认是开启的） |
| `--admin-port` / `--admin-listen` / `--admin-password` | 管理面的端口 / 监听地址 / 口令 |
| `--ref <分支>` | 从指定分支/tag 下载二进制（默认 main） |
| `--check` | 只体检不改动（不需要 root） |
| `--uninstall` | 停服务、删 unit 和二进制（保留口令文件） |

重复执行是安全的：不会重置口令、不会重复写配置。

## 宿主到底要不要配置

原本有两项宿主配置，现在**只剩一项**。

| 需求 | 怎么解决 | 要动宿主吗 |
|---|---|---|
| 绑定 /56 里任意一个未配置的地址 | 代码里开 `IPV6_FREEBIND` | **不用** |
| 上游回包能被本机收下 | `ip -6 route add local <前缀> dev lo` | **要** |

**第一项不需要任何特权。** `IPV6_FREEBIND` 是 per-socket 选项（Linux 4.15+），
不需要 root、不需要 capability、不需要 sysctl。实测把该选项关掉作对照组，
绑定立刻报 `cannot assign requested address`，开启则成功——所以它确实是
起作用的那一项，替代了原来的 `net.ipv6.ip_nonlocal_bind=1`。
服务进程因此能一路收紧到 `DynamicUser=yes`，不带任何 capability。

**第二项是网络层面的，绕不过去。** 上游回包的目的地址是 `/56` 里的某个地址，
内核必须知道"这个地址算我的"才会收下并交给本进程，否则包会被丢弃或按普通
路由转发走。`deploy.sh` 会把这条路由加好并做成开机自启的 oneshot unit，
不重启网络、不影响其他服务。

服务 unit 里写了 `Requires=ipv6-proxy-route.service`，所以重启机器后路由会被
依赖关系自动带起来，不需要手工干预。

如果你的机器上 `ip -6 addr` 看不到全球单播地址，那是网络层面缺 IPv6，
任何配置方式都救不了。

## 管理面（默认开启）

部署完就能用，地址和口令在 `deploy.sh` 的输出里。

```bash
sudo ./deploy.sh                          # 默认：管理面在 0.0.0.0:6081
sudo ./deploy.sh --admin-listen 127.0.0.1 # 只听本地，走 SSH 隧道（更安全）
sudo ./deploy.sh --no-admin               # 完全不要管理面
```

浏览器打开 `http://服务器IP:6081`，用管理口令登录。四块内容：

- **状态**：版本、运行时长、在途/累计连接数、最近 200 条连接（时间、协议、来源、目标、出口地址、结果）
- **批量生成代理串**：填个数量点生成，一键复制全部或下载 `.txt`。
  SOCKS5 / HTTP / 两种都要，出口地址**随机**取（不是 `::1 ::2` 顺序排——
  顺序地址在上游看来高度规律，一个被标记时相邻的容易被连坐）。
  生成的串直接可用，形如：
  ```
  socks5h://2604-2dc0-143-8200--a1b2:口令@服务器IP:6080
  http://2604-2dc0-143-8200--a1b2:口令@服务器IP:6080
  ```
  用 `socks5h` 而非 `socks5`：`h` 表示域名交给代理解析。用 `socks5` 的话
  客户端会先本地解析再把 IP 发过来，而白名单模式下服务端拒绝 IP 字面量目标。
- **配置**：增删目标白名单、修改代理口令。**改完立刻对下一个连接生效，不需要重启**，
  同时写回配置文件，重启后保持。
- **管理口令**：在线修改登录本页面的口令。改完本页自动换用新口令，不会把你登出。

管理口令与代理口令是**分开的**，且两边都不允许改成相同——启动时 `main.go` 会因为
两者相同而拒绝启动，所以放行的话服务这次还能跑、下次重启就起不来，现场完全看不出
是几天前那次改口令埋的。管理口令要求 12 位起（比代理口令严一档：它能改白名单）。

> ⚠️ **开管理面之前先想清楚这两件事**
>
> **1. 管理面能改白名单，就等于能把这个定向代理变成公网开放代理。**
> 白名单是"口令泄漏后滥用价值接近零"的唯一依据。管理面一旦被攻破，
> 攻击者把白名单改成 `*`，你的服务器就成了别人的匿名出口，溯源指向你。
>
> **2. 走的是明文 HTTP，没有 TLS。** 公网上任何中间人都能读到管理口令。
>
> 缓解手段（至少做一样）：
> - 防火墙限定来源：`ufw allow from <你的固定IP> to any port 6081 proto tcp`
> - 或者只听本地、用 SSH 隧道：`--admin-listen 127.0.0.1`，
>   然后 `ssh -L 6081:127.0.0.1:6081 root@服务器`
>
> 已有的缓解：登录失败 5 次锁 5 分钟（按来源 IP）；口令定长比较防时序侧信道；
> 状态页和配置接口都**不返回明文代理口令**。

## 停止服务

```bash
sudo ./stop.sh              # 停止（保留开机自启）
sudo ./stop.sh --disable    # 停止并关掉开机自启
sudo ./stop.sh --force      # 连手工起的野进程一起杀
sudo ./stop.sh --status     # 只看状态，不改动
```

停完会确认 6080/6081 是否真的释放了。"服务已停止"不等于"端口空了"——
手工跑二进制留下的残留进程会让下次启动报 `bind: address already in use`，
而那个报错看不出跟上次停止有关。

`--force` 只杀不归 systemd 管的进程。无差别 `pkill` 会连服务自己的一起杀，
而 unit 里是 `Restart=always`，它会立刻被拉起来，看上去像"杀不掉"。

彻底卸载用 `sudo ./deploy.sh --uninstall`。

## 用户名 = 出口地址

**用户名一律用破折号形态**，把 IPv6 里的 `:` 全部换成 `-`：

```
2604:2dc0:143:8200::1   →   2604-2dc0-143-8200--1
2604:2dc0:143:82ff::dead →  2604-2dc0-143-82ff--dead
```

含冒号的用户名会被**明确拒绝**，不做兼容。原因是凭据里的冒号是分隔符：
curl 的 `--proxy-user` 和 RFC 7617 的 Basic 都规定用户名不含冒号、按第一个
冒号拆分。`2604:2dc0::1:pass` 在发出前就被客户端切成了用户名 `2604`、
口令 `2dc0::1:pass`，服务端拿到的只是碎片，再怎么兜底都是在猜哪一段是
地址、哪一段是口令。从格式上排除冒号，这类歧义就不存在了。

（口令本身可以含冒号，不受影响。）

地址必须落在 `PROXY_IPV6_PREFIX` 内，否则拒绝——这是防止本服务
被当成"绑任意源地址发包"工具的关键闸门。

## 配置

全部通过环境变量，没有配置文件。

| 变量 | 默认值 | 说明 |
|---|---|---|
| `PROXY_LISTEN` | `0.0.0.0:6080` | 监听地址。收敛暴露面可改 `127.0.0.1:6080` 走 SSH 隧道 |
| `PROXY_IPV6_PREFIX` | 自动探测 | 出口前缀 CIDR。**强烈建议显式配置**，见下方警告 |
| `PROXY_PASSWORD` | 随机生成 | 唯一凭据。不设则每次启动随机生成并打印到日志 |
| `PROXY_ALLOWED_HOSTS` | `chatgpt.com,*.chatgpt.com,*.openai.com` | 目标白名单，逗号分隔；`*` = 不限制 |
| `PROXY_DIAL_TIMEOUT` | `15s` | 连接上游超时 |
| `PROXY_IDLE_TIMEOUT` | `300s` | 空闲连接回收 |
| `PROXY_MAX_CONNS` | `256` | 并发连接上限 |
| `PROXY_ADMIN_LISTEN` | 空（不开启） | 管理面监听地址，如 `0.0.0.0:6081` |
| `PROXY_ADMIN_PASSWORD` | 随机生成 | 管理面口令，**必须与 `PROXY_PASSWORD` 不同** |
| `PROXY_ENV_FILE` | 空 | 配置文件路径。管理面靠它持久化在线修改；不设则改动重启后丢失 |

> ⚠️ **自动探测只能看到网卡上宣告的前缀（通常是 `/64`）。**
> 如果服务商路由给你的是 `/56`，探测结果只覆盖其中一个 `/64`，
> 落在其他 `/64` 的地址会被误判为越界。这种情况必须显式设置 `PROXY_IPV6_PREFIX`。

## 两道安全防线

这是一个**开放在公网上的代理**，口令是唯一屏障。两道防线都保留：

**1. 目标白名单**（按域名，DNS 解析之前）
限定只能连 OpenAI 相关域名。即便口令泄漏，别人也拿不到一个通用代理，
滥用价值接近零。匹配按标签边界，`*.openai.com` **不会**放行 `evilopenai.com`。

**2. 内网拦截**（按解析出的 IP，建立连接之前）
拦掉回环、私网、链路本地、CGNAT、组播、6to4/Teredo，
以及 `::ffff:127.0.0.1` 这类 IPv4-mapped 形态。
没有这道闸，代理就是把内网暴露出去的跳板——云环境里 `169.254.169.254`
元数据端点尤其致命。

解析后**直接连校验过的 IP**，不拿域名二次解析，避免 DNS rebinding。

白名单模式下拒绝以 IP 字面量为目标——放行等于开了绕过白名单的口子。

## deploy.sh 做了什么

`/56` 里有 7.2×10^16 个地址，不可能预先 `ip addr add` 上去。脚本按顺序做：

1. **探测前缀** —— 从 `ip -6 route show` 里挑全局单播、长度 32..120 的最短那条
   （最短 = 路由给本机的最大地址块）。也可以 `--prefix` 显式指定。
2. **加 local 路由** —— `ip -6 route replace local <前缀> dev lo`，
   并做成开机自启的 oneshot unit。这是唯一必须动宿主的一项。
3. **老内核兜底** —— 内核 < 4.15 时才写 `net.ipv6.ip_nonlocal_bind=1`；
   4.15+ 有 `IPV6_FREEBIND`，不碰 sysctl。
4. **装二进制** —— 先写 `.new` 再 `mv`（原子替换，避免覆盖正在运行的文件时
   撞上 `ETXTBSY`）。装之前先跑一次 `--version`，用能否执行来验证架构对不对。
5. **写配置** —— `/etc/ipv6-proxy/env`，权限 600，属主是专用系统用户。
   口令只在这个文件里，不写进 unit（unit 对所有用户可读）。
6. **装 systemd unit 并启动** —— `ProtectSystem=strict`、`CapabilityBoundingSet=`（一个都不给）、
   `ReadWritePaths=` 只开放配置目录。

   > 为什么不用 `DynamicUser=yes`：那样最干净，但动态 UID 无法拥有 `/etc` 下的文件，
   > 管理面就写不了配置（实测过，即使配上 `ReadWritePaths` 也不行）。改用固定的
   > nologin 系统用户，`DynamicUser` 隐式带的那批加固项全部显式写回 unit。
   > 服务本身仍然一个 capability 都不需要——FREEBIND 是 per-socket 选项。
7. **自检** —— 服务活着、端口在听、local 路由生效，最后**真的从代理走一趟**，
   看对端报回来的源 IP 是不是指定的那个。失败时读服务端日志给出确切原因，
   而不是笼统地猜。

幂等：重复执行不会重置口令、不会重复写配置。

## 发布新版本

二进制**跟源码一起提交**在 `dist/` 下，服务器上不需要装 Go，也不需要 Token。

```bash
./build.sh amd64 arm64        # 编译两个架构 + 生成 SHA256SUMS
git add -A && git commit -m "..." && git push
```

服务器上重新跑一次 `sudo ./deploy.sh` 即可升级（会保留现有口令和白名单）。

`CGO_ENABLED=0` 静态链接，产物约 6MB，不依赖目标机的 glibc——
实测在 alpine（musl，无 glibc）里也能直接跑。

> **仓库不会因此膨胀。** git 对同一路径的历次版本做 delta 压缩，而 Go 静态
> 二进制版本之间绝大部分内容是相同的。实测连续 8 次发布：每版只改版本号 →
> 零增长；每版新增一批功能代码 → 总共涨 0.2MB。8 版原始总量 88MB，
> 仓库实际 5.1MB。
>
> 会让它实打实变大的只有换 Go 版本（runtime 整体变了，delta 失效，
> 那一版多约 5MB）。真到了需要瘦身的那天，`deploy.sh` 里换个 URL
> 就能改回 Release 分发。

## 排错

| 现象 | 原因 |
|---|---|
| `cannot assign requested address` | 内核 < 4.15 不支持 FREEBIND，跑 `sudo ./deploy.sh` |
| 连上了但收不到响应 | 缺 local 路由，跑 `sudo ./deploy.sh --check` 确认 |
| `用户名（出口地址）无效` | 地址不在 `PROXY_IPV6_PREFIX` 内，或前缀配错 |
| `口令错误` 但口令是对的 | 用户名写成了冒号形态、被客户端切碎；改用破折号形态 |
| `出口地址不能含冒号` | 同上，把地址里的 `:` 全换成 `-` |
| `目标不在白名单内` | 调整 `PROXY_ALLOWED_HOSTS` |
| `目标没有可用的 IPv6 地址` | 目标只有 A 记录没有 AAAA，或本机无 IPv6 出口 |
| 管理面登录一直 429 | 失败 5 次后锁 5 分钟，等一会儿；或 `systemctl restart ipv6-proxy` 清掉计数 |
| 管理面改的配置重启后没了 | `PROXY_ENV_FILE` 没配。用 `--admin` 部署会自动写上 |

验证出口是否真的在变：
```bash
for i in 1 2 3; do
  curl -s --socks5-hostname 127.0.0.1:6080 \
       --proxy-user "2604-2dc0-143-8200--$i:$PROXY_PASSWORD" \
       https://api64.ipify.org; echo
done
# 应输出三个不同的 IP
```

## 开发

```bash
go test ./...        # 62 个用例
gofmt -l . && go vet ./...

# 无本机 Go 环境时（-race 需要 cgo，所以要装 gcc）：
docker run --rm -v "$PWD":/src -w /src -e CGO_ENABLED=1 golang:1.22-alpine \
  sh -c 'apk add --no-cache gcc musl-dev >/dev/null && go test -race ./...'
```

`deploy.sh` 本身也过 shellcheck：

```bash
docker run --rm -e LC_ALL=C.UTF-8 -v "$PWD":/src -w /src \
  koalaman/shellcheck:stable -f gcc deploy.sh build.sh
```
