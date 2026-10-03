# 操作与维护

[项目入口](../README.md) · [实现说明](../engine/README.md) · [历史验收](history.md)

本文记录现行入口和操作条件。它不是“一键重装”说明；换机器或更换网络后，要先核对网卡、网关、DNS、账户和文件权限。不要直接套用仓库中的机器配置。

## 组件清单

### 运行组件

系统任务定义来自 [config/launchd/](../config/launchd/)，安装在 `/Library/LaunchDaemons/`。表中任务由 launchd 管理，不要另外手动启动副本。

| 源码或来源 | 安装程序 | 任务标签或调用方式 |
| --- | --- | --- |
| [Go 代理核心](../engine/main.go) | `/usr/local/libexec/network-domain-engine` | `com.local.network-domain-proxy`，以 nobody 运行 |
| [Go DNS 观察服务](../engine/cmd/network-split-dns-event-route-agent/main.go) | `/usr/local/sbin/network-split-dns-event-route-agent` | `com.local.network-split-dns-event-route-agent` |
| [Go 健康检查](../engine/cmd/network-split-health/main.go) | `/usr/local/sbin/network-split-health` | `com.local.network-split-domestic-health`，每 30 秒唤起 |
| [Go 状态页](../engine/cmd/network-split-status/main.go) | `~/.local/share/network-split-log-guard/network-split-status` | 用户任务 `com.local.network-split-log-guard`，每 300 秒运行 |
| [默认路由守护](../scripts/network-split-guard.sh) | `/usr/local/sbin/network-split-guard.sh` | `com.local.network-split-guard`，含 30 秒周期检查 |
| [国内路由守护](../scripts/china-route.sh) | `/usr/local/sbin/china-route.sh` | `com.local.china-route` |
| 单独安装的 dnsmasq | `/usr/local/sbin/dnsmasq-network-split` | `homebrew.mxcl.dnsmasq` |
| [Go 地址策略](../engine/cmd/network-split-policy/main.go) | `/usr/local/sbin/network-split-policy` | 由守护调用，没有独立常驻任务 |

状态页使用本机 `~/Library/LaunchAgents/com.local.network-split-log-guard.plist`，不是系统 LaunchDaemon。该文件含绝对用户路径，不直接提交公开仓库；定义应保持原任务标签、300 秒间隔和输出位置。源码与 HTML 模板在 [statuspage](../engine/internal/statuspage/) 中。

### 人工工具

| 入口 | 用途及影响 |
| --- | --- |
| [network-domain-proxy-config](../engine/cmd/network-domain-proxy-config/main.go) | 按需构建，生成配置，不下载规则、不安装或修改路由 |
| [network-domain-proxy-deploy](../engine/cmd/network-domain-proxy-deploy/main.go) | 安装在 `/usr/local/sbin/`；部署、维护和清理需要管理员授权，具体影响见下表 |
| [network-domain-proxy-evidence](../engine/cmd/network-domain-proxy-evidence/main.go) | 按需构建，建立真实 TLS 连接并核对代理日志和内核连接；完整取证需要管理员权限 |
| [deploy-security-update.zsh](../scripts/deploy-security-update.zsh) | 批量更新地址策略、路由守护、DNS 观察服务与维护工具；会重载已启用的观察服务 |
| [install-network-split-dns-event-route-agent.sh](../scripts/install-network-split-dns-event-route-agent.sh) | DNS 查询日志和观察服务的初始化入口；会修改 DNS 配置并重启 dnsmasq，不用于日常清理 |
| [deploy-remote-access.zsh](../scripts/deploy-remote-access.zsh) | 可选的 SSH 加固安装、状态检查和卸载，见后文 |

旧的 `network-domain-proxy-deploy health-check` 保留兼容性，但已不作为定时任务入口。不要同时配置它和 `network-split-health`。兼容命令和初始化工具不等于正在运行的重复服务，删除前必须核对调用者。

### 配置与安装位置

| 仓库来源 | 去向或用途 |
| --- | --- |
| [dnsmasq 配置](../config/dnsmasq-network-split.conf) | `/usr/local/etc/dnsmasq-network-split.conf` |
| [中国地址表](../config/china_ip_list.txt)、[额外地址表](../config/domestic_extra_routes.txt)、[国内域名表](../config/domestic_domains.conf) | 对应文件安装到 `/usr/local/etc/` |
| [代理域名覆盖表](../config/domestic_proxy_hosts.conf)及地址表 | 配置生成器的输入，不是可直接运行的程序 |
| [代理任务定义](../config/launchd/com.local.network-domain-proxy.plist) | `/Library/LaunchDaemons/com.local.network-domain-proxy.plist` |
| [DNS 观察任务定义](../config/launchd/com.local.network-split-dns-event-route-agent.plist) | `/Library/LaunchDaemons/com.local.network-split-dns-event-route-agent.plist` |
| [健康任务定义](../config/launchd/com.local.network-split-domestic-health.plist) | `/Library/LaunchDaemons/com.local.network-split-domestic-health.plist` |
| [默认路由任务定义](../config/launchd/com.local.network-split-guard.plist) | `/Library/LaunchDaemons/com.local.network-split-guard.plist` |
| [国内路由任务定义](../config/launchd/com.local.china-route.plist) | `/Library/LaunchDaemons/com.local.china-route.plist` |
| [dnsmasq 任务定义](../config/launchd/homebrew.mxcl.dnsmasq.plist) | `/Library/LaunchDaemons/homebrew.mxcl.dnsmasq.plist` |
| [Chrome 配置](../config/chrome/) | 参考配置；分流工具升级不会自动覆盖正在使用的浏览器 |
| [SSH 配置](../config/sshd-remote-access.conf) | 可选模板，安装前还需确定登录账户；不是已部署状态的证明 |

生成的代理配置安装在 `/usr/local/etc/network-domain-proxy.json`，初始规则在 `/usr/local/etc/network-domain-rules-independent/`，规则缓存在 `/var/db/network-domain-proxy/independent-cache/`。路径约定以 [runtimecheck/paths.go](../engine/internal/runtimecheck/paths.go) 和 [proxyconfig](../engine/internal/proxyconfig/) 为准。

仓库文件只是来源。只有相关部署入口说明的文件才应安装，不能把整个 `config/`、`archive/` 或 `local/` 复制到系统目录。

## 构建与部署

### 准备候选程序

从 `engine/` 执行。下面的 `STAGE` 必须换成本任务独有、已经创建的系统临时目录；不要使用仓库根目录，也不要使用其他任务的暂存目录。

```sh
STAGE="/path/to/existing/task-stage"
CGO_ENABLED=0 GOTOOLCHAIN=go1.26.8 go build -trimpath -buildvcs=false \
  -ldflags '-s -w' -o "$STAGE/network-domain-engine" .
CGO_ENABLED=0 GOTOOLCHAIN=go1.26.8 go build -trimpath -buildvcs=false \
  -o "$STAGE/network-domain-proxy-deploy" ./cmd/network-domain-proxy-deploy
```

按实际操作构建所需程序即可，不要每次都重编译整套系统。构建在普通账户下完成，安装才授权。逐字节复现历史二进制还要匹配当时的 Go 版本、目标平台及构建参数；版本号相同不代表哈希相同。

### 代理核心升级

1. 在同一暂存目录放入核心、部署工具、代理 plist，以及生成的 `config.json`。生成命令是 `go run ./cmd/network-domain-proxy-config "$STAGE/config.json"`，默认读取工作目录上方最近的 `config/`。
2. 准备 `domestic.json`、`foreign.json`、`china.json` 三份规则种子。来源 URL 由生成配置指定，下载必须验证 HTTPS 证书。它们是外部分类数据，不是引擎源码。
3. 候选试运行使用 nobody 身份，所需目录、二进制和种子须可读；诊断输出和私人数据仍应保密。
4. 管理员授权执行暂存部署工具的 `upgrade`。首次安装才用 `install`。它先验证参数和规则，启动隔离候选并探测国内外 HTTPS，成功后才停止旧核心、记录受影响文件、原子替换并检查新服务。
5. 验收配置、二进制哈希、实际出口和退出行为。通过后再明确删除对应验收备份及本次暂存材料；不要按通配符删除系统目录。

部署锁拒绝并发升级。上线失败会恢复涉及的文件和缓存并重启原服务；回滚失败会保留并报告恢复目录。成功升级保留一份验收备份，不能仅凭“安装成功”就删除。

`enable` 会先检查代理，再记录并修改系统 HTTP/HTTPS 代理设置；`rollback` 恢复的是这些代理设置，不是旧核心二进制。浏览器仍指向代理时，不要直接停掉代理进程。密码只在 macOS 授权窗口或本机终端输入。

### 维护工具、守护和健康任务

以下动作都由同一个 Go 部署工具处理，不能互相替代：

| 动作 | 暂存输入 | 实际影响 |
| --- | --- | --- |
| `install-tool` | 新部署工具本身 | 只替换维护工具；先检查备份清单，再核对核心 PID 与其他安装文件不变 |
| `install-route-guard` | 新部署工具、`network-split-guard.sh` | 检查语法、持有现有守护锁、原子替换该文件；不重启代理、DNS 或观察服务 |
| `install-health-maintenance` | 新部署工具、`network-split-health`、健康 plist | 先做真实有线 HTTP 预检，只重载原健康任务，等待新一轮成功样本并核对核心服务未变 |

健康程序从 `./cmd/network-split-health` 构建，使用与维护工具相同的参数。健康任务更换失败会恢复原工具、程序和 plist；验收成功或完整回滚后移除临时恢复目录。失败后遗留的恢复目录必须先审查，不能自动当作垃圾。

路由守护在执行 dnsmasq 配置测试前，要求固定程序是可执行的普通文件、不是符号链接，且符合 `root:wheel:555` 基线。程序缺失或不安全时只报警，不会从 Homebrew 自动导入。父目录、DNS 配置和服务定义仍必须受管理员保护；这不是程序来源的密码学验证，也不替代 launchd 自身的权限检查。

### 状态页

状态页程序从 `./cmd/network-split-status` 构建。已有程序的只读取证入口是：

```sh
"$HOME/.local/share/network-split-log-guard/network-split-status" -check
```

`-check` 会进行有限的真实 DNS/HTTP 探测并输出证据，不写 HTML 或状态文件；原始输出只留本机。它不是无网络请求的离线检查。

原用户任务调用 `network-split-status -output /absolute/path/network-split-status.html`。可用 `-state`、`-log` 显式指定状态和日志路径。替换时保留原任务标签、频率、绝对输出路径和错误日志位置；不要另建一份 LaunchAgent。先在本任务临时目录试运行，再验收实际任务参数、程序哈希和新一轮输出。

程序不会修改网络，境外 HEAD 请求绑定 Wi-Fi，不跟随重定向、不下载正文。它按 IP 路由判断当前样本，分别显示 `policy-excluded`、解析失败和漂移。403/404 只说明收到 HTTP 响应，不证明应用可用。

### 仍保留的 Shell 安装入口

`deploy-security-update.zsh` 是批量安装路径，不是 Go `install-route-guard` 的别名。它需要平铺暂存目录，包含：
- `network-split-policy`、`network-split-dns-event-route-agent`、`network-domain-proxy-deploy`；
- 两份路由守护、观察服务 plist 和安装脚本本身。

它检查脚本语法、地址策略的正反例及观察服务的 `-check`，等待路由重建结束后备份并逐个原子替换文件。已启用的观察服务会被重载；未启用的不会被自动启动。失败会尝试恢复，成功后才移除已退役的 Python 文件。该路径不重启 dnsmasq。

`install-network-split-dns-event-route-agent.sh` 则会配置查询日志并重启 dnsmasq。不要把它当作无中断更新工具。这两项保留给明确的安装场景，不在普通整理、健康检查或清理时执行。

DNS 日志保持安装规定的所有者与权限。旧观察服务没有记录路由所有权，迁移时只能根据旧日志和策略移除已确认的过时路由，不能清空所有主机路由。

## 备份与残留

部署工具除帮助信息外需要管理员授权，复用现有部署锁。下表中的路径、哈希必须来自本次审查，不接受猜测值。

| 命令 | 范围 |
| --- | --- |
| `backups` | 列出已识别备份及异常，不删除 |
| `inspect-backup <exact-path>` | 检查一份备份的格式、内容哈希及限制 |
| `remove-backup <exact-path>` | 删除明确指定、已确认可舍弃的备份 |
| `residues` | 检查已知健康临时状态和退役 DNS 状态 |
| `cleanup-residues` | 清理符合条件的已知残留，保留不明或非空旧状态 |
| `cleanup-health-state` | 仅处理健康临时状态，不清备份 |
| `cleanup-policy-cache <sha256>` | 仅删除已审阅的旧 Python 地址策略缓存及空目录，不接受路径或通配符 |

备份识别不等于删除授权。工具拒绝危险路径、链接、额外内容、占用、检查失败和检查期间变化；清理后核对核心 PID 与安装文件。删除完成但事后验证失败，会与“尚未删除”分别报告。

健康任务的自动回收仅限已知临时写入：持有 POSIX `fcntl` 锁，保留五分钟宽限期、活动状态、未知内容和非空旧 DNS 状态。私人历史归档不属于自动回收范围。

## 日志与状态

根目录 `network-split-status.html`、用户缓存目录中的状态页状态、`/var/db/network-split-domestic-health.state` 及代理规则缓存都是运行数据，不提交 Git，也不按“文件多”直接删除。

系统 `/etc/newsyslog.d/network-split.conf` 对部分日志定期检查轮转。阈值不是即时硬上限；DNS 查询日志还被观察服务实时读取，不能随意截断或删除。

| 日志 | 用途 | 当前边界 |
| --- | --- | --- |
| `dnsmasq-network-split-query.log` | DNS 路由决策输入 | 观察服务消费后在 64 MiB 处压缩；消费停止或落后时可能超过阈值 |
| `network-split-guard.log`、`china-route.log` | 路由变化与修复 | newsyslog 1 MiB 阈值，各十份归档 |
| `network-split-dns-event-route-agent.log` | DNS 观察结果 | newsyslog 1 MiB 阈值，五份归档；轮转后重新打开文件 |
| `network-split-domestic-health.log` | 健康探测、恢复与节奏调整 | newsyslog 1 MiB 阈值，五份归档 |
| `network-domain-proxy/service.log` | 代理连接和规则事件 | 新写入文件 2 MiB 上限，三份编号归档；启动时已有超大文件会被归档 |
| `~/Library/Logs/network-split-log-guard.log` | 状态页变化和有限条异常原因 | 每份 1 MiB，三份归档；拒绝静默截断迁移前已有超大日志 |
| 路由守护及健康任务 `.out` / `.err` | 任务启动、退出异常 | newsyslog 256 KiB 阈值，各三份归档 |
| DNS 观察服务和用户状态页任务的 stdout/stderr | 启动与发布失败 | 不包含在上述主日志上限保证中，须单独检查 |

原来的大状态日志和旧源码保存在 `local/archive/retired-status-page-20261003/`，旧缓存历史件在 `local/archive/python-cache/`。这些归档已退出运行位置，但不等于获准删除；保持 Git 忽略，不复制回部署目录。

## 验证

在 `engine/` 中运行：

```sh
GOTOOLCHAIN=go1.26.8 go test -race -timeout 5m ./...
GOTOOLCHAIN=go1.26.8 go vet ./...
GOTOOLCHAIN=go1.26.8 go test -tags integration -run Integration -timeout 5m .
```

在仓库根目录运行现有离线检查：

```sh
zsh tests/security_shell.zsh
zsh tests/recovery.zsh
zsh tests/route-snapshot.zsh
zsh tests/remote_access.zsh
git diff --check
```

[GitHub 检查配置](../.github/workflows/checks.yml)使用 macOS、固定 Go 版本和固定 Action 提交，令牌只有读取权限。它不部署，不运行 `NETWORK_SPLIT_LIVE=1` 的真实网络测试。已有离线测试不修改系统路由或 `/etc/ssh`。

真实出口验收使用 `network-domain-proxy-evidence`：建立验证证书的 TLS 连接，将本次代理日志与唯一新增的内核连接对应。缺少管理员权限或无法唯一归因时，不能把结果说成已确认；报告只保留在本机。

`NETWORK_SPLIT_LIVE=1` 会启用真实网络集成测试，`NETWORK_SPLIT_RULES` 用于选择规则种子目录。它注入无效网卡来检查失败处理，不是真正断开物理 Wi-Fi。按需授权运行，不作为每次整理的必选动作。

验收分开记录：文件与版本是否一致、任务是否成功执行、请求实际走哪条网卡、用户症状是否改善。测试或单次 HTTP 成功不能替代后两项。

## 可选 SSH

[SSH 模板](../config/sshd-remote-access.conf)安装后位于 `/etc/ssh/sshd_config.d/050-remote-access.conf`。2026-10-03 整理时该文件尚未安装，不能把仓库中有模板当作已启用远程登录。

模板要求一个明确账户使用密钥登录、禁止 root 登录。安装工具先在临时配置中检查实际生效设置，拒绝被其他更早的配置削弱，失败时恢复原文件。不同账户重装不能悄悄更改 `AllowUsers`；卸载只移除带自身标记的配置。

已有工具的状态入口如下，它会读取真实系统配置：

```sh
sudo /bin/zsh scripts/deploy-remote-access.zsh status
```

`install` 与 `uninstall` 会修改系统，必须单独确认。远程登录、路由器端口转发、DDNS 和客户端密钥仍需各自配置；启用此功能不属于普通项目整理。FileVault 启用的机器重启后，在本地解锁前可能无法提供 SSH，需另行安排远程重启方案。

旧版本的内核路由分析见[历史验收](history.md#远程登录方案)。不要将旧内核源码分析当作当前机器掉线场景的实测。
