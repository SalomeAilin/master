# 双线网络分流

境外走 Wi-Fi，国内走有线。分流服务已由系统任务管理，正常使用不需要手动运行安装或清理命令。

## 平时只看这里

- **看状态**：本机 `network-split-status.html` 每五分钟更新。它是抽查结果，不是所有网站、所有连接都正常的保证。
- **有异常**：先按发生时间查现有日志和实际连接出口，不用重复安装、重启整套服务或清空缓存代替排查。
- **要更新**：构建、推送和上线是三步；只更新本次涉及的组件，系统安装必须经过管理员授权。

自研 Go 核心负责代理，DNS、健康检查、状态页和路由守护各自负责一件事。分开运行是为了隔离权限和故障，不需要把这些内部组件都当作日常操作入口。

<details>
<summary>维护时展开：检查、更新与安全清理</summary>

## 检查

在 `engine/` 运行：
```sh
GOTOOLCHAIN=go1.26.8 go test -race -timeout 5m ./...
GOTOOLCHAIN=go1.26.8 go vet ./...
GOTOOLCHAIN=go1.26.8 go test -tags integration -run Integration -timeout 5m .
```

在仓库根目录运行：
```sh
zsh tests/security_shell.zsh
zsh tests/recovery.zsh
zsh tests/route-snapshot.zsh
zsh tests/remote_access.zsh
git diff --check
```

[GitHub 检查](.github/workflows/checks.yml)执行同类离线测试，不自动部署。仅显式设置 `NETWORK_SPLIT_LIVE=1` 才运行真实网络集成测试；`NETWORK_SPLIT_RULES` 指定种子目录，无效网卡测试不等于真实断开 Wi-Fi。

本机状态检查用 `"$HOME/.local/share/network-split-log-guard/network-split-status" -check`。它会进行有限 DNS/HEAD 请求，但不写状态页。代理出口用取证工具核对；原始输出留本机。状态页 OK 或 HTTP 403/404 只说明当次样本情况，不证明应用可用、视频流畅或长期稳定。

## 维护

以下是 Go 部署工具的人工动作。帮助信息之外需要管理员授权；密码只在系统窗口或本机终端输入。工具共用部署锁，不能把“代码已推送”当作“线上已更新”。

| 动作 | 输入或影响 |
| --- | --- |
| `install` / `upgrade` | 首次安装 / 升级核心；需要核心、工具、配置、代理 plist 和三份规则种子，会切换代理进程 |
| `install-tool` | 只替换维护工具；先确认健康任务已独立，再核对其他文件及核心 PID 不变 |
| `install-route-guard` | 工具与守护文件放在同一暂存目录；持锁替换守护，不重启核心、DNS 或观察服务 |
| `install-health-maintenance` | 需要工具、独立健康程序和健康 plist；真实有线预检后，仅重载原健康任务并等待新样本 |
| `enable` / `rollback` | 设置 / 恢复系统代理设置；`rollback` 不是回退核心二进制 |
| `backups` / `inspect-backup <exact-path>` | 列出或检查备份，不删除 |
| `remove-backup <exact-path>` | 删除明确指定且已确认可舍弃的备份 |
| `residues` / `cleanup-residues` | 检查 / 清理已知状态残留，保留未知内容与非空旧状态 |

清理前检查归属、哈希和占用，拒绝危险链接、额外文件及检查期间变化。健康任务的自动回收限于持锁后的已知临时写入，保留五分钟宽限期；私人归档不是自动清理对象。

维护工具的 `--help` 按检查、清理和安装分组。已退役的健康别名、重复清理入口和一次性 Python 缓存清理命令不再接受调用，也不会悄悄转成其他动作。旧环境须先迁移到独立健康任务，再更新维护工具或核心。

### 构建与上线

从 `engine/` 构建，`STAGE` 换成本任务独有、已经创建的系统临时目录，不使用仓库根目录：
```sh
STAGE="/path/to/existing/task-stage"
CGO_ENABLED=0 GOTOOLCHAIN=go1.26.8 go build -trimpath -buildvcs=false \
  -ldflags '-s -w' -o "$STAGE/network-domain-engine" .
CGO_ENABLED=0 GOTOOLCHAIN=go1.26.8 go build -trimpath -buildvcs=false \
  -o "$STAGE/network-domain-proxy-deploy" ./cmd/network-domain-proxy-deploy
```

- 核心升级还需 `go run ./cmd/network-domain-proxy-config "$STAGE/config.json"` 生成配置，加入代理 plist，以及从配置指定 URL 经证书验证下载的 `domestic.json`、`foreign.json`、`china.json`。其他 Go 命令按表中的源码入口构建，只准备本次所需组件。
- 候选核心以 nobody 试运行，暂存目录、二进制和种子须可读；私人诊断数据仍需保密。验证成功后才停旧核心并原子替换，失败恢复原文件；回滚失败时保留恢复目录。
- 验收实际文件哈希、任务参数、新一轮执行结果和连接出口。成功升级留下的验收备份须另行确认后删除；浏览器仍指向代理时，不能直接停止核心。复现旧二进制要匹配当时源码、Go 版本、平台和构建参数。
- 更新状态页时保留现有用户任务标签、300 秒间隔和绝对输出路径，不另建任务；`-output`、`-state`、`-log` 指定其文件位置，先在本任务临时目录验证。
- 批量安全安装脚本需要三个 Go 程序（策略、观察服务、部署工具）、两份路由守护、观察服务 plist 和脚本本身。它会重载观察服务；DNS 初始化脚本还会重启 dnsmasq，都不能当作无中断清理工具。
- SSH 是可选操作，状态入口为 `sudo /bin/zsh scripts/deploy-remote-access.zsh status`；`install`、`uninstall` 必须另行确认。模板存在不代表远程登录、密钥、端口转发已配置，FileVault 还会影响重启后的远程可达性。

</details>

<details>
<summary>开发或排查时展开：组件、日志与实现边界</summary>

## 程序与位置

除注明位置的项目外，安装程序在 `/usr/local/sbin/`，系统任务定义在 `/Library/LaunchDaemons/`。源码与安装副本用途不同，不能把后者当作重复文件删除。

| 程序或入口 | 职责与运行方式 |
| --- | --- |
| [network-domain-engine](engine/main.go) | 代理核心，位于 `/usr/local/libexec/`；`com.local.network-domain-proxy` 以 nobody 运行 |
| [network-split-dns-event-route-agent](engine/cmd/network-split-dns-event-route-agent/main.go) | 常驻 DNS 观察服务；同名 `com.local.` 系统任务 |
| [network-split-health](engine/cmd/network-split-health/main.go) | 独立健康检查；`com.local.network-split-domestic-health` 每 30 秒唤起，实际探测间隔为 30/60/120 秒 |
| [network-split-status](engine/cmd/network-split-status/main.go) | 用户任务 `com.local.network-split-log-guard` 每 300 秒生成状态页；安装在 `~/.local/share/network-split-log-guard/` |
| [network-split-policy](engine/cmd/network-split-policy/main.go) | 按需判断地址是否允许走国内路由，不是常驻服务 |
| [network-domain-proxy-config](engine/cmd/network-domain-proxy-config/main.go) | 按需构建并生成配置，不修改网络 |
| [network-domain-proxy-deploy](engine/cmd/network-domain-proxy-deploy/main.go) | 人工部署和维护，不是定时任务 |
| [network-domain-proxy-evidence](engine/cmd/network-domain-proxy-evidence/main.go) | 按需构建，核对真实代理连接与内核出口；完整取证需要管理员权限 |
| [network-split-guard.sh](scripts/network-split-guard.sh)、[china-route.sh](scripts/china-route.sh) | 默认路由和国内路由守护；对应 `com.local.network-split-guard`、`com.local.china-route` |
| `dnsmasq-network-split` | 单独安装的 DNS 解析器，由 `homebrew.mxcl.dnsmasq` 管理 |
| [deploy-security-update.zsh](scripts/deploy-security-update.zsh) | 批量安装策略、守护和观察服务，会重载已启用的观察服务 |
| [install-network-split-dns-event-route-agent.sh](scripts/install-network-split-dns-event-route-agent.sh) | DNS 日志初始化，会修改 DNS 配置并重启 dnsmasq |
| [deploy-remote-access.zsh](scripts/deploy-remote-access.zsh) | 可选 SSH 配置的安装、检查和卸载，不属于日常维护 |

系统 plist 来源是 [config/launchd/](config/launchd/)。状态页使用本机 `~/Library/LaunchAgents/com.local.network-split-log-guard.plist`，其中的用户绝对路径不公开。健康任务只运行独立的 `network-split-health`，不再经过部署工具。

[config/](config/) 中的 DNS 配置、中国地址表、额外地址表和国内域名表安装到 `/usr/local/etc/`；代理覆盖表是生成器输入。代理配置为 `/usr/local/etc/network-domain-proxy.json`，规则种子在 `network-domain-rules-independent/`，缓存位于 `/var/db/network-domain-proxy/independent-cache/`。完整路径以 [runtimecheck/paths.go](engine/internal/runtimecheck/paths.go) 为准，Chrome 和 SSH 模板不会随普通升级自动启用。

## 日志

| 日志 | 上限或轮转条件 |
| --- | --- |
| `dnsmasq-network-split-query.log` | 观察服务消费后在 64 MiB 处压缩；停读或落后时可超过阈值，不能随意删除 |
| `network-split-guard.log`、`china-route.log` | newsyslog 1 MiB 阈值，各十份归档 |
| `network-split-dns-event-route-agent.log`、`network-split-domestic-health.log` | newsyslog 1 MiB 阈值，各五份归档 |
| `network-domain-proxy/service.log` | 新写入文件 2 MiB 上限，三份归档；已有超大日志先归档 |
| `~/Library/Logs/network-split-log-guard.log` | 每份 1 MiB，三份归档；迁移前已有的大日志不会静默截断 |
| 守护与健康任务的 `.out` / `.err` | newsyslog 256 KiB 阈值，各三份归档 |
| 观察服务与状态页任务的 stdout/stderr | 不包含在上述主日志上限保证中，须单独检查 |

系统轮转配置在 `/etc/newsyslog.d/network-split.conf`；周期检查的阈值不是即时硬上限。`network-split-status.html`、健康状态和规则缓存都是运行数据，不进入 Git。

## 实现边界

- 支持 HTTP、CONNECT、WebSocket 和 SOCKS5 TCP；不提供 TUN、SOCKS UDP、TLS 解密或 IPv6 代理。连接绑定内核网卡，失败不换接口；直连程序仍依赖周期性 IP 路由守护，不能承诺即时阻断。
- 已知域名按“境外保护、国内覆盖、境外库、国内库”判断；未知域名按首个公共 IPv4 选择地理组，只在同组地址中重试。IP 归属不等于网站归属，特殊地址拒绝连接。
- [DNS](engine/dns.go)使用证书验证的 DoH，没有明文回落；成功结果按 TTL 缓存，最长五分钟、每解析器最多 4096 个域名。隧道双向都空闲五分钟才超时，真实半关闭后另一方向有 30 秒继续发送。
- [规则更新](engine/rules.go)每小时经 Wi-Fi HTTPS/ETag 重验证，每份最多 16 MiB；无效数据保留最后可用规则。Wi-Fi 按流量计费，不增加重复保活。
- DNS 观察按进程、查询 ID 和客户端关联 CNAME，不把共享 CDN 永久标成国内；路由必须再通过地址策略。健康检查只有确认漂移才请求已有守护，HTTP 错误和延迟本身不重启服务。
- dnsmasq 固定程序必须符合 `root:wheel:555` 基线，异常时报警，不从用户可改写的 Homebrew 目录自动复制执行；父目录、配置和任务定义也须受管理员保护。

本仓库的 Go 模块只依赖标准库；Go、macOS 和 [外部分流数据](https://github.com/MetaCubeX/meta-rules-dat)保留各自权利及[数据许可证](https://github.com/MetaCubeX/meta-rules-dat/blob/master/LICENSE)。旧核心的[许可证原文](archive/sing-box-LICENSE)保留不变，自研不代表取得上游作者权利。

## 文件与历史

`engine/` 是源码和包内测试，`config/` 是配置来源，`scripts/` 是仍有用途的守护与安装工具，`tests/` 是既有回归检查。`archive/` 保留公开历史材料；`local/docs/` 与 `local/archive/` 留存私人文档及历史文件，均被忽略，不按文件名直接删除。

旧操作、实现和测量记录保存在[精简前的 Git 版本](https://github.com/SalomeAilin/master/tree/057bacc903164a81c23b39830f844d2dd1ca9a00)。不再另放重复 Markdown 副本；历史测量不能代替当前验收。

</details>

助手约束见 [AGENTS.md](AGENTS.md)，少量排查经验见[共同记忆](docs/project-memory.md)。部署细节和协议限制保留在本页，不再另写重复说明。
