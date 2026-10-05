# 双线网络分流

境外走 Wi-Fi，国内走有线；代理连接失败时不换到另一条线路。

**2026-10-05 已上线 0.3.0-native-dns。** DNS 已由同一个 Go 主程序接管，旧 dnsmasq 的进程、启动定义、独立二进制和防火墙放行项已退役。安装哈希与构建产物一致，代理、DNS 和地址策略配置未变；UDP/TCP DNS、新健康样本、状态页发布回执及实际 HTML 哈希均通过验收。真实套接字与日志确认抖音、CSDN 走有线，GitHub 走 Wi-Fi。此次没有重启 Mac、人为断开 Wi-Fi 或进行视频播放测试，短期验收不等于长期稳定保证。

## 平时使用

正常联网不需要手动运行维护命令。本机 `network-split-status.html` 每五分钟更新；出现异常先对照发生时间查日志和实际连接，不靠反复安装、重启或清空缓存代替排查。

现在只使用一个入口：
```sh
/usr/local/libexec/network-domain-engine status
/usr/local/libexec/network-domain-engine --help
```

`status` 做有限 DNS 和 HEAD 抽查，不改网络。需要核对代理真实出口时，经管理员授权使用同一程序的 `evidence` 命令；它把连接日志与内核套接字对应起来，无法唯一归属时明确报告不确定。原始结果只留本机。状态页 OK、HTTP 403/404 或单次成功连接都不能证明视频流畅或长期稳定。

## 一个程序，多进程

代理、DNS 和项目维护功能都编入 `network-domain-engine`，不再分别构建策略、观察、健康、状态、部署和取证程序。后台业务不调用旧 Shell/Python 守护。主程序启动内部工作进程，launchd 负责重启与身份隔离：

| 内部职责 | 身份与调度 |
| --- | --- |
| 代理 | nobody，常驻，保持原端口、配置和轮转日志 |
| DNS 观察 | root，常驻，复用原查询关联和地址策略 |
| 默认路由、国内路由 | root，原生 Go，保留现有锁和故障阻断顺序 |
| 健康检查 | root，每 30 秒唤起；实际探测仍按 30/60/120 秒调整 |
| 状态页 | 原用户，每 300 秒更新原文件，不以 root 写用户目录 |
| DNS 服务 | nobody，常驻；同一主程序接收 launchd 交付的 UDP/TCP 53 端口 |

唯一自动启动定义是 `/Library/LaunchDaemons/com.local.network-split-service.plist`。内部任务定义放在 `/usr/local/etc/network-split-jobs/`，不会被系统目录扫描独立启动；全部由 [service 包](engine/internal/service/)生成，不另存一套手工模板。主程序重启时只接管路径、程序及参数均匹配的任务，不重启健康的工作进程。

多进程用于权限和故障隔离，只需维护同一个项目可执行程序；系统仍依赖 macOS 和第三方协议库，不能称只有一个进程或所有代码全部自研。

DNS 报文处理使用编译进主程序的 `miekg/dns v1.1.73`，运行时不调用 dnsmasq；出口选择、缓存、安全策略和部署由本项目实现。DNS 工作进程以 nobody 运行，53 端口由 launchd 创建并交接，不让解析报文的进程以 root 常驻。需要 `CGO_ENABLED=1` 调用 macOS 套接字激活接口。

<details>
<summary>维护：验证、迁移和更新</summary>

## 验证

在 `engine/` 运行：
```sh
GOTOOLCHAIN=go1.26.8 go mod download
GOTOOLCHAIN=go1.26.8 go mod verify
GOTOOLCHAIN=go1.26.8 go test -race -timeout 5m ./...
GOTOOLCHAIN=go1.26.8 go vet ./...
GOTOOLCHAIN=go1.26.8 go test -tags integration -run Integration -timeout 5m .
```

在仓库根目录运行 `zsh tests/remote_access.zsh` 和 `git diff --check`。SSH 测试只操作临时配置，不安装远程登录。路由策略、切换顺序、锁、DNS 恢复与迁移回滚的回归检查已在 Go 包内，不再提取旧脚本函数执行。

[GitHub 检查](.github/workflows/checks.yml)运行离线测试，并在系统服务域验证隔离任务的注册和普通用户启动，随后卸载测试任务；不部署或运行生产网络业务。显式设置 `NETWORK_SPLIT_LIVE=1` 才会运行真实双线集成测试，`NETWORK_SPLIT_RULES` 指定种子目录。错误网卡测试不等于真实拔掉 Wi-Fi。

## 构建

在 `engine/` 构建一次即可，`STAGE` 使用本任务独有的系统临时目录：
```sh
CGO_ENABLED=1 GOTOOLCHAIN=go1.26.8 go build -trimpath -buildvcs=false \
  -o "$STAGE/network-domain-engine" .
```

首次迁移，在普通用户身份下运行：
```sh
"$STAGE/network-domain-engine" prepare-service "$STAGE/service.json"
"$STAGE/network-domain-engine" check-service -c "$STAGE/service.json"
```

准备命令读取现有代理接口、网关、系统 DNS 和用户状态页任务，不猜测缺失值，不修改系统；生成的本机配置是私有文件，禁止提交。将已安装的 `domestic.json`、`foreign.json`、`china.json` 复制到同一暂存目录。候选二进制和种子需允许 nobody 读取，配置仍保持 600。

## 授权上线

管理员凭据只能输入系统授权窗口或本机终端，不发到聊天。优先直接调用 Go 程序；用户明确同意时，可以用 AppleScript 唤起系统授权窗口，但预检、安装与回退仍由 Go 完成，不再另写业务脚本。先单独预检，再确认允许短暂中断后切换：
```sh
sudo "$STAGE/network-domain-engine" check-service -c "$STAGE/service.json" -live
sudo "$STAGE/network-domain-engine" upgrade "$STAGE/service.json"
```

- `-live` 只临时启动隔离候选代理，检查国内和境外连接后退出；不安装、不停止现有服务。
- `upgrade` 复用现有代理配置、种子、DNS 和路由策略，先预检、快照，再停止旧任务并原子安装。迁移会中断当前连接，不能称无感升级。
- 验收要求任务身份和参数正确、新健康样本通过、状态任务成功退出并提交本次 OK 发布回执，以及国内外代理探测通过。回执复用原状态文件，记录检查与发布时间、页面路径、大小和 SHA-256；最终另以普通用户身份比对实际 HTML，避免让管理员读取受保护的文档目录。任一步失败恢复原文件与原先加载的任务；恢复失败保留备份并明确报错。
- 成功后退役旧独立程序、旧 Shell 守护和分散自启动定义，不删除用户日志、历史归档或未获准删除的备份。
- 后续升级同样准备新程序和三份种子，执行 `sudo "$STAGE/network-domain-engine" upgrade`，默认使用已安装的私有服务配置。升级不允许顺带改接口或状态页身份。
- 上线后另核对程序哈希、任务参数、用户身份、DNS、套接字出口及日志。没有实际验收就不能把源码更新写成“线上已接管”。

已经统一运行的系统迁移到内置 DNS，使用同一个入口：
```sh
sudo "$STAGE/network-domain-engine" check-service -live -native-dns
sudo "$STAGE/network-domain-engine" upgrade -native-dns
```

第一条只在临时端口试运行 nobody DNS 工作进程，验证 UDP/TCP、国内外回答、AAAA 过滤和无效域名后退出；线上 DNS 和防火墙不变。第二条须另行确认：除替换程序外，还把 DNS 的显式防火墙放行从旧程序迁到主程序，不关闭防火墙、不扩大 DNS 监听地址。升级保留 DNS 策略及日志的原文件名，这些兼容数据路径中的 `dnsmasq` 不代表仍调用旧程序。验收成功才删除旧 DNS 二进制；失败恢复程序、任务、配置及原防火墙状态，恢复材料保留在同一验收备份中。

## 维护命令

`0.3.1-native-dns` 的备份识别修复已通过测试，尚未替换线上 `0.3.0-native-dns`。指定的旧软件回滚包已用候选版安全清理，常驻服务 PID 和安装文件哈希未变；下面的未识别项提示及旧软件包支持需更新到 `0.3.1` 才会出现在已安装命令中。

`network-domain-engine maintenance --help` 显示现有动作：

| 动作 | 边界 |
| --- | --- |
| `backups`、`inspect-backup <exact-path>` | 检查备份；清单列出已识别格式及未识别的备份类名称，不删除 |
| `remove-backup <exact-path>` | 仅删除明确指定且已确认可舍弃的一份；核对内容、占用、PID 和安装哈希 |
| `residues`、`cleanup-residues` | 检查或回收已知状态残留，保留未知内容与非空旧状态 |
| `enable`、`rollback` | 设置或恢复系统代理；`rollback` 不是版本回退 |

维护共用部署锁。健康任务的自动回收只处理已知临时写入，并保留五分钟宽限期；不会清理私人归档。验收备份保留为恢复途径，删除前须明确确认。

备份清单的范围是 `/var/db`，不是全机历史文件清单；不会扫描 `/usr/local/etc` 的手工 `.bak`、旧日志或 Homebrew。已支持旧 `network-software-update.*` 回滚包的固定文件结构，严格限制子目录、文件大小和链接；未识别名称标为 `unrecognized`，不能删除。旧软件包仅在统一程序和内置 DNS 已运行时允许清理，并核对文件占用、内容哈希及运行状态。

`config [flags] output.json` 仅按仓库策略生成新的代理配置，不覆盖已有文件，也不会安装。可选 SSH 工具仍是 [deploy-remote-access.zsh](scripts/deploy-remote-access.zsh)，不属于网络后台；其安装、卸载必须另行授权，模板存在不代表远程登录可用。

</details>

<details>
<summary>排查：日志、源码与能力边界</summary>

## 数据和日志

代理配置为 `/usr/local/etc/network-domain-proxy.json`，统一服务配置为 `/usr/local/etc/network-split-service.json`。规则种子在 `/usr/local/etc/network-domain-rules-independent/`，缓存仍在 `/var/db/network-domain-proxy/independent-cache/`。这些本机内容及状态页不进 Git。

| 日志 | 轮转或压缩 |
| --- | --- |
| DNS 查询日志 | 观察进程消费后在 64 MiB 处压缩；内置 DNS 达到阈值时暂停写入，最多超出一批 8 KiB |
| 路由、观察、健康日志 | 沿用 newsyslog；路由十份归档，观察和健康五份，每份阈值 1 MiB |
| 代理 service.log | 新写文件 2 MiB，三份归档 |
| 用户状态日志 | 每份 1 MiB，三份归档，已有超大文件不静默截断 |
| 主服务和新增 stdout/stderr | 纳入现有 newsyslog，256 KiB 阈值、三份归档 |

不新增日志清理服务。newsyslog 的周期阈值不是即时硬上限，不能承诺磁盘永远不增长；查询日志不能未经判断直接删除。

状态任务直接使用原有用户日志，不建立额外的系统 stdout/stderr 文件。每次发布更新状态回执，但相同检查结果不重复写日志。

## 实现边界

- 支持 HTTP、CONNECT、WebSocket 和 SOCKS5 TCP；没有 TUN、SOCKS UDP、TLS 解密或 IPv6 代理。代理连接绑定网卡，失败不换接口。
- 已知域名按境外保护、国内覆盖、境外库、国内库判断；未知域名按首个公共 IPv4 选择地理组，只在同组重试。IP 归属不等于网站归属，不能承诺网站全覆盖。
- 代理 DNS 使用证书验证的 DoH，无明文回落；成功结果按 TTL 缓存，最长五分钟、每解析器最多 4096 域名。隧道双向都空闲五分钟才超时，真正半关闭后另一方向有 30 秒继续发送。
- 规则每小时经 Wi-Fi HTTPS/ETag 重验证，每份最多 16 MiB；无效更新保留最后可用规则。热点按流量计费，不增加重复保活。
- 不使用代理的程序仍依赖周期性 IP 路由守护，存在检测空档，不能承诺即时阻断。Wi-Fi 不可用时先添加境外拒绝路由，再允许国内有线默认路由；恢复后先确认 Wi-Fi 默认路由，才解除阻断。
- DNS 观察按进程、查询 ID 和客户端关联 CNAME；不把共享 CDN 永久当成国内。所有 DNS 派生路由必须再次通过地址策略，健康检查不因 HTTP 错误或单次延迟重启服务。
- 旧版服务配置仅用于迁移与恢复兼容，仍检查 dnsmasq 的 `root:wheel:555` 安装基线，不从 Homebrew 自动复制执行。当前内置 DNS 模式不依赖该程序。
- 内置 DNS 使用与现有 DNS 相同的上游、域名后缀、监听地址及 TTL 设置。上游查询绑定选定网卡，UDP 截断后只在同接口改用 TCP；不会借另一线路重试。缓存最多 10000 项并设估算内存上限 32 MiB；失败不缓存，带客户端选项的查询不共享缓存。保留 hosts、私网反查、AAAA 过滤、环路检测和本地网段访问限制，拒绝上游返回的私网 A 地址及服务地址提示。它是有限的 DNS 转发器，不提供 DHCP、TFTP、DNSSEC 验证或 DoH；遇到未支持的旧配置项会拒绝迁移。
- 内置 DNS 模式要求主程序 `root:wheel:755`、工作进程 nobody 和严格匹配的 launchd 套接字定义。状态页按实际后端核对权限，不以删掉旧检查来掩盖不一致。

## 目录

`engine/` 是唯一 Go 模块，包内测试与源码同目录；`config/` 保存策略、DNS、Chrome 与可选 SSH 配置。`scripts/` 只剩可选 SSH 工具，`tests/` 保留对应检查。公开历史在 `archive/`，私人内容在被忽略的 `local/`，不另存旧源码副本。

旧程序和操作可从 [Git 历史](https://github.com/SalomeAilin/master/tree/93da85ee314542351ebf06bda139a5375fc0645f)恢复。Go 模块现在包含第三方 DNS 协议库，不再声称只依赖标准库。依赖固定在 `go.mod`/`go.sum`，[第三方许可](docs/THIRD-PARTY-NOTICES)随源码保留，分发二进制时也须附带。Go、macOS、dnsmasq 和[外部分流数据](https://github.com/MetaCubeX/meta-rules-dat)保留各自权利及许可证，旧核心的[许可证原文](archive/sing-box-LICENSE)保留不变。

</details>

协作约束见 [AGENTS.md](AGENTS.md)，少量排查经验见[共同记忆](docs/project-memory.md)。本页优先更新已有说明，不再堆叠重复文档。
