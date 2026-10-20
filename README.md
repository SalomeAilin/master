# 双线网络分流

境外走 Wi-Fi，国内走有线；代理连接失败时不换到另一条线路。

**2026-10-16 已上线 0.3.5-native-dns。** 修复未收录域名判为境外后仍沿用国内 DNS 答案的问题：现在用 Wi-Fi 加密 DNS 重新解析，失败不回退。首轮完整验收通过，程序与测试构建逐字节一致，配置和规则未变，状态页 22 项检查通过。此前返回 502 的站点经生产代理返回 200，证书校验通过；国内、境外抽样的连接日志与内核套接字出口一致。单元测试、并发检测、离线集成测试及隔离双线测试通过；这些结果不代表所有网站、视频播放或长期稳定性已验证。断网 FALLBACK 仍只有回归测试覆盖，未做真实断开 Wi-Fi 的验证。

## 平时使用

正常联网不需要手动运行维护命令。本机 `network-split-status.html` 每五分钟更新；出现异常先对照发生时间查日志和实际连接，不靠反复安装、重启或清空缓存代替排查。

现在只使用一个入口：
```sh
/usr/local/libexec/network-domain-engine status
/usr/local/libexec/network-domain-engine --help
```

`status` 做有限 DNS 和 HEAD 抽查，不改网络。需要核对代理真实出口时，经管理员授权使用同一程序的 `evidence` 命令；它把连接日志与内核套接字对应起来，无法唯一归属时明确报告不确定。原始结果只留本机。状态页 OK、HTTP 403/404 或单次成功连接都不能证明视频流畅或长期稳定。

### 百度网盘的临时有线会话

**2026-10-20，0.3.9 已部署，通过系统升级验收、本机双向 PF 门槛和实际有线下载核验。** 约 1 GB 的源码归档已完整下载并与原件哈希匹配；采样关联了写入文件的原生辅助进程、有线连接字节和 PF 双向计数，受控进程没有 Wi-Fi 接收增量。按用户要求未做物理拔线，真实链路断开后的客户端状态及重新接线恢复仍未验证。0.3.9 识别内核已确认的僵尸进程，只对 ESRCH 最多重做一次完整扫描，仍失败就保留屏障。它不安装新后台任务，不改现有 DNS、路由或系统代理；只有显式 `start` 才创建会话和专用 PF 规则，平常的 `run`、`service` 与原状态任务不启用此功能。

```sh
/usr/local/libexec/network-domain-engine wired-app plan
sudo /usr/local/libexec/network-domain-engine wired-app preflight -uid "$(id -u)"
sudo /usr/local/libexec/network-domain-engine wired-app open -uid "$(id -u)"
sudo /usr/local/libexec/network-domain-engine wired-app start -uid "$(id -u)"
```

`open` 是日常受保护入口：没有会话时按 `start` 的顺序先建立 PF，再打开网盘；已有同用户的活动会话时，核对进程身份、PF、代理响应和持锁 Go 进程后复用，不再创建控制器或代理。检查不完整或发现普通实例就拒绝，不会退回普通启动。原始 `start` 继续要求没有会话。

本地“百度网盘·有线保护”入口只通过系统授权调用已安装 Go 的 `open`，冷启动仍可能要求认证。入口在后台等待会话结束，收尾由 Go 管理；重复点击正在等待的入口不保证再次核验或切换窗口。它只覆盖经此入口创建的会话；直接打开原网盘、原登录项及独立更新器重启仍可能绕过。自动保护入口不等于对原应用所有启动方式的系统级拦截。

部署仍按下文的管理员授权流程进行；上述命令只有在更新原 Go 程序后才可用。`preflight` 只读检查。开始前须明确同意退出、重启百度网盘，并先关闭现有主程序及下载 helper；程序发现旧实例会拒绝运行，不自行结束用户应用。只支持 `/Applications/BaiduNetdisk.app` 的原始签名程序，应用仍以原 UID 运行，将主 GID 换成未占用的会话 GID，保留原补充组。旧主组不会自动成为额外补充组，不修改系统组数据库或组上限。

会话使用现有配置中经过交叉核对的 Ethernet/LAN 接口。临时代理的连接和 DoH 通过内核 `IP_BOUND_IF` 绑定该接口，关闭 Multipath TCP；原生辅助程序的受控 IPv4 TCP 只允许在该有线接口双向收发，其余接口、IPv6 和 UDP 双向阻断。PF 不改变路由选择，原生连接选到其他接口时仍会失败。临时代理监听 `127.0.0.1:17891`，由 root 预绑定并把同一个监听 socket 交给 nobody，不释放端口后重新绑定；出网 socket 由低权限代理创建。PF 允许受控 UID/GID 连接该端口，并要求入站服务 socket 保持 root 创建的凭据；有线及四个回环方向均不创建 state，其他本机代理仍被阻断。百度网盘内的 HTTP 代理需设为这个地址。

PF 检查采取严格的支持范围：主过滤规则须能到达现有 `com.apple/*` 入口，不能跳过接口，不能有本功能之外的 pass、quick、转换旁路或既存 state。遇到不兼容规则会拒绝，不重载全局规则、不清空连接。专用规则放在 `com.apple/000.network-domain-wired-app`；只释放本会话的 PF token。管理员须验证本机 listener/accept 的 PF 凭据行为、进程身份和 socket 句柄持有者；离线测试不能代替这些验证。

`start` 在前台管理本次会话。应用及 helper 都退出，控制器已见的 socket 对象在两次完整扫描中均无持有者后，才撤销规则和退出；代理故障或控制进程中断时保留 PF。仍有应用、已见 socket 被其他进程持有、身份不明或检查失败时不解除阻断。可用下列命令检查、恢复或在手动关闭应用后释放：

```sh
sudo /usr/local/libexec/network-domain-engine wired-app status
sudo /usr/local/libexec/network-domain-engine wired-app evidence
sudo /usr/local/libexec/network-domain-engine wired-app recover
sudo /usr/local/libexec/network-domain-engine wired-app release
```

`evidence` 按精确 PID 采样代理和当前受控网盘进程，最多 64 个，输出三次全接口连接 CSV、前后各不超过 128 KiB 的 PF label 计数，以及最近 128 KiB 私有代理日志。采样前后核验代理、进程启动身份和 PF；正常退出或新出现的辅助进程另行列出，PID 被复用或身份改变则拒绝输出已核验结果。命令只读，不下载、不写报告、不自动判定下载成功。实际验收须把具体文件增长与对应进程、连接、接口和双向计数关联；原生辅助程序的流量不会出现在代理日志里。输出含本机连接信息，只留本机。

恢复不会自动重启应用或拆除仍有进程的屏障。GUI 启动器须先登记 root 进程身份并取得确认才可创建应用；释放也等待这个启动器退出，避免启动超时后才出现应用。中途已清空专用规则的释放阶段会如实记录，可在确认进程/socket 为空后继续释放自己的 token；未知规则或状态会停止自动清理。小型 root 状态保留在 `/var/db/network-domain-wired-app`，临时缓存采用 root 所有的父目录与 nobody 所有的 worker 子目录，路径记录在状态中，成功释放时通过固定目录描述符清理。存在活动或未收尾会话时 `upgrade` 拒绝执行，并持有与会话创建相同的锁直到升级结束。应用签名校验兼容标准的 root:admin、775 的 `/Applications`，不改变其权限；管理员替换应用或泄漏 root 监听 FD 均超出普通用户隔离边界。

保护按继承会话身份的正常应用进程设计。libproc 不提供原始 socket 凭据，`status/evidence` 明确记为 unknown；控制器按持有进程记录已见对象的 SO、PCB、generation、family 和 protocol。完整扫描后，持久化仍可见的已见对象及本次新见对象，最多 4096 项，只有集合变化时重写。`status/evidence` 本身不保存新观察；旧状态缺少观察记录时不能冒充已采样，须显式恢复后再检查释放条件。首次观察前、扫描间完全未被观察到的 FD 转移、排队中的 rights，以及 Finder、LaunchServices、XPC 等普通 GID 外部 broker 均不在此保证内。发现外部 broker 参与下载时不得宣称全部锁线。五秒扫描不能补足内核覆盖；实际下载验收须关联文件写入、helper、临时代理、有线字节及双向 PF 计数。若要确认真实断线后的表现，还须在用户允许时保留 Wi-Fi、物理拔掉有线，核对停止传输和没有 Wi-Fi 回落；不做这一步时明确保留未测结论。UDP 用前后正常回显、独立 nonce 未到监听端及对应 deny 增长判断；Write 成功或超时、错误接口模拟都不能代替实机或真实拔线验收。

普通目标用户进程只有在 `proc_pidpath` 明确返回 ENOENT、内核名称不含 baidu/netdisk、不占用整个专用 GID 区间且不是已登记的应用、代理或启动器时，才允许保留内核身份和空路径继续扫描。前后须核对 PID、启动时间、UID、三个 GID 和内核名称；其他路径或 FD 错误仍拒绝。`preflight/start/status/evidence` 的 `unresolved_paths` 字段（取证分前后两次）列出最多 128 项，表示分类未知，不能据此证明与网盘无关；这些进程持有的已见 socket 仍会阻止释放。网盘、专用组和已登记进程继续要求完整路径，不会把路径缺失误报为退出。

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

网盘 PF 验收默认跳过。明确获准退出网盘后，先关闭原实例及辅助进程，再单独编译并以管理员身份运行；暂存目录及测试程序须允许 nobody 遍历和执行：

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -c \
  -o "$STAGE/wiredguard-live.test" ./internal/wiredguard
sudo env MASTER_WIRED_PF_LIVE=1 MASTER_WIRED_PF_UID="$(id -u)" \
  "$STAGE/wiredguard-live.test" -test.run='^TestWiredPFLive$' -test.timeout=90s -test.v
```

该测试只收发本机回环数据，分别检查 TCP/UDP、IPv4/IPv6 的出站和入站拦截，以及可信监听 socket 身份；不下载文件，也不自行退出用户应用。测试会临时加载专用规则并持久记录自己的 token；已有会话或不兼容规则会拒绝。正常结束先回收测试进程和套接字，再释放规则；被强制终止或无法确认归属时保留状态，按 `wired-app status/release` 检查收尾。通过本项后，还要另核对原生下载辅助程序的有线双向收发；物理拔线须经用户允许，未做时不能写成断线实测通过。

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
- `0.3.2` 的上线验收允许网络探测失败后最多两次完整复测，总时限十分钟。每轮重新核对文件和任务，使用新健康样本及新状态回执，再做 DNS 和国内外 HTTP 检查；只有全部通过才接受。复测仅唤起原状态任务，不重装、不重启代理或 DNS，不新增定时任务。权限、文件、启动参数、路由漂移或 DNS 安全检查异常直接回退；失败信息保留在部署输出中。
- 成功后退役旧独立程序、旧 Shell 守护和分散自启动定义，不删除用户日志、历史归档或未获准删除的备份。
- 后续升级同样准备新程序和三份种子，执行 `sudo "$STAGE/network-domain-engine" upgrade`，默认使用已安装的私有服务配置。升级不允许顺带改接口或状态页身份。
- DNS 策略不随升级安装。修改 `config/dnsmasq-network-split.conf` 后，先用 `sudo install -o root -g wheel -m 644` 把它放到 `/usr/local/etc/`，再执行 `upgrade`：隔离预检读的就是新策略，切换后 DNS 工作进程按新策略启动并参与验收。升级备份不含 DNS 策略，需要退回时以 Git 中的上一版为准。
- 上线后另核对程序哈希、任务参数、用户身份、DNS、套接字出口及日志。没有实际验收就不能把源码更新写成“线上已接管”。

已经统一运行的系统迁移到内置 DNS，使用同一个入口：
```sh
sudo "$STAGE/network-domain-engine" check-service -live -native-dns
sudo "$STAGE/network-domain-engine" upgrade -native-dns
```

第一条只在临时端口试运行 nobody DNS 工作进程，验证 UDP/TCP、国内外回答、AAAA 过滤和无效域名后退出；线上 DNS 和防火墙不变。第二条须另行确认：除替换程序外，还把 DNS 的显式防火墙放行从旧程序迁到主程序，不关闭防火墙、不扩大 DNS 监听地址。升级保留 DNS 策略及日志的原文件名，这些兼容数据路径中的 `dnsmasq` 不代表仍调用旧程序。验收成功才删除旧 DNS 二进制；失败恢复程序、任务、配置及原防火墙状态，恢复材料保留在同一验收备份中。

## 维护命令

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

- 支持 HTTP、CONNECT、WebSocket 和 SOCKS5 TCP；没有 TUN、SOCKS UDP、TLS 解密或 IPv6 代理。代理连接绑定网卡，失败不换接口。每个目标的建连总共最多等 10 秒：前面的地址各试 3 秒，最后一个地址（常常也是唯一的地址）用满剩余时间，热点若丢包，也给重传留出余地。
- 已知域名按境外保护、国内覆盖、境外库、国内库判断；未知域名先用国内 DNS 按首个公共 IPv4 选出口。国内组继续使用同组地址；境外组改用 Wi-Fi 加密 DNS 重新解析，失败就停止，不退回初次答案或有线。重新解析仍拒绝私网和不支持的地址，也不重新选择出口。IP 归属不等于网站归属，不能承诺网站全覆盖。
- 代理 DNS 使用证书验证的 DoH，无明文回落；成功结果按 TTL 缓存，最长五分钟、每解析器最多 4096 域名。隧道双向都空闲五分钟才超时，真正半关闭后另一方向有 30 秒继续发送。
- 规则每小时经 Wi-Fi HTTPS/ETag 重验证，每份最多 16 MiB；无效更新保留最后可用规则。热点按流量计费，不增加重复保活。
- 不使用代理的程序仍依赖周期性 IP 路由守护，存在检测空档，不能承诺即时阻断。Wi-Fi 不可用时先添加境外拒绝路由，再允许国内有线默认路由；恢复后先确认 Wi-Fi 默认路由，才解除阻断。阻断经状态页核实生效时，境外样本和境外探测记为 blocked；不存在域名检查若因境外 DNS 被阻断而失败，且本机 DNS 仍能解析国内对照域名，也记为 blocked。其余检查全部正常时页面显示 FALLBACK。Wi-Fi 正常、阻断未生效、出现劫持式回答或其他检查失败，仍报 BAD。
- DNS 观察按进程、查询 ID 和客户端关联 CNAME；不把共享 CDN 永久当成国内。所有 DNS 派生路由必须再次通过地址策略，健康检查不因 HTTP 错误或单次延迟重启服务。
- 旧版服务配置仅用于迁移与恢复兼容，仍检查 dnsmasq 的 `root:wheel:555` 安装基线，不从 Homebrew 自动复制执行。当前内置 DNS 模式不依赖该程序。
- 内置 DNS 使用与现有 DNS 相同的上游、域名后缀、监听地址及 TTL 设置。上游查询绑定选定网卡，UDP 截断后只在同接口改用 TCP；不会借另一线路重试。一次转发在整组上游里最多用 5 秒，状态页和路由守护等满 6 秒才判定解析失败；超过 1 秒的回答在查询日志中另记耗时。缓存最多 10000 项并设估算内存上限 32 MiB；失败不缓存，带客户端选项的查询不共享缓存。保留 hosts、私网反查、AAAA 过滤、环路检测和本地网段访问限制，拒绝上游返回的私网 A 地址及服务地址提示。它是有限的 DNS 转发器，不提供 DHCP、TFTP、DNSSEC 验证或 DoH；遇到未支持的旧配置项会拒绝迁移。
- 内置 DNS 模式要求主程序 `root:wheel:755`、工作进程 nobody 和严格匹配的 launchd 套接字定义。状态页按实际后端核对权限，不以删掉旧检查来掩盖不一致。

## 目录

`engine/` 是唯一 Go 模块，包内测试与源码同目录；`config/` 保存策略、DNS、Chrome 与可选 SSH 配置。`scripts/` 只剩可选 SSH 工具，`tests/` 保留对应检查。公开历史在 `archive/`，私人内容在被忽略的 `local/`，不另存旧源码副本。

旧程序和操作可从 [Git 历史](https://github.com/SalomeAilin/master/tree/93da85ee314542351ebf06bda139a5375fc0645f)恢复。Go 模块现在包含第三方 DNS 协议库，不再声称只依赖标准库。依赖固定在 `go.mod`/`go.sum`，[第三方许可](docs/THIRD-PARTY-NOTICES)随源码保留，分发二进制时也须附带。Go、macOS、dnsmasq 和[外部分流数据](https://github.com/MetaCubeX/meta-rules-dat)保留各自权利及许可证，旧核心的[许可证原文](archive/sing-box-LICENSE)保留不变。

</details>

协作约束见 [AGENTS.md](AGENTS.md)，少量排查经验见[共同记忆](docs/project-memory.md)。本页优先更新已有说明，不再堆叠重复文档。
