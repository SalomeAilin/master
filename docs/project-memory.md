# 项目共同记忆

日常操作只看 [README](../README.md)，协作约束见 [AGENTS](../AGENTS.md)。这里只留容易重复踩到的坑；部署版本和成功记录查 Git，不继续逐次堆叠。精简前的[完整记录](https://github.com/SalomeAilin/master/blob/057bacc903164a81c23b39830f844d2dd1ca9a00/docs/project-memory.md)和[历史验收](https://github.com/SalomeAilin/master/blob/057bacc903164a81c23b39830f844d2dd1ca9a00/docs/history.md)仍可追溯。

- **2026-09-25，系统日志**：zsh 的 `log` 是内置命令；必须用 `/usr/bin/log show`。否则可能报 `too many arguments`，重定向错误后又被误判为“没有日志”。
- **2026-09-26，历史 Python 权限问题**：Claude 桌面中第三方 `/usr/local/bin/python3` 访问局域网曾报 `[Errno 65] No route to host`，Apple 自带 Python、curl、nc、ping 当时正常。不能据此判定路由器断网；该观察不证明 Codex 相同，当前运行组件已不用 Python。
- **2026-09-26，zsh 清理陷阱**：`set -e` 在函数中退出时，顶层 `EXIT` 陷阱可能不执行；还需处理 `ZERR`，用 `ZSH_SUBSHELL == 0` 限定主 shell 清理。参考 [SSH 安装工具](../scripts/deploy-remote-access.zsh)，不要删除条件分支中的必要错误处理。
- **2026-10-01，掉线时序**：历史样本中，守护实际间隔约 30–40 秒，掉线后 1–5 秒加阻断、恢复后 6–9 秒解除。阻断前的空档可能让直连境外流量走有线；代理因网卡绑定会失败。这些数字不是时限保证，也不代表已消除直连空档。
- **2026-10-02，取证权限**：直接在 zsh 中调用 netstat 能看到 nobody 引擎连接，新编译 Go 程序启动的 netstat 当时却被隐藏连接表。Go 取证工具因此用需要管理员权限的 lsof；空结果不等于没有连接，不能据此确认线路。
- **2026-10-02，热点流量**：独立每分钟保活任务 `com.local.network-split-foreign-keepalive` 已停用，不应顺手恢复。过去整页探测、重复保活和规则下载合计约 113 MB/日；优化后约 7 MB/日只是估算。新增境外探测仍须低频、只取响应头。
- **2026-10-03，状态页误报**：dnsmasq 权限不符、未遵循地址策略都曾导致 BAD。检查应区分 `policy-excluded`、解析失败和真实漂移，兼容 dnsmasq 的 `-C` 配置参数。状态页查的是 IP 路由，不等于代理域名出口验收；403/404 也不是应用可用证明。
- **2026-10-05，清理与验收**：备份清单不等于全机历史残留清单。曾因工具只识别三种前缀，漏掉旧 `network-software-update.*` 回滚包；汇报须说明扫描范围，并分别列出本次临时材料、保留的恢复备份和未处理的历史文件。优先用现有 Go 维护入口，按指定对象、占用和哈希检查；用户说“运行了”之后仍须核对本机文件和任务。私有历史统一在 `local/archive/`，系统旧缓存被清除不代表历史归档获准删除。
- **2026-10-05，入口与说明**：用户允许多进程，并同意将成熟 Go DNS 协议库编入主程序，替换外部 DNS 的方案不再受“必须保留 dnsmasq”约束。保留权限隔离，不把第三方库冒称为全部自研。原 DNS 策略与查询日志的文件名继续兼容保留，其中出现 `dnsmasq` 不代表旧程序仍在运行，须核对任务、进程及二进制。不要新增独立维护或诊断程序。Markdown 只保留 README、协作规则、Claude 引用和本文件；更新原位置，旧实现与验收留 Git。源码完成、管理员授权、线上接管须分别核实，不能混称完成。
- **2026-10-05，原生迁移验收**：`plutil` 曾接受成对布尔标签，`launchd` 却拒绝，须使用标准空标签并做隔离注册测试。launchd 把 `/var/db` 显示为 `/private/var/db`，临时任务须在注册前解析真实路径，否则身份检查与清理会误拒绝。普通用户状态任务不能向 `/var/log` 重定向；继续用原用户日志。管理员读取 `Documents` 曾报 `operation not permitted`，不能当成页面未更新；验收读原状态文件中的发布回执，另以普通用户比对 HTML 哈希，不扩大文档访问权限。

“复刻”在本项目指 GitHub Fork，旧上游 fork 为 `SalomeAilin/sing-box`。其许可证与附加名称限制以[保留的原文](../archive/sing-box-LICENSE)为准；重新引入上游核心仍需用户确认。
