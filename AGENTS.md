# 协作规则与共同记忆

这个仓库由 Claude Code 和 Codex 共同维护。Codex 会自动读取本文件，Claude Code 通过 `CLAUDE.md` 引用本文件，两边都以这里为准。项目本身的说明见 `README.md`。

## 协作规则

1. 同一时间只让一方修改这个目录，另一方只查看、不改动。不确定对方是否正在改时，先问用户。
2. 动手前先运行 `git status`。如果有不是自己留下的未提交改动，先停下来问用户，不要覆盖、还原或代为提交。
3. 每完成一件事就提交，提交信息写清楚改了什么、为什么。不要留下改到一半的文件。
4. 提交后直接推送到 GitHub（`origin main`），不用再问用户。仓库是公开的，推送前确认改动里没有密钥、个人信息或本机网络细节。推送被拒绝时先运行 `git pull --rebase origin main`；有冲突就停下来问用户，不要强制推送。
5. `sing-box/` 是引擎源码（squashed Git subtree），修改前先和用户确认。
6. 部署到系统位置（如 `/usr/local`、`/Library/LaunchDaemons`）需要管理员权限，按 `README.md` 的步骤进行，并由用户确认后执行。

## 共同记忆的写法

- 对以后有用、又不能直接从代码或提交记录看出来的事实、决定和踩过的坑，写进下面的"共同记忆"，不要只存进自己的私有记忆。
- 写之前先看有没有相关条目：有就更新，发现过时或错误的就改掉或删除。
- 每条都注明日期，用绝对日期。
- 本仓库在 GitHub 上是公开的（`SalomeAilin/master`）。不要写密码、密钥、个人信息，也不要写只该留在本机的网络细节。

## 共同记忆

- 2026-09-25：在这台 Mac 的 zsh 里，`log` 是 shell 内置命令。查系统日志必须写 `/usr/bin/log show ...`。直接写 `log show` 会报 "too many arguments"，加了 `2>/dev/null` 就会静默返回空结果，曾因此误判为"没有日志记录"。
- 2026-09-25：用户说的"复刻"指 GitHub Fork。sing-box 的 fork 在 `SalomeAilin/sing-box`。
- 2026-09-26：`sing-box/` 已改为 squashed Git subtree，不再是单独的仓库。正在运行的代理引擎由其中的 v1.14.2 源码编译，详见 `README.md`。
- sing-box 的许可证是 GPL-3.0-or-later，另附条款：衍生作品未经许可不得使用 sing-box 的名称。
