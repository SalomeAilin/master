# macOS Split Routing Backup

This repository backs up the active split-routing configuration for this Mac.

## Repository Layout

| Directory | Contents |
| --- | --- |
| `scripts/` | Runtime scripts, shared policy module, and manual build/install tools |
| `config/` | Domain/address policy and DNS/SSH configuration sources |
| `config/launchd/` | LaunchDaemon property lists |
| `config/chrome/` | Chrome preference snapshots |
| `tests/` | Offline checks and the explicitly authorized live-evidence check |
| `docs/` | Published, redacted verification records |
| `assets/images/` | Project images with descriptive names |
| `archive/` | Preserved historical material; not an active policy or deployment source |
| `sing-box/` | Upstream engine source as a squashed Git subtree |
| `local/` | Private working documents and preserved local caches; ignored by Git |

File organization is part of every project task, checked at task start and
completion. Follow the [automatic organization rules](AGENTS.md) when creating,
moving, archiving, or cleaning up task files.

Run repository commands from the repository root. For example:

```sh
python3 -B tests/security_policy.py
zsh tests/security_shell.zsh
```

To generate proxy configuration, use
`python3 -B scripts/build-domain-proxy.py /path/to/staging/config.json`, replacing
`/path/to/staging` with an existing private staging directory. The builder reads
policy from `config/`. System installation still requires administrator
authorization; see the deployment sections below.

The generated `network-split-status.html` stays at the repository root and is
ignored by Git so its existing external updater can keep using the same path.

## Browser Domain Routing

Chrome and applications honoring macOS HTTP/HTTPS proxy settings now use the
loopback proxy `127.0.0.1:17890`. New connections are classified automatically:
protected foreign domains, local domestic overrides, the maintained foreign
domain set, then the maintained domestic domain set. Known domain decisions
precede DNS resolution, so CDN addresses do not override their classification.
For unknown hostnames, the user explicitly selected IP-based inference on
2026-09-11: resolve through domestic DoH, route China IPs over `en0`, otherwise
use `en1`. This is a geographic heuristic, not proof of website ownership:
unknown foreign sites using China CDNs can be classified as domestic, and the
reverse can happen for unknown domestic sites hosted abroad. Mixed-address DNS
answers also warrant inspection. Unknown private-address answers are rejected.

SagerNet `geosite-geolocation-cn`, `geosite-geolocation-!cn`, and `geoip-cn`
binary rule sets are checked hourly over HTTPS through Wi-Fi. The engine
applies valid updates to new connections without restarting the proxy; failed
downloads or malformed rules keep the last working in-memory rules. Cached
sets persist at `/var/db/network-domain-proxy/cache.db`; root-owned initial
sets under `/usr/local/etc/network-domain-rules` permit offline startup even
without a cache. Rule downloads bootstrap through the existing loopback DNS
resolver, independently of new DoH transport startup. Website DNS uses
certificate-verified AliDNS DoH pinned to `en0` and Cloudflare DoH pinned to
`en1`. Unknown-domain classification needs the domestic resolver; failure does
not silently retry that lookup over the other interface.

Sources: [sing-geosite](https://github.com/SagerNet/sing-geosite),
[sing-geoip](https://github.com/SagerNet/sing-geoip), and
[native rule-set updates](https://sing-box.sagernet.org/configuration/rule-set/).

Since 2026-09-26, the running engine is built from the stable `v1.14.2` tag in
[SalomeAilin/sing-box](https://github.com/SalomeAilin/sing-box), commit
`af6e64c3b69e6132ebaee0e1a3d24e93903f6709`, with no engine source changes.
The build uses Go 1.26.8, darwin/arm64, CGO, the full
`release/DEFAULT_BUILD_TAGS`, and `release/LDFLAGS`. Installed binary SHA-256:
`09e56e101f5340b4c43e331a07a4f99d434cc785b68c0ca68939efe0cf0f025c`.
The stable source is tracked under [sing-box/](sing-box/) as a squashed Git
subtree, not a separate nested repository. Its original license, source tree
and optional client references are preserved; the root `.gitmodules` maps those
clients to their prefixed paths. The engine build does not require initializing
the optional client submodules. Compiled binaries and local caches are ignored.
Only the proxy engine was replaced; routing, DNS, service configuration and
cache were preserved. The inactive official binary backup was removed at the
owner's request after verifying the running source-built binary.

After replacement, held TLS connections and unique kernel sockets confirmed
Douyin and CSDN over Ethernet and GitHub over Wi-Fi, each returning HTTP 200.
The source build also passed isolated automatic-classification, rule-update,
cached-restart and fail-closed checks. These checks do not establish long-term
stability or video playback quality; source compilation alone is not a latency
optimization.

There is no TLS interception, remote proxy server, TUN, or route-table mutation.
The service runs as `nobody` and keeps up to four 2 MiB private log files under
`/var/log/network-domain-proxy`. Existing DNS and IP guards remain for clients
that do not use the HTTP/HTTPS proxy; they are not domain-aware enforcement.
Existing system bypass entries, including `*.crashlytics.com`, were preserved.
WebRTC, non-proxy clients and existing direct pooled connections are not covered.

Files:
- `scripts/build-domain-proxy.py` generates `/usr/local/etc/network-domain-proxy.json`
  from the checked-in domain and address policy. Regenerate, check with the
  installed sing-box binary, and redeploy after changing those lists.
- `config/domestic_proxy_hosts.conf` adds exact observed Douyin resource hosts without
  classifying every shared ByteDance/TikTok suffix as domestic. These entries
  affect proxy connections only, not global routes or dnsmasq configuration.
- `/usr/local/libexec/network-domain-sing-box` is the pinned source-built binary.
- `scripts/network-domain-proxy-run.py` is installed under `/usr/local/sbin/`.
- `config/launchd/com.local.network-domain-proxy.plist` is a system LaunchDaemon.
- `scripts/deploy-domain-proxy.py` separates service installation from proxy activation.
  Its fresh `install` action still expects the original release-package layout
  and refuses to replace an installed service; it is not an engine upgrade tool.
  Its `update-auto` action first prewarms all rule sets in an isolated candidate
  using the same unprivileged account, then installs validated staged `.srs`
  seeds and `config.json`, retains a root-private configuration backup, and restores the
  previous configuration if activation health probes fail. Its deployment
  inputs retain a flat staging layout outside protected Documents: copy
  `scripts/deploy-domain-proxy.py`, `scripts/network-domain-proxy-run.py`, and
  `config/launchd/com.local.network-domain-proxy.plist` there under their original
  basenames, alongside `config.json` and the three `.srs` rule files. For a fresh
  install, also include the release binary at
  `sing-box-1.14.2-darwin-arm64/sing-box` inside that staging directory. Run the
  staged `deploy-domain-proxy.py` as administrator with the intended action;
  running the repository copy does not assemble those deployment inputs.
  No additional updater daemon is needed.
  Cache prewarming avoids the observed first-background-download cancellation
  during initial network detection; cached startup does not immediately fetch.
  If both the runtime cache is lost and the initial background fetch fails,
  the seed remains usable and the engine retries at the next hourly interval.

Rollback: run `sudo /usr/local/bin/python3 -B
/usr/local/sbin/network-domain-proxy-deploy.py rollback` as one command. This
restores the previous Wi-Fi/Ethernet HTTP/HTTPS settings from
`/var/db/network-domain-proxy.previous.json` before any service shutdown.
This command does not restore the preceding engine binary.
Do not stop the proxy while browser settings still point at it.

Verified on 2026-09-11: Chrome opened loopback proxy connections; actual Douyin
video hosts `v26-web-prime.douyinvod.com` and `v11-weba.douyinvod.com` matched
the wired outbound. Held TLS connections showed Douyin and Aliyun billing
using the Ethernet source address, GitHub using the Wi-Fi source address. Isolated invalid-interface
injection rejected foreign traffic while domestic access remained usable.
This does not establish long-term playback stability, a physical Wi-Fi-loss
test, or complete coverage of every website. Claude returned HTTP 403 in a
command-line probe; that is not a successful application-health check.

The [redacted verification record](docs/verification-2026-09-11.html) records
the 23:39 live TCP/TLS measurements and their limits. Raw socket addresses,
ephemeral ports, process IDs and full browsing logs are intentionally not published.
Reproduce the read-only live check locally with administrator authorization:
`python3 -B tests/domain_proxy_live_evidence.py`. Keep its raw output private.

## Log Retention

The system configuration `/etc/newsyslog.d/network-split.conf` controls rotation
for the route guard, China routes, DNS event agent, and domestic health check.
The DNS event agent uses `WatchedFileHandler` so it reopens the current log
after external rotation instead of continuing to write into an archive.
macOS runs `newsyslog` hourly at minute 30, so these thresholds are checked
periodically rather than enforced as hard byte caps. Do not manually remove
the dnsmasq query log: the live DNS event agent consumes it for route decisions.

| Source | Purpose | Retention / status |
| --- | --- | --- |
| `dnsmasq-network-split-query.log` | Live input for domestic DNS route decisions | Agent compacts after consuming the file at 64 MiB; this is not a hard cap if the consumer stops or falls behind |
| `network-split-guard.log`, `china-route.log` | Route drift and recovery evidence | `newsyslog`: 1 MiB threshold, ten archives each |
| `network-split-dns-event-route-agent.log` | DNS-derived route changes and observer errors | `newsyslog`: 1 MiB threshold, five archives |
| `network-split-domestic-health.log` | Domestic HTTP probe failures and recovery | `newsyslog`: 1 MiB threshold, five archives |
| `network-domain-proxy/service.log` | Domain routing and proxy connection errors | Existing proxy supervisor: 2 MiB threshold, three archives |
| Guard and health `.out` / `.err` | Short-lived job output and startup failures | `newsyslog`: 256 KiB threshold, three archives each |
| DNS event agent `.out` / `.err` | Long-lived process startup/output channels | Presently empty; not covered by the main-log rotation guarantee |

Additional tests: `python3 -B tests/domain_proxy.py`,
`python3 -B tests/domain_proxy_deploy.py`,
`python3 -B tests/domain_proxy_automatic.py <sing-box-binary>` and
`python3 -B tests/domain_proxy_failclosed.py <sing-box-binary> [seed-directory]`.
The automatic fixture uses local rule/DNS data and invalid egress interfaces;
it checks precedence, unknown-IP decisions, hot updates, corrupt-update
retention and cached restart with the update server unavailable. These are
engine tests, not proof of production video playback quality.

## Policy

- Foreign/default traffic uses Wi-Fi (`en1`, gateway `172.20.10.1`).
- Domestic traffic uses Ethernet (`en0`, gateway `192.168.1.1`).
- If Wi-Fi is unavailable, foreign traffic is blocked instead of falling back
  to Ethernet. More-specific domestic routes remain available over Ethernet.
- System DNS uses the local split resolver at `192.168.1.100`.
- Replies of inbound connections to `192.168.1.100`, such as router-forwarded
  SSH, leave through `en0` even while Wi-Fi is unavailable; the reject routes do
  not apply to them. The owner accepted this for remote access on 2026-09-26.
  See Remote Access (SSH).

## Remote Access (SSH)

The router forwards one external port to `192.168.1.100:22`; no routing
exception is installed. In the published XNU source (xnu-12377.121.6) the
accepted socket's route is looked up in the scope of the interface the SYN
arrived on (`tcp_setup_server_socket`), TCP output asks for source-interface
selection (`IPOAF_SELECT_SRCIF`), so later lookups are scoped to the owner of
`192.168.1.100`, and a scoped lookup skips `lo0` routes that carry `RTF_GATEWAY`
(`rt_lookup_common`). The guard's Wi-Fi-loss reject routes are such gateway
routes, so SSH replies leave through `en0` to any client, Wi-Fi or not;
`tests/remote_access.zsh` fails if they become `-interface` routes. This rests on
the published source, not a live Wi-Fi-loss test, and the running kernel is newer.
A pf `reply-to` anchor was written for this on 2026-09-26 and removed the same day
once the source showed it unnecessary; it remains in Git history.

`config/sshd-remote-access.conf` becomes `/etc/ssh/sshd_config.d/050-remote-access.conf`:
key-only login for one account and no root login. It sorts before Apple's
`100-macos.conf` because sshd keeps the first value it reads, and it has no effect
until Remote Login is on. `MaxAuthTries` keeps its default because a lower value
locks out clients whose agent offers several keys first; clients should set
`IdentitiesOnly yes` with the intended key. There is no connection-rate limit:
launchd starts `sshd -i` per connection, so `MaxStartups` and `PerSourcePenalties`
do not apply, and key-only login leaves no password to guess.

Run `sudo zsh scripts/deploy-remote-access.zsh install|status|uninstall` from the account
that will log in. Install evaluates the real main configuration and the other
drop-ins with the candidate in a scratch copy, requires the effective settings for
an outside connection to be key-only for that account, checks the live result
again and restores the previous drop-in otherwise. It will not hand `AllowUsers`
to another account unless `REMOTE_USER` names it. Status also reports Remote
Login, host key fingerprints, `authorized_keys` and the Remote Login access list;
uninstall removes only a drop-in that carries its marker line.

Remote Login, the router port forward, DDNS and client keys stay manual; the
external port is router configuration and is not recorded here. Compare the host
key fingerprint on the LAN before trusting it from outside. FileVault is on, so
after an unattended restart sshd stays unreachable until someone unlocks the Mac
locally; plan restarts with `fdesetup authrestart`.
Offline checks: `zsh tests/remote_access.zsh`.

## Active File Mapping

- `scripts/network-split-guard.sh` -> `/usr/local/sbin/network-split-guard.sh`
- `scripts/china-route.sh` -> `/usr/local/sbin/china-route.sh`
- `scripts/network-split-dns-event-route-agent.py` -> `/usr/local/sbin/`
- `scripts/network_split_policy.py` -> `/usr/local/sbin/` (required by the DNS event agent and shell guards)
- `scripts/network-split-domestic-health.sh` -> `/usr/local/sbin/`
- `config/dnsmasq-network-split.conf` -> `/usr/local/etc/`
- `config/china_ip_list.txt` -> `/usr/local/etc/`
- `config/domestic_domains.conf` -> `/usr/local/etc/`
- `config/domestic_extra_routes.txt` -> `/usr/local/etc/`
- `config/launchd/com.local.china-route.plist` -> `/Library/LaunchDaemons/`
- `config/launchd/com.local.network-split-guard.plist` -> `/Library/LaunchDaemons/`
- `config/launchd/com.local.network-split-domestic-health.plist` -> `/Library/LaunchDaemons/`
- `config/launchd/com.local.network-split-dns-event-route-agent.plist` -> `/Library/LaunchDaemons/`
- `config/launchd/com.local.network-domain-proxy.plist` -> `/Library/LaunchDaemons/`
- `config/launchd/homebrew.mxcl.dnsmasq.plist` -> `/Library/LaunchDaemons/`
- `config/sshd-remote-access.conf` -> `/etc/ssh/sshd_config.d/050-remote-access.conf` (account name filled in at install)

Deploy only the files listed in the active mapping. Retired implementations
remain available in Git history, not in the current deployment or test suite.

### Script Roles

| Role | Files | Use on this Mac |
| --- | --- | --- |
| Runtime | `scripts/network-domain-proxy-run.py`, `scripts/network-split-dns-event-route-agent.py`, `scripts/network-split-guard.sh`, `scripts/china-route.sh`, `scripts/network-split-domestic-health.sh` | Managed by the six active launchd jobs, together with the external dnsmasq binary; do not run duplicate instances manually |
| Shared dependency | `scripts/network_split_policy.py` | Required by the event agent and both routing scripts; not a redundant daemon |
| Maintenance | `scripts/build-domain-proxy.py`, `scripts/deploy-domain-proxy.py`, `scripts/deploy-security-update.zsh`, `scripts/deploy-remote-access.zsh`, `scripts/install-network-split-dns-event-route-agent.sh` | Manual build, deployment and installation tools, not background jobs; installation can restart services |
| Verification | The ten files in `tests/` | Retained tests, not launchd jobs; `domain_proxy_live_evidence.py` accesses the live network and requires administrator authorization |

Source/deployed copies have different roles: the repository is the editable
source; `/usr/local/sbin` is the launchd execution location. Compare their
contents before deployment rather than treating either location as disposable.
This inventory establishes roles and references, not playback stability.

Route-guard runs share the root-owned `/var/db/network-split-guard.flock` kernel
lock before any network changes. Overlapping invocations exit without repair;
the kernel releases the lock when its owner exits, including after a crash.
The domestic health check requests the existing launchd guard with `kickstart`
without `-k`, so it does not start a separate shell guard or terminate an active
repair. HTTP errors and slow responses alone do not request route repair.
This serializes guard instances, not every component that manages routes.

The end-of-scan recovery check reconciles foreign fallback blocks even when
macOS has already restored a Wi-Fi default route. A correct default alone does
not prove the more-specific reject routes are gone. This handles Wi-Fi recovery
during a domestic scan without waiting for another scheduled guard run; it does
not replace the existing 30-second schedule with event-driven recovery.

Address authorization uses a sorted index of merged IPv4 intervals instead of
scanning every prefix for each answer. It preserves gaps and special-address
rejection, checks policy-file identity and modification metadata on every call,
and fails closed on a missing or malformed policy. The guard filters each
domain's DNS answers in one helper process; route mutations still independently
recheck policy. No extra daemon, persistent index file, DNS TTL extension, or
proxy change is involved. Reduced local policy overhead is not a claim of faster
Internet transit or smoother video playback.

On 2026-09-26, a local comparison against the preceding implementation measured
the same eight-address check at a median 295 ms across eight helper processes
versus 48 ms through the new batch path (three samples, about 84% less time).
For 320 repeated checks including policy-file metadata validation, five-sample
medians were 242 ms and 1.3 ms. The real policy matched the preceding algorithm
on 526 deterministic cases; regression tests also cover interval boundaries,
gaps, special addresses, policy replacement, and malformed-policy rejection.

### Adaptive HTTP Probe Cadence

The domestic health check can now tune its own **active HTTP probe interval**;
this is background-load control, not automatic DNS selection, bandwidth tuning,
or a claim that playback stutter has been fixed. Its existing launchd job still
wakes every 30 seconds. Runs between due probes take the existing lock, validate
the existing state file, and exit without HTTP requests or route checks. The
separate route guard keeps its 30-second schedule and the DNS event observer
remains active. Proxy configuration, interface policy, DNS and engine source
are unchanged; there is no new daemon, script, timer, or persistent file.

- Start at 30 seconds. Six healthy 2xx/3xx samples establish a median latency
  baseline and start a 60-second trial; six acceptable trial samples allow
  120 seconds. The existing endpoint, wired-route check and four-second health
  limit are retained. A 401/403 response is not a performance baseline.
- Keep comparing new samples with that baseline. A regression must exceed both
  50% and 250 ms: three consecutive regressions, or a six-sample median above
  that threshold, restores 30 seconds. A failed probe, route drift, unacceptable
  status or the existing absolute timeout/slow limit also restores 30 seconds.
  A ten-minute healthy cooldown is required before another slower-cadence trial.
- Trial, six-sample verification and rollback events use the existing rotated
  health log. State reuses the existing private, atomically replaced health
  state file and stores at most six timing samples. Legacy, malformed, oversized
  or duplicate-key state, a backward clock jump, or a probe gap over ten minutes
  resets the schedule to 30 seconds. State is parsed as data, never executed.
- Only confirmed route drift can request the existing non-restarting route
  guard. Timing changes and HTTP errors cannot restart services, rewrite routes,
  switch interfaces, extend DNS TTLs, or weaken foreign fail-closed behavior.

Tradeoff: at the 120-second stage this HTTP monitor may take about two minutes
plus probe execution time to observe a new failure; latency regression detection
needs multiple samples. This is not real-time application monitoring, and a
single endpoint cannot establish the health of all domestic or foreign sites.
Reduced probe count is measurable; latency comparisons here are safeguards,
not evidence that reducing probes caused a website speed improvement.

`zsh tests/recovery.zsh` exercises the actual program with mocked external
commands and a simulated clock. A healthy one-hour replay makes 37 HTTP probes
across 121 scheduled invocations instead of 121, including the initial baseline
and trials. The steady 120-second stage targets 75% fewer probes than 30 seconds;
these are replay/count results, not measured live traffic or playback gains.

Deployment is separate from source acceptance: after administrator approval,
replace only the mapped `scripts/network-split-domestic-health.sh` atomically while
holding its existing health lock. Validate syntax and retain the prior deployed
file until the first scheduled run and state/log checks pass. Do not restart
the proxy, DNS, route guard or event observer. Rollback restores that one file;
the preceding version can still read `failure_count` from the extended state.

Review interface names, gateways, DNS addresses, ownership, and launchd state
before restoring on another Mac or after a major network topology change.
`network-split-status.html` is intentionally excluded because it can contain
local network details and is generated from the live system.

## Security Update Deployment

DNS-derived host routes require an address in `china_ip_list.txt` or an explicit
administrator-approved `domestic_extra_routes.txt` entry. Domain ownership alone
does not authorize a global route. Unapproved answers still resolve, but do not
receive an Ethernet override. Missing or malformed address policy fails closed.
Keep both policy files and their parent directory root-owned and not writable by
unprivileged accounts. Never automatically add exceptions from DNS answers.

Install the policy module before replacing the DNS event agent or shell guards.
Deploy `scripts/china-route.sh` and `scripts/network-split-guard.sh` together: their lock and
force marker now live under root-only-writable `/var/db`, with no `/tmp` fallback.
Let an existing route rebuild finish before replacement; restart the DNS event
agent only if it is already enabled. Do not restart dnsmasq merely to update these
scripts. Preserve query logging with `nobody:wheel` ownership and mode `0660`.

The old event agent did not track route ownership. Before declaring migration
complete, review existing Ethernet host routes against the address policy and
the old agent log; remove only confirmed obsolete agent-created routes. Do not
flush all host routes or infer ownership from the interface alone.

Offline checks: `python3 -B tests/security_policy.py`,
`zsh tests/security_shell.zsh`, `zsh tests/recovery.zsh`,
`zsh tests/route-snapshot.zsh`, and `zsh tests/remote_access.zsh`. Tests do not
mutate system routes or `/etc/ssh`.
