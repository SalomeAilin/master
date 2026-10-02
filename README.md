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
| `engine/` | Independent Go proxy source and package-local tests |
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

The independent proxy implementation is in [engine/](engine/README.md), version
`0.1.1-independent`. It is authored in this repository and builds using only
the Go standard library, without importing or executing sing-box. The existing
DNS event observer, IP guards and dnsmasq service remain separate components.
Production takeover was accepted on 2026-10-02 at 11:32 (+08:00), after macOS
administrator authentication. The existing launchd job now runs the independent
binary directly as `nobody`. The stopped previous binary, its dedicated rules
and cache, current upstream source tree and optional client references were
removed after acceptance. Original commits remain in Git history, and the
former [license notice](archive/sing-box-LICENSE) is retained unchanged.
DNS, route guards, macOS proxy settings and bypass entries were preserved.
The takeover ran `0.1.0-independent`. Version `0.1.1-independent` adds a
TTL-bounded DNS cache and ends tunnels only when both directions are idle;
installing it requires administrator authorization.

New connections use protected foreign domains, local domestic overrides,
maintained foreign domains, then maintained domestic domains. Known domain
decisions precede DNS resolution, so CDN location does not override them.
Unknown domains use domestic certificate-verified DoH and IP-based inference.
The first public IPv4 answer selects the geographic group, and retries are
restricted to addresses from that same group. This heuristic does not prove
site ownership; mixed answers and cross-region CDNs can still be classified
differently from a site's business identity. Private or unsupported answers
are rejected, including for known domains.

All data and DoH sockets are bound in the macOS kernel: domestic uses Ethernet
and foreign uses Wi-Fi. There is no unbound retry or cross-interface fallback.
Website DNS uses AliDNS DoH and Cloudflare DoH with pinned endpoint addresses
and certificate names. Successful answers are cached in memory for their DNS
TTL, at most five minutes; failures are not cached. Rule refresh uses foreign
DoH for hostname resolution and HTTPS pinned to Wi-Fi. Failed foreign access
does not fall back to Ethernet; domestic access remains independently available.

The three externally maintained datasets are JSON from
[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat), retained
under their [original license](https://github.com/MetaCubeX/meta-rules-dat/blob/master/LICENSE).
They are classification data, not imported engine code. Hourly native updates
validate and compile before replacing the private cache and live rules.
Failed or corrupt updates preserve the last good data. Root-owned initial
seeds allow offline startup; valid cache files take precedence after updates.
The external datasets, Go and macOS retain their own authorship and licenses.

The native service implements HTTP forwarding, CONNECT, WebSocket upgrades and
SOCKS5 TCP CONNECT at `127.0.0.1:17890`. It runs as `nobody`, has a bounded
client count, and is directly managed by the existing launchd job. Tunnels
close after five minutes without bytes in either direction, so one quiet
direction does not cut a long download or upload. There is no TLS
interception, remote proxy node, TUN or route-table mutation. IPv6 proxy
destinations and SOCKS UDP are rejected. Non-proxy clients, WebRTC and existing
direct connections are outside this proxy's enforcement; existing system
bypass entries and DNS/IP guards are preserved.

### Build and Install

Build with Go 1.26.8 from `engine/` into an existing task staging directory:

```sh
CGO_ENABLED=0 GOTOOLCHAIN=go1.26.8 go build -trimpath -buildvcs=false \
  -ldflags '-s -w' -o /path/to/staging/network-domain-engine .
```

From the repository root, generate `config.json` in that staging directory
with `python3 -B scripts/build-domain-proxy.py /path/to/staging/config.json`.
The builder reads the existing policies in `config/`; it does not download
data, install files, change routes or start services.

Flat staging inputs are the compiled `network-domain-engine`, generated
`config.json`, `scripts/deploy-domain-proxy.py`,
`config/launchd/com.local.network-domain-proxy.plist`, and three JSON files
named `domestic.json`, `foreign.json`, `china.json` downloaded over
certificate-verified HTTPS from the URLs in the generated configuration.
Do not use the repository root as a deployment directory. The staging directory,
binary and seed data must be readable by `nobody`; configuration and caches
used for private diagnostics must stay private.

Run the staged installer with administrator authorization and action `upgrade`
for an existing service, or `install` for a fresh service. It validates the
service arguments and production policy, starts an isolated unprivileged
candidate and probes domestic/foreign HTTPS before stopping the live engine.
A private kernel lock rejects overlapping deployments. After writer exit it
snapshots exact affected files, atomically installs the binary, configuration,
JSON seeds, plist and installer, waits up to 15 seconds for the listener, then
health-checks the live service. Failed activation restores affected files and
cache before restarting the previous
service. A failed rollback retains and reports its private recovery backup.
Successful activation retains one acceptance backup until real socket evidence
has been checked; then remove that exact backup and reviewed retired core.
It does not change macOS proxy settings, bypass entries or unrelated services.

The manual `enable` action health-checks first, records previous HTTP/HTTPS
settings once and enables the loopback proxy. The `rollback` action restores
those settings; it does not restore a previous engine binary. Do not stop a
proxy while browsers still point at it.

### Verification

`go test -race ./...` from `engine/`, plus
`python3 -B tests/domain_proxy.py`,
`python3 -B tests/domain_proxy_deploy.py`,
`python3 -B tests/domain_proxy_native.py <binary>`,
`python3 -B tests/domain_proxy_automatic.py <binary>` and
`python3 -B tests/domain_proxy_failclosed.py <binary> <seed-directory>`
cover protocol forwarding, rule precedence, corrupt updates, cached restart,
log limits, shutdown and interface-failure isolation.

Production acceptance on 2026-10-02 at 11:32 (+08:00) held certificate-verified
TLS connections and matched each request's native log to a unique new kernel
socket. The single independent process was directly owned by launchd; the old
process had exited. Measurements include TLS and socket inspection, not ping
RTT or bandwidth:

| Probe | HTTP | Kernel Egress | Seconds to Response Headers |
| --- | --- | --- | --- |
| Douyin | 200 | Ethernet | 0.168 |
| Bilibili | 200 | Ethernet | 0.231 |
| Youku | 302 | Ethernet | 0.205 |
| Baidu Netdisk | 200 | Ethernet | 0.186 |
| CSDN | 200 | Ethernet | 0.647 |
| GitHub | 200 | Wi-Fi | 1.196 |

The installed binary matched the tested binary's SHA-256:
`6fe3210ee89f1dfc1eff26968ac75875186fcd9e9a5887f385b8ddc767999239`.
DNS and route-guard hashes and proxy settings remained unchanged. The reviewed
acceptance backup was removed after these checks. This is a short production
acceptance sample, not a long-term stability guarantee or video test. No raw
socket addresses or browsing logs are published.

After installation, run the read-only
`python3 -B tests/domain_proxy_live_evidence.py` with administrator
authorization. It holds verified TLS connections, correlates the current
request's structured log with kernel sockets and reports ambiguous attribution
honestly. Keep raw output private. Historical measurements remain in the
[redacted verification record](docs/verification-2026-09-11.html); they do not
prove present-day performance, a physical Wi-Fi-loss test, Claude application
health or long-term playback quality.

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
| `network-domain-proxy/service.log` | Domain routing, startup and proxy connection errors | Native engine: 2 MiB cap for newly written files, three numbered archives |
| Guard and health `.out` / `.err` | Short-lived job output and startup failures | `newsyslog`: 256 KiB threshold, three archives each |
| DNS event agent `.out` / `.err` | Long-lived process startup/output channels | Presently empty; not covered by the main-log rotation guarantee |

Additional tests: `python3 -B tests/domain_proxy.py`,
`python3 -B tests/domain_proxy_deploy.py`,
`python3 -B tests/domain_proxy_native.py <network-domain-engine-binary>`,
`python3 -B tests/domain_proxy_automatic.py <network-domain-engine-binary>` and
`python3 -B tests/domain_proxy_failclosed.py <network-domain-engine-binary> [seed-directory]`.
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
- Compiled independent `network-domain-engine` -> `/usr/local/libexec/network-domain-engine`
- `scripts/deploy-domain-proxy.py` -> `/usr/local/sbin/network-domain-proxy-deploy.py` (manual maintenance entry, not a daemon)
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

Deploy only the files listed in this mapping. Retired implementations remain
available in Git history, not in the current deployment or test suite. The
former engine's license notice is retained in `archive/sing-box-LICENSE`.

### Script Roles

| Role | Files | Use on this Mac |
| --- | --- | --- |
| Runtime | Native proxy engine, `scripts/network-split-dns-event-route-agent.py`, `scripts/network-split-guard.sh`, `scripts/china-route.sh`, `scripts/network-split-domestic-health.sh` | Managed by the six active launchd jobs, together with the external dnsmasq binary; do not run duplicate instances manually |
| Shared dependency | `scripts/network_split_policy.py` | Required by the event agent and both routing scripts; not a redundant daemon |
| Maintenance | `scripts/build-domain-proxy.py`, `scripts/deploy-domain-proxy.py`, `scripts/deploy-security-update.zsh`, `scripts/deploy-remote-access.zsh`, `scripts/install-network-split-dns-event-route-agent.sh` | Manual build, deployment and installation tools, not background jobs; installation can restart services |
| Verification | Files in `tests/` and Go package tests in `engine/` | Retained tests, not launchd jobs; `domain_proxy_live_evidence.py` accesses the live network and requires administrator authorization |

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
Service-start requests use the actual child exit status, with a bounded timeout
and child reaping; a failed `launchctl` request must not be reported as success.

The DNS event observer correlates CNAME replies only within the same dnsmasq
process, query ID and client. It no longer retains a global shared-CDN alias
map. Pending domestic queries expire after 30 seconds and are capped at 4096;
reused IDs, resolver configuration reloads and query-log changes discard stale
context. Address policy still authorizes every route mutation. This removes
cross-query classification inheritance, not the remaining limitations of
global IP routes for non-proxy clients.

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
