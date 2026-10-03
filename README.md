# macOS Split Routing Backup

This repository backs up the active split-routing configuration for this Mac.

[中文概览](docs/overview.zh-CN.md)

## Repository Layout

| Directory | Contents |
| --- | --- |
| `scripts/` | zsh route guards and installers |
| `config/` | Domain/address policy and DNS/SSH configuration sources |
| `config/launchd/` | LaunchDaemon property lists |
| `config/chrome/` | Chrome preference snapshots |
| `tests/` | Offline zsh checks of the route guards and installers |
| `docs/` | Published, redacted verification records |
| `assets/images/` | Project images with descriptive names |
| `archive/` | Preserved historical material; not an active policy or deployment source |
| `engine/` | Go module: proxy engine, address policy, DNS event agent, configuration and deployment tools, with package-local tests |
| `local/` | Private working documents and preserved local caches; ignored by Git |

File organization is part of every project task, checked at task start and
completion. Follow the [automatic organization rules](AGENTS.md) when creating,
moving, archiving, or cleaning up task files.

Since 2026-10-02 the repository contains no Python. Every program the root and
`nobody` services run is a Go binary built from `engine/` or a zsh script. The
former Python address policy, DNS event agent, configuration builder and
deployment tool were ported to `engine/cmd/` after their decisions and output
were compared with the originals. Root services therefore no longer run an
interpreter that an administrator account can modify without authentication.
The Go programs were installed on 2026-10-02 at 21:25 (+08:00) with
`scripts/deploy-security-update.zsh`. Afterwards the DNS event agent ran the Go
binary and logged its 58 suffixes, the route guard and China routes exited
cleanly with the new policy program, `/usr/local/sbin` held no Python, and the
status page reported OK.

Run Go checks from `engine/` and the shell checks from the repository root:

```sh
(cd engine && go test -race ./... && go vet ./...)
zsh tests/security_shell.zsh
```

GitHub Actions runs the Go race tests, vet, offline integration and all four
existing zsh regression suites on macOS for pushes to `main` and pull requests.
The workflow pins Go 1.26.8 and action commits, uses a read-only token, and
does not deploy or run live-network integration checks. Its results cover
repository regressions, not production routing or playback quality.

The DNS route guard never restores executables from Homebrew automatically.
Before a configuration test or guard-requested restart, the fixed dnsmasq path
must be an executable regular file, not a symlink, with `root:wheel:555`
ownership/mode. A missing or unsafe binary requires an authorized reinstall;
the guard logs the failure and continues protecting the routing policy.
The executable's parent directories, DNS configuration and launchd definition
remain administrator-controlled deployment prerequisites. This gate is not
a cryptographic provenance check and does not change launchd's own restart path.
For a guard-only update, stage the tested `network-domain-proxy-deploy` binary
beside `network-split-guard.sh` and authorize its `install-route-guard` action.
It checks syntax without executing the guard, holds the existing guard lock,
publishes atomically, and checks hashes and core service PIDs. Failure restores
the prior file; temporary recovery material is removed after success or a
successful rollback. It does not run the broader security-update installer.

To generate proxy configuration, run
`(cd engine && go run ./cmd/network-domain-proxy-config /path/to/staging/config.json)`,
replacing `/path/to/staging` with an existing private staging directory. The tool
reads policy from the nearest `config/` directory. System installation still
requires administrator authorization; see the deployment sections below.

The generated `network-split-status.html` stays at the repository root and is
ignored by Git. The native replacement for the external updater is now versioned
in `engine/cmd/network-split-status` and `engine/internal/statuspage`. It reads
installed interfaces and DNS configuration; home-directory/output paths are
runtime arguments, not public source. Switching the existing user LaunchAgent
requires explicit local activation and verification; no extra schedule is needed.

## Browser Domain Routing

The independent proxy implementation is in [engine/](engine/README.md), version
`0.1.2-independent`. It is authored in this repository and builds using only
the Go standard library, without importing or executing sing-box. The existing
DNS event observer, IP guards and dnsmasq service remain separate components.
Production takeover was accepted on 2026-10-02 at 11:32 (+08:00), after macOS
administrator authentication. The existing launchd job now runs the independent
binary directly as `nobody`. The stopped previous binary, its dedicated rules
and cache, current upstream source tree and optional client references were
removed after acceptance. Original commits remain in Git history, and the
former [license notice](archive/sing-box-LICENSE) is retained unchanged.
DNS, route guards, macOS proxy settings and bypass entries were preserved.
The takeover ran `0.1.0-independent`. Version `0.1.1-independent` replaced only
the binary on 2026-10-02 at 12:50 (+08:00), using the staged `upgrade` action.
It caches DNS answers for their TTL and ends tunnels only when both directions
are idle. Afterwards Douyin, Bilibili, Youku, Baidu Netdisk and CSDN used
Ethernet, and GitHub and Claude used Wi-Fi. Repeated GitHub CONNECTs took
about 270 ms instead of 515-647 ms. A 60 KB/s HTTP/1.1 download through the
proxy kept its upstream connection open for the full 400-second test; under
`0.1.0` the engine sent a FIN at five minutes and the server closed the
connection about 80 seconds later. These checks do not establish long-term
playback stability.

Version `0.1.2-independent` replaced only the binary on 2026-10-02 at 21:46
(+08:00), installed by the Go deployment tool's `upgrade` action. It
revalidates the rule datasets with ETags, so unchanged data is no longer
downloaded again every hour. Afterwards Douyin and Bilibili used Ethernet and
GitHub used Wi-Fi.

Wi-Fi is a metered mobile hotspot. On 2026-10-02 the measured background use of
it was about 113 MB a day: about 78 MB from status-page probes every five
minutes, which downloaded the 230 KB Anthropic console page each time; about
29 MB from a separate one-minute keepalive monitor; and about 5.5 MB from
hourly rule downloads. The legacy status page outside this repository was changed to probe
with header-only requests and no longer fetches the console. The duplicate
keepalive LaunchAgent is disabled, with its files kept. Together with rule
revalidation, this brings the expected background use to about 7 MB a day.
New background probes over Wi-Fi should stay header-only and infrequent.

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
revalidate with the last ETag, so unchanged data is not downloaded again, and
validate and compile new data before replacing the private cache and live rules.
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
CGO_ENABLED=0 GOTOOLCHAIN=go1.26.8 go build -trimpath -buildvcs=false \
  -ldflags '-s -w' -o /path/to/staging/network-domain-proxy-deploy ./cmd/network-domain-proxy-deploy
```

Generate `config.json` in that staging directory with
`go run ./cmd/network-domain-proxy-config /path/to/staging/config.json` from
`engine/`. It reads the existing policies in `config/` and writes output
byte-identical to the former Python builder; it does not download data,
install files, change routes or start services.

Flat staging inputs are the compiled `network-domain-engine` and
`network-domain-proxy-deploy`, generated `config.json`,
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

### Backup Maintenance

Use the existing Go deployment tool for backup maintenance, with administrator
authorization:

| Action | Result |
| --- | --- |
| `network-domain-proxy-deploy backups` | List backup metadata and report unrecognized contents without deleting anything |
| `network-domain-proxy-deploy inspect-backup <exact-path>` | Validate and hash one backup without displaying configuration contents |
| `network-domain-proxy-deploy remove-backup <exact-path>` | Remove only that reviewed backup and verify unchanged service PIDs and installed-file hashes |

Both manifest-based proxy acceptance backups and the known flat installation
backup format are supported. Select an exact name or direct-child path under
the backup directory; wildcards, batch deletion, symlinks, hard links,
unexpected entries and mismatched manifests are rejected. Inspection identifies
the backup format, not whether its recovery data is still needed. Deletion
discards the local rollback copy and requires an explicit command.

Maintenance shares the proxy deployment lock. Deletion also refuses an active
security installer, open backup files, unavailable occupancy checks, stopped
services or changes detected during validation. It uses Go filesystem APIs and
direct calls to the macOS service/process tools, without generating cleanup
scripts or running an interpreter. It does not download web pages or restart
services. A failure after deletion is reported separately from a refusal before
deletion; unexpected new files are left in place rather than recursively removed.

To update only this maintenance tool, build `./cmd/network-domain-proxy-deploy`
using the build flags above, then run the staged executable with `install-tool`
and administrator authorization. Backup inventory is checked before publication;
only matching backup names receive metadata checks, avoiding unrelated protected
macOS databases. It uses the existing atomic installer and
checks that only the tool hash changed; engine, DNS and observer PIDs stay the
same. No rule/configuration staging or proxy upgrade is needed.

State residue is separate from backups. `residues` lists only the known health
temporary-state names and the retired DNS route-state file; `cleanup-residues`
removes eligible files after checking ownership, type, contents, age and open
file use. The active health state, unrelated files, links, unrecognized data,
recent writes and nonempty legacy DNS state are preserved.

The health job definition directly runs `network-split-health`, a dedicated
one-shot executable. It imports the shared health and read-only runtime-check
packages, not the deployment package, and accepts no installation/deletion
actions. The old tool's `health-check` action remains a compatibility entry,
not a second scheduled job. Activation requires the migration below; changing
this repository alone does not switch the installed job.
Go holds the POSIX `fcntl` writer lock across orphan recovery, probing and state
publication, including scheduled invocations where no HTTP probe is due. It
applies a five-minute grace period to abandoned complete or partial health writes.
Cleanup results use the existing health log. Automatic recovery never removes
the legacy DNS file or backups. The existing launchd `RunAtLoad` and 30-second
schedule remain the startup path; there is no health-check shell entry point.

To install this integration, build `./cmd/network-split-health` using the same
Go version/build flags and stage it beside the compiled deployment tool and
`config/launchd/com.local.network-split-domestic-health.plist` and run
`install-health-maintenance` with administrator authorization. It checks a real
native HTTP request and the wired route before changing files, snapshots the
prior tool/health binary/job/legacy script privately, reloads only the existing health job,
and removes the legacy script after native activation succeeds. Failure restores
the prior files and job; incomplete rollback retains and reports its recovery
directory. Successful activation removes temporary rollback material and verifies
that the proxy, DNS and observer PIDs and unrelated installed files are unchanged.

### Verification

`go test -race ./...` from `engine/` covers protocol forwarding, rule
precedence, corrupt updates, DNS caching, tunnel idle handling, the address
policy, DNS event correlation, configuration output and every deployment
rollback path. `go test -tags integration -run Integration .` additionally runs
the compiled engine: log limits and SIGTERM, automatic classification, hot and
corrupt updates and cached restart. `NETWORK_SPLIT_LIVE=1` adds the real-network
check that an invalid foreign interface fails closed while domestic access
works; `NETWORK_SPLIT_RULES` selects its seed directory.

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

After installation, build and run the read-only
`engine/cmd/network-domain-proxy-evidence` with administrator authorization. It
holds verified TLS connections, correlates the current request's structured log
with kernel sockets and reports ambiguous attribution honestly. Without
administrator rights it reports that the socket table is unavailable: macOS
hides it from that program's netstat, and lsof needs root. Keep raw output
private. Historical measurements remain in the
[redacted verification record](docs/verification-2026-09-11.html); they do not
prove present-day performance, a physical Wi-Fi-loss test, Claude application
health or long-term playback quality.

## Log Retention

The system configuration `/etc/newsyslog.d/network-split.conf` controls rotation
for the route guard, China routes, DNS event agent, and domestic health check.
The DNS event agent reopens its log before each write when the file was rotated
or removed, so it never continues writing into an archive.
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

The integration tests in `engine/integration_test.go` build the engine and run
it. The automatic fixture uses local rule/DNS data and invalid egress interfaces;
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
- `engine/cmd/network-split-dns-event-route-agent` (Go) -> `/usr/local/sbin/network-split-dns-event-route-agent`
- `engine/cmd/network-split-policy` (Go) -> `/usr/local/sbin/network-split-policy` (address policy the shell guards call)
- `engine/cmd/network-split-health` -> `/usr/local/sbin/network-split-health` (dedicated launchd entry; activation requires migration)
- Compiled independent `network-domain-engine` -> `/usr/local/libexec/network-domain-engine`
- `engine/cmd/network-domain-proxy-deploy` (Go) -> `/usr/local/sbin/network-domain-proxy-deploy` (manual maintenance; legacy health command retained for compatibility)
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

### Program Roles

| Role | Files | Use on this Mac |
| --- | --- | --- |
| Runtime | Native proxy engine, Go DNS event agent, Go health check, `scripts/network-split-guard.sh`, `scripts/china-route.sh` | Managed by the existing system jobs, together with the external dnsmasq binary; do not run duplicate instances manually |
| Shared dependency | `engine/internal/policy` (built into the agent) and the `network-split-policy` program | Address policy for the event agent and both routing scripts; not a daemon |
| Maintenance | `network-domain-proxy-config`, `network-domain-proxy-deploy`, `network-domain-proxy-evidence` from `engine/cmd/`, `scripts/deploy-security-update.zsh`, `scripts/deploy-remote-access.zsh`, `scripts/install-network-split-dns-event-route-agent.sh` | Manual build, deployment and installation tools, not background jobs; installation can restart services |
| Verification | Files in `tests/` and Go package tests in `engine/` | Retained tests, not launchd jobs; the evidence tool and the `NETWORK_SPLIT_LIVE` integration test use the live network |

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

The Go tests in `engine/internal/healthcheck` exercise the actual scheduler with
a simulated clock, native HTTP/TLS fixtures and mocked macOS route/service APIs.
A healthy one-hour replay makes 37 HTTP probes
across 121 scheduled invocations instead of 121, including the initial baseline
and trials. The steady 120-second stage targets 75% fewer probes than 30 seconds;
these are replay/count results, not measured live traffic or playback gains.

HTTP, scheduling, bounded state parsing and atomic publication are native Go.
The request uses direct IPv4, certificate-verified TLS, the same endpoint and
timeouts, and a 4 MiB response cap. The expected wired interface comes from the
installed proxy configuration and its gateway from the scoped macOS route.
An unavailable route query does not count as confirmed drift. The private state
format stays compatible with the prior version. See Backup Maintenance above
for the transactional health-job migration and rollback procedure.

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

`scripts/deploy-security-update.zsh` installs this side from a flat staging
directory: build `network-split-policy`, `network-split-dns-event-route-agent`
and `network-domain-proxy-deploy` from `engine/cmd/` into it, copy in
`scripts/china-route.sh`, `scripts/network-split-guard.sh`, the agent plist from
`config/launchd/` and the installer itself, then run the staged installer with
administrator authorization. Before touching live files it syntax-checks the
scripts, requires the staged policy to allow `223.5.5.5` and refuse `8.8.8.8`,
and runs the agent's `-check`. It waits for any route rebuild to finish,
backs up every file it replaces, and publishes the policy before the guards
that call it, each by atomic rename. Their lock and force marker live under
root-only-writable `/var/db`, with no `/tmp` fallback. An already loaded DNS
event agent is booted out and bootstrapped from its new definition and must be
running the new program; an unloaded agent stays unloaded. The former Python
files are removed only after that, and any failure restores the backup.
dnsmasq is not restarted. Query logging keeps `nobody:wheel` ownership and mode
`0660`.

The old event agent did not track route ownership. Before declaring migration
complete, review existing Ethernet host routes against the address policy and
the old agent log; remove only confirmed obsolete agent-created routes. Do not
flush all host routes or infer ownership from the interface alone.

Offline checks: `go test ./...` in `engine/`,
`zsh tests/security_shell.zsh`, `zsh tests/recovery.zsh`,
`zsh tests/route-snapshot.zsh`, and `zsh tests/remote_access.zsh`. Tests do not
mutate system routes or `/etc/ssh`.
