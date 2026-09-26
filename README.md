# macOS Split Routing Backup

This repository backs up the active split-routing configuration for this Mac.

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
- `build-domain-proxy.py` generates `/usr/local/etc/network-domain-proxy.json`
  from the checked-in domain and address policy. Regenerate, check with the
  installed sing-box binary, and redeploy after changing those lists.
- `domestic_proxy_hosts.conf` adds exact observed Douyin resource hosts without
  classifying every shared ByteDance/TikTok suffix as domestic. These entries
  affect proxy connections only, not global routes or dnsmasq configuration.
- `/usr/local/libexec/network-domain-sing-box` is the pinned source-built binary.
- `network-domain-proxy-run.py` is installed under `/usr/local/sbin/`.
- `com.local.network-domain-proxy.plist` is a system LaunchDaemon.
- `deploy-domain-proxy.py` separates service installation from proxy activation.
  Its fresh `install` action still expects the original release-package layout
  and refuses to replace an installed service; it is not an engine upgrade tool.
  Its `update-auto` action first prewarms all rule sets in an isolated candidate
  using the same unprivileged account, then installs validated staged `.srs`
  seeds and `config.json`, retains a root-private configuration backup, and restores the
  previous configuration if activation health probes fail. Stage the script,
  configuration and the three rule files together outside protected Documents
  before running as administrator. No additional updater daemon is needed.
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

## Active File Mapping

- `network-split-guard.sh` -> `/usr/local/sbin/network-split-guard.sh`
- `china-route.sh` -> `/usr/local/sbin/china-route.sh`
- `network-split-dns-event-route-agent.py` -> `/usr/local/sbin/`
- `network_split_policy.py` -> `/usr/local/sbin/` (required by the DNS event agent and shell guards)
- `network-split-domestic-health.sh` -> `/usr/local/sbin/`
- `dnsmasq-network-split.conf` -> `/usr/local/etc/`
- `china_ip_list.txt` -> `/usr/local/etc/`
- `domestic_domains.conf` -> `/usr/local/etc/`
- `domestic_extra_routes.txt` -> `/usr/local/etc/`
- `com.local.china-route.plist` -> `/Library/LaunchDaemons/`
- `com.local.network-split-guard.plist` -> `/Library/LaunchDaemons/`
- `com.local.network-split-domestic-health.plist` -> `/Library/LaunchDaemons/`
- `com.local.network-split-dns-event-route-agent.plist` -> `/Library/LaunchDaemons/`
- `com.local.network-domain-proxy.plist` -> `/Library/LaunchDaemons/`
- `homebrew.mxcl.dnsmasq.plist` -> `/Library/LaunchDaemons/`

Deploy only the files listed in the active mapping. Retired implementations
remain available in Git history, not in the current deployment or test suite.

### Script Roles

| Role | Files | Use on this Mac |
| --- | --- | --- |
| Runtime | `network-domain-proxy-run.py`, `network-split-dns-event-route-agent.py`, `network-split-guard.sh`, `china-route.sh`, `network-split-domestic-health.sh` | Managed by the six active launchd jobs, together with the external dnsmasq binary; do not run duplicate instances manually |
| Shared dependency | `network_split_policy.py` | Required by the event agent and both routing scripts; not a redundant daemon |
| Maintenance | `build-domain-proxy.py`, `deploy-domain-proxy.py`, `deploy-security-update.zsh`, `install-network-split-dns-event-route-agent.sh` | Manual build, deployment and installation tools, not background jobs; installation can restart services |
| Verification | The nine files in `tests/` | Retained tests, not launchd jobs; `domain_proxy_live_evidence.py` accesses the live network and requires administrator authorization |

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
Deploy `china-route.sh` and `network-split-guard.sh` together: their lock and
force marker now live under root-only-writable `/var/db`, with no `/tmp` fallback.
Let an existing route rebuild finish before replacement; restart the DNS event
agent only if it is already enabled. Do not restart dnsmasq merely to update these
scripts. Preserve query logging with `nobody:wheel` ownership and mode `0660`.

The old event agent did not track route ownership. Before declaring migration
complete, review existing Ethernet host routes against the address policy and
the old agent log; remove only confirmed obsolete agent-created routes. Do not
flush all host routes or infer ownership from the interface alone.

Offline checks: `python3 -B tests/security_policy.py`,
`zsh tests/security_shell.zsh`, `zsh tests/recovery.zsh`, and
`zsh tests/route-snapshot.zsh`. Tests do not mutate system routes.
