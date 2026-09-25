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

This uses the official sing-box 1.14.2 darwin-arm64 release, archive SHA-256
`925c5382eca8492b0150f868a6db20b18290a38700e621724b3703fd453e032d`.
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
- `/usr/local/libexec/network-domain-sing-box` is the pinned external binary.
- `network-domain-proxy-run.py` is installed under `/usr/local/sbin/`.
- `com.local.network-domain-proxy.plist` is a system LaunchDaemon.
- `deploy-domain-proxy.py` separates service installation from proxy activation.
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

The system configuration `/etc/newsyslog.d/network-split.conf` retains the existing route-guard,
China-route, and DNS-event-agent rules and adds rotation for the domestic
health check: 1 MiB with five archives for its main log, and 256 KiB with
three archives each for health-check and route-guard stdout and stderr.
The DNS event agent uses `WatchedFileHandler` so it reopens the current log
after external rotation instead of continuing to write into an archive.
Same-process reopening was verified on the live service on 2026-09-25.
macOS runs `newsyslog`
hourly at minute 30, so these thresholds are checked periodically rather
than enforced as hard byte caps. The first health-log rotation was triggered
and verified on 2026-09-25; the previous log was retained as `.log.0`. Do not
manually remove the dnsmasq query log: the live DNS event agent consumes it
for route decisions.

| Source | Purpose | Retention / status |
| --- | --- | --- |
| `dnsmasq-network-split-query.log` | Live input for domestic DNS route decisions | Agent compacts after consuming the file at 64 MiB; this is not a hard cap if the consumer stops or falls behind |
| `network-split-guard.log`, `china-route.log` | Route drift and recovery evidence | `newsyslog`: 1 MiB threshold, ten archives each |
| `network-split-dns-event-route-agent.log` | DNS-derived route changes and observer errors | `newsyslog`: 1 MiB threshold, five archives |
| `network-split-domestic-health.log` | Domestic HTTP probe failures and recovery | `newsyslog`: 1 MiB threshold, five archives |
| `network-domain-proxy/service.log` | Domain routing and proxy connection errors | Existing proxy supervisor: 2 MiB threshold, three archives |
| Guard and health `.out` / `.err` | Short-lived job output and startup failures | `newsyslog`: 256 KiB threshold, three archives each |
| DNS event agent `.out` / `.err` | Long-lived process startup/output channels | Presently empty; not covered by the main-log rotation guarantee |
| Old DNS route-agent and DNS firewall logs | Historical diagnostics | Corresponding jobs are not loaded as of 2026-09-25; preserve pending archive review |

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
- `network_split_policy.py` -> `/usr/local/sbin/` (required by both DNS agents and shell guards)
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

The older `com.local.network-split-dns-route-agent` and
`com.local.network-split-dns-firewall` jobs are not loaded or installed as
LaunchDaemons on 2026-09-25. Their repository files and installers are
historical material, not part of the active mapping. The old DNS route-agent
source is retained for regression tests and updates of machines still running
that legacy service. The security-update installer deploys it only when that
service is loaded; it must not recreate an unused executable on this Mac. Do not restore
every `com.local.*.plist` as a group: that would reintroduce these older jobs.

On 2026-09-25, the unused deployed
`/usr/local/sbin/network-split-dns-route-agent.py` was removed after checking
service references and matching its contents to the retained repository source.
The installed `network-domain-proxy-deploy.py` was synchronized with
`deploy-domain-proxy.py`, including the 1.14.2 installation-package path.
Byte comparison passed; running proxy/DNS/event-agent PIDs and start times
were unchanged. The task-specific staging directory was removed after verification.

### Script Roles

| Role | Files | Use on this Mac |
| --- | --- | --- |
| Runtime | `network-domain-proxy-run.py`, `network-split-dns-event-route-agent.py`, `network-split-guard.sh`, `china-route.sh`, `network-split-domestic-health.sh` | Managed by the six active launchd jobs, together with the external dnsmasq binary; do not run duplicate instances manually |
| Shared dependency | `network_split_policy.py` | Required by the event agent and both routing scripts; not a redundant daemon |
| Maintenance | `build-domain-proxy.py`, `deploy-domain-proxy.py`, `deploy-security-update.zsh`, `install-network-split-dns-event-route-agent.sh` | Manual build, deployment and installation tools, not background jobs; installation can restart services |
| Legacy implementation | `network-split-dns-route-agent.py`, `install-network-split-dns-route-agent.sh` | Not used by the current services; the source remains covered by offline tests; do not run the old installer on this Mac |
| Legacy firewall tools | `install-network-split-dns-no-bypass.sh`, `remove-network-split-dns-firewall.sh` | Historical PF setup and rollback, not current maintenance entrypoints; neither should be run for normal troubleshooting |
| Verification | The nine files in `tests/` | Retained tests, not launchd jobs; `domain_proxy_live_evidence.py` accesses the live network and requires administrator authorization |

Source/deployed copies have different roles: the repository is the editable
source; `/usr/local/sbin` is the launchd execution location. Compare their
contents before deployment rather than treating either location as disposable.
This inventory establishes roles and references, not playback stability.

On 2026-09-25, 25 inactive `.bak` files were moved out of `/usr/local/sbin`
and `/Library/LaunchDaemons` into the root-private archive
`/var/backups/network-split/retired.pMQuNgn3`. Its `SHA256SUMS` records their
original relative paths; all 25 archived files passed verification. Current
programs and launchd configurations stayed in place.

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

Install the policy module before replacing either DNS agent or shell guard.
Deploy `china-route.sh` and `network-split-guard.sh` together: their lock and
force marker now live under root-only-writable `/var/db`, with no `/tmp` fallback.
Let an existing route rebuild finish before replacement; restart only DNS route
agents that are already enabled. Do not restart dnsmasq merely to update these
scripts. Preserve query logging with `nobody:wheel` ownership and mode `0660`.

The old event agent did not track route ownership. Before declaring migration
complete, review existing Ethernet host routes against the address policy and
the old agent log; remove only confirmed obsolete agent-created routes. Do not
flush all host routes or infer ownership from the interface alone.

Offline checks: `python3 -B tests/security_policy.py`,
`zsh tests/security_shell.zsh`, `zsh tests/recovery.zsh`, and
`zsh tests/route-snapshot.zsh`. Tests do not mutate system routes.
