# Independent Routing Engine

This directory contains an independently written macOS direct-proxy engine and
the Go programs for the rest of the split-routing system (see the table below).
It does not import, link, copy, invoke, or build the former sing-box engine.
`go list -m all` lists only `network-owned-engine`; there are no third-party
Go module dependencies or a `go.sum`. Protocol parsing, HTTP, TLS and the DNS
message parser are supplied by the Go standard library. Routing decisions,
interface constraints, proxy dispatch, rule refresh, lifecycle and private log
retention are implemented here.

This is implementation independence, not a claim that the Go runtime, macOS or
the external rule datasets are original work. Those components retain their
own authorship and licenses. The historical upstream source remains in Git
history, with its original notice at [archive/sing-box-LICENSE](../archive/sing-box-LICENSE).
No upstream copyright is reassigned by this migration.

## Build and Check

Run from this directory with Go 1.26.8:

```sh
go test -race ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '-s -w' \
  -o /path/to/staging/network-domain-engine .
```

Package-local tests are colocated with their Go package. Integration tests that
build and run the engine binary use the `integration` tag:
`go test -tags integration -run Integration .`; add `NETWORK_SPLIT_LIVE=1` for
the real-network fail-closed check.

## Programs and Shared Code

The root package builds `network-domain-engine`; `cmd/` contains the native
policy, observer, health, status, configuration, deployment and evidence
commands. Their roles, installation paths and invocation rules are listed once
in the [operations guide](../docs/operations.md#组件清单).

| Package | Responsibility |
| --- | --- |
| `internal/policy` | Authorize public IPv4 addresses against the configured intervals |
| `internal/dnsobserver` | Follow DNS query logs, correlate answers and request authorized routes |
| `internal/healthcheck` | Probe, schedule, lock and publish bounded private health state |
| `internal/statuspage` | Collect read-only evidence and render the local status page |
| `internal/proxyconfig` | Generate proxy configuration from repository policy |
| `internal/runtimecheck` | Shared paths, command results and runtime-file/PID checks |
| `internal/deploy` | Administrator-authorized installation, rollback and explicit maintenance |

The dedicated health command does not import `internal/deploy`. Its scheduled
entry is separate from the maintenance CLI; the latter retains a legacy
`health-check` action only for compatibility. Two IP guards still use system
zsh, and dnsmasq is installed separately.

Builds do not activate services. See [deployment](../docs/operations.md#构建与部署),
[maintenance](../docs/operations.md#备份与残留) and
[log limits](../docs/operations.md#日志与状态) before changing an installed copy.
Historical measurements are in the [acceptance record](../docs/history.md).

## Routing Contract

The listener is IPv4 loopback only. HTTP forwarding, HTTP CONNECT, cleartext
WebSocket upgrades, and SOCKS5 TCP CONNECT share the same routing core.
Tunnels close after five minutes without bytes in either direction, so a quiet
request side never ends a long download, or the reverse. A real end of stream
is forwarded as a half-close; the other side then has 30 seconds to send again.
SOCKS UDP, IPv6 proxy destinations, remote proxy protocols, TUN, TLS interception
and global route changes are deliberately outside this engine.

Classification order is protected foreign domains, local domestic overrides,
maintained foreign domains, then maintained domestic domains. Known domains
retain their decision even if their CDN address is in the other region.
Unknown hostnames use domestic DoH and IP-based inference. The first returned
public IPv4 address chooses the geographic group; only addresses from that
same group are eligible for connection attempts. This is a geographic
heuristic, not a guarantee about site ownership. Any private, loopback,
link-local, shared-address or unsupported answer rejects the request.

Every data and DoH socket has a macOS `IP_BOUND_IF` kernel constraint before
connect. Multipath TCP is disabled. Interface failure is an error, never an
invitation to dial unbound or retry on the other interface. DoH endpoints are
IP literals with certificate-verified TLS names; there is no plaintext DNS
transport fallback. Go's resolver handles DNS framing and response validation
through a DoH adapter. Successful answers are kept in memory for their DNS
TTL, at most five minutes and 4096 names per resolver. Failures are not cached,
and nothing is written to disk.

## Data and Updates

The three external JSON datasets come from
[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat), with
their [original license](https://github.com/MetaCubeX/meta-rules-dat/blob/master/LICENSE)
and source attribution preserved by reference. These are classification data,
not an imported routing engine. No datasets are vendored in this repository.
Local policy is still read from the checked-in `config/` files.

Valid cached JSON takes precedence over read-only installation seeds, so a
restart survives unavailable update servers. Updates occur hourly over
certificate-verified HTTPS bound to the foreign interface. After the first
download each check sends the dataset's ETag, so an unchanged dataset costs a
small 304 response instead of a full download over the metered Wi-Fi link; a
validator is adopted only together with data that was applied successfully.
Each payload is limited to 16 MiB, parsed strictly and compiled before atomic
cache replacement and in-memory activation. Failed, empty, oversized,
unsupported or corrupt updates keep the last working rules. Runtime caches are private, with only
three fixed dataset names. No additional updater daemon is installed.

## IP Routing and Health Checks

The DNS observer correlates CNAME answers within one dnsmasq process, query ID
and client. Pending domestic queries expire after 30 seconds and are capped at
4096; reused IDs, configuration reloads and log changes discard stale context.
A shared CDN alias is not retained as a global domestic classification.

Address policy uses sorted, merged IPv4 intervals. It preserves gaps, rejects
special addresses, checks file identity and modification metadata, and
authorizes nothing when an input is missing or malformed. Guards filter each
domain's answer batch in one helper invocation; route mutations check policy
again. Domain ownership alone does not authorize a global IP route.

The default-route guard holds its existing kernel lock to prevent overlapping
instances. It reconciles reject routes even if the Wi-Fi default has already
returned. This is scheduled recovery, not an event-driven guarantee; the lock
does not serialize every component that can manage routes.

The domestic health job wakes every 30 seconds. Six healthy 2xx/3xx samples
establish a latency baseline and permit a 60-second probe interval; six
acceptable trial samples permit 120 seconds. A 401/403 response can establish
connectivity but is not a performance-baseline sample.

A latency regression must exceed both 50% and 250 ms. Three consecutive
regressions, or a six-sample median above that threshold, restore 30 seconds.
Probe failures, confirmed drift and unacceptable/slow responses also restore
the baseline cadence, with a ten-minute cooldown before another trial.
Malformed, stale or backward-clock state resets the schedule.

The probe uses direct IPv4, certificate-verified TLS and a 4 MiB response cap.
The expected interface comes from the installed configuration and its gateway
from the scoped route. Only confirmed route drift requests the existing guard,
using `kickstart` without `-k`; DNS/HTTP errors or timing changes do not restart
services. At a 120-second interval, detecting a failure can take about two
minutes plus probe time. One endpoint is not a monitor for every application.

## Verification Limits

Tests cover routing precedence, mixed answers, private-address rejection,
cached restart, corrupt-update retention, native log limits, buffered CONNECT
bytes, HTTP payload and header forwarding, SOCKS commands, DoH parsing, DNS
cache lifetime, one-way transfers past the idle limit, interface failure and
shutdown. Isolated invalid-interface injection does not disconnect the host's
physical Wi-Fi. Successful TLS and HTTP probes do not
establish sustained video playback quality or the absence of all defects.
