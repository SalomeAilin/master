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

The module also holds the system's native programs, removing the runtime
dependency on a user-writable Python interpreter. The two IP guards still use
the system zsh:

| Program | Role |
| --- | --- |
| `.` (`network-domain-engine`) | Interface-bound HTTP/SOCKS proxy, run by launchd as `nobody` |
| `cmd/network-split-policy` | Address policy for the zsh route guards: one address sets the exit status; standard input is filtered to authorized addresses |
| `cmd/network-split-dns-event-route-agent` | Root daemon that tails dnsmasq's query log and binds authorized domestic answers to Ethernet; `-check` verifies its inputs |
| `cmd/network-split-health` | Dedicated scheduled health executable, with no deployment package dependency |
| `cmd/network-split-status` | Read-only local HTML status collector; `-check` prints evidence without writing files |
| `cmd/network-domain-proxy-config` | Writes the engine configuration from `config/` |
| `cmd/network-domain-proxy-deploy` | Transactional deployment, tool-only installation and explicit backup inspection/removal |
| `cmd/network-domain-proxy-evidence` | Read-only live egress evidence |

Shared code is in `internal/`: `policy`, `dnsobserver`, `proxyconfig` and
`deploy`, `healthcheck`, `runtimecheck` and `statuspage`.

Generate a configuration into an existing private staging directory with
`go run ./cmd/network-domain-proxy-config <config-path>`.
The engine accepts `check -c <path>`, `run -c <path>` and `version`.
The installed deployment tool accepts `backups`, `inspect-backup <exact-path>`
and `remove-backup <exact-path>` for administrator-authorized maintenance.
`install-tool` updates only that executable. The backup and CLI tests cover
path/manifest validation, occupied files, changed state, deployment locking,
preservation of other backups, and tool-only installation failure.
`residues` and `cleanup-residues` inspect and retire known orphan state files.
The health job definition runs the dedicated `network-split-health` executable.
The old deployment-tool `health-check` action is a compatibility entry only.
`internal/healthcheck` owns HTTP/TLS probing, route assessment, the 30/60/120-second
scheduler and private atomic state. `install-health-maintenance` migrates the
existing launchd definition and retires the former shell entry after activation.
Tests cover native cross-process locking, partial writes, grace-period recovery,
scheduling replay, route-drift-only recovery and migration rollback. The health
runtime and its tests do not execute shell scripts or curl. The migration stages
both native executables and the existing health plist; deployment still requires
administrator authorization and scheduled-sample acceptance.

The status collector reads installed configuration instead of embedding local
addresses or home directories. Foreign HEAD probes bind to the configured
foreign interface, never use a proxy or download response bodies. The existing
user LaunchAgent can invoke it with `-output /absolute/path/network-split-status.html`.
It retains the existing private state/log locations by default; outputs are
atomic and log history is bounded to one 1 MiB file plus three archives.
Preexisting oversized logs are refused, not silently discarded. Archive those
privately before migrating. Status output is IP-route/DNS/connectivity evidence,
not proof of proxy domain routing, application success or playback stability.
Private native logs use `--log-file`, `--log-max-size` and
`--log-max-backups`. The service defaults to one 2 MiB active file and three
numbered archives. Oversized entries are marked and bounded; an old oversized
file is archived at startup rather than silently truncated. Only one process
may write a log path.

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

## Verification Limits

Tests cover routing precedence, mixed answers, private-address rejection,
cached restart, corrupt-update retention, native log limits, buffered CONNECT
bytes, HTTP payload and header forwarding, SOCKS commands, DoH parsing, DNS
cache lifetime, one-way transfers past the idle limit, interface failure and
shutdown. Isolated invalid-interface injection does not disconnect the host's
physical Wi-Fi. Successful TLS and HTTP probes do not
establish sustained video playback quality or the absence of all defects.
