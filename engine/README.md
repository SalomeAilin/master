# Independent Routing Engine

This directory contains an independently written macOS direct-proxy engine.
It does not import, link, copy, invoke, or build the former sing-box engine.
`go list -m all` lists only `network-owned-engine`; there are no third-party
Go module dependencies or a `go.sum`. Protocol parsing, HTTP, TLS and the DNS
message parser are supplied by the Go standard library. Routing decisions,
interface constraints, proxy dispatch, rule refresh, lifecycle and private log
retention are implemented here.

This is implementation independence, not a claim that the Go runtime, macOS or
the external rule datasets are original work. Those components retain their
own authorship and licenses. The historical upstream source and its notices
remain in Git history. No upstream copyright is reassigned by this migration.

## Build and Check

Run from this directory with Go 1.26.8:

```sh
go test -race ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '-s -w' \
  -o /path/to/staging/network-domain-engine .
```

Package-local tests are colocated with their Go package. Integration checks
and deployment checks are in the repository's `tests/` directory.

From the repository root, generate a configuration into an existing private
staging directory with `python3 -B scripts/build-domain-proxy.py <config-path>`.
The program accepts `check -c <path>`, `run -c <path>` and `version`.
Private native logs use `--log-file`, `--log-max-size` and
`--log-max-backups`. The service defaults to one 2 MiB active file and three
numbered archives. Oversized entries are marked and bounded; an old oversized
file is archived at startup rather than silently truncated. Only one process
may write a log path.

## Routing Contract

The listener is IPv4 loopback only. HTTP forwarding, HTTP CONNECT, cleartext
WebSocket upgrades, and SOCKS5 TCP CONNECT share the same routing core.
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
through a DoH adapter. DNS results are not persistently cached by this engine.

## Data and Updates

The three external JSON datasets come from
[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat), with
their [original license](https://github.com/MetaCubeX/meta-rules-dat/blob/master/LICENSE)
and source attribution preserved by reference. These are classification data,
not an imported routing engine. No datasets are vendored in this repository.
Local policy is still read from the checked-in `config/` files.

Valid cached JSON takes precedence over read-only installation seeds, so a
restart survives unavailable update servers. Updates occur hourly over
certificate-verified HTTPS bound to the foreign interface. Each payload is
limited to 16 MiB, parsed strictly and compiled before atomic cache replacement
and in-memory activation. Failed, empty, oversized, unsupported or corrupt
updates keep the last working rules. Runtime caches are private, with only
three fixed dataset names. No additional updater daemon is installed.

## Verification Limits

Tests cover routing precedence, mixed answers, private-address rejection,
cached restart, corrupt-update retention, native log limits, buffered CONNECT
bytes, HTTP payload and header forwarding, SOCKS commands, DoH parsing,
interface failure and shutdown. Isolated invalid-interface injection does not
disconnect the host's physical Wi-Fi. Successful TLS and HTTP probes do not
establish sustained video playback quality or the absence of all defects.
