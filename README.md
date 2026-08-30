# macOS Split Routing Backup

This repository backs up the active split-routing configuration for this Mac.

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
- `network-split-domestic-health.sh` -> `/usr/local/sbin/`
- `dnsmasq-network-split.conf` -> `/usr/local/etc/`
- `china_ip_list.txt` -> `/usr/local/etc/`
- `domestic_domains.conf` -> `/usr/local/etc/`
- `domestic_extra_routes.txt` -> `/usr/local/etc/`
- `com.local.*.plist` -> `/Library/LaunchDaemons/`
- `homebrew.mxcl.dnsmasq.plist` -> `/Library/LaunchDaemons/`

Review interface names, gateways, DNS addresses, ownership, and launchd state
before restoring on another Mac or after a major network topology change.
`network-split-status.html` is intentionally excluded because it can contain
local network details and is generated from the live system.
