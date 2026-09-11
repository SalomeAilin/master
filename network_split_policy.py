"""Authorize DNS-derived routes independently of domain ownership."""

import ipaddress
import os
import sys

POLICY_FILES = (
    "/usr/local/etc/china_ip_list.txt",
    "/usr/local/etc/domestic_extra_routes.txt",
)
_signature = None
_networks = ()


def allowed(ip):
    global _signature, _networks
    try:
        address = ipaddress.IPv4Address(ip)
        if not address.is_global or address.is_multicast:
            return False
        signature = tuple((p, os.stat(p).st_mtime_ns, os.stat(p).st_size) for p in POLICY_FILES)
        if signature != _signature:
            networks = []
            for path in POLICY_FILES:
                with open(path, encoding="ascii") as source:
                    for line in source:
                        value = line.split("#", 1)[0].strip()
                        if value:
                            networks.append(ipaddress.IPv4Network(value))
            _networks = tuple(networks)
            _signature = signature
        return any(address in network for network in _networks)
    except (OSError, ValueError, UnicodeError):
        # Missing or invalid policy must never authorize a route from DNS alone.
        _signature, _networks = None, ()
        return False


if __name__ == "__main__":
    if len(sys.argv) == 2:
        sys.exit(0 if allowed(sys.argv[1]) else 1)
    for line in sys.stdin:
        value = line.strip()
        if allowed(value):
            print(value)
