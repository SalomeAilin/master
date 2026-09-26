"""Authorize DNS-derived routes independently of domain ownership."""

from bisect import bisect_right
import ipaddress
import os
import sys

POLICY_FILES = (
    "/usr/local/etc/china_ip_list.txt",
    "/usr/local/etc/domestic_extra_routes.txt",
)
_signature = None
_starts = ()
_ends = ()


def allowed(ip):
    global _signature, _starts, _ends
    try:
        address = ipaddress.IPv4Address(ip)
        if not address.is_global or address.is_multicast:
            return False
        signature = []
        for path in POLICY_FILES:
            status = os.stat(path)
            signature.append((path, status.st_dev, status.st_ino,
                              status.st_mtime_ns, status.st_ctime_ns, status.st_size))
        signature = tuple(signature)
        if signature != _signature:
            ranges = []
            for path in POLICY_FILES:
                with open(path, encoding="ascii") as source:
                    for line in source:
                        value = line.split("#", 1)[0].strip()
                        if value:
                            network = ipaddress.IPv4Network(value)
                            ranges.append((int(network.network_address), int(network.broadcast_address)))
            # Merge only overlapping or adjacent ranges; gaps remain unauthorized.
            merged = []
            for start, end in sorted(ranges):
                if merged and start <= merged[-1][1] + 1:
                    merged[-1] = (merged[-1][0], max(merged[-1][1], end))
                else:
                    merged.append((start, end))
            _starts = tuple(start for start, _ in merged)
            _ends = tuple(end for _, end in merged)
            _signature = signature
        value = int(address)
        index = bisect_right(_starts, value) - 1
        return index >= 0 and value <= _ends[index]
    except (OSError, ValueError, UnicodeError):
        # Missing or invalid policy must never authorize a route from DNS alone.
        _signature, _starts, _ends = None, (), ()
        return False


if __name__ == "__main__":
    if len(sys.argv) == 2:
        sys.exit(0 if allowed(sys.argv[1]) else 1)
    for line in sys.stdin:
        value = line.strip()
        if allowed(value):
            print(value)
