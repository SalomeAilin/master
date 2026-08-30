#!/usr/bin/env python3
"""Observe dnsmasq replies and promptly bind domestic CDN IPs to Ethernet.

This service never proxies DNS. If it stops, dnsmasq continues to resolve
normally and the existing route guard remains the fallback.
"""

import logging
import os
import re
import subprocess
import time

DNSMASQ_LOG = "/var/log/dnsmasq-network-split-query.log"
DNSMASQ_CONFIG = "/usr/local/etc/dnsmasq-network-split.conf"
LOG_FILE = "/var/log/network-split-dns-event-route-agent.log"
MAX_DNSMASQ_LOG_BYTES = 64 * 1024 * 1024
ETH_GATEWAY = "192.168.1.1"
ETH_INTERFACE = "en0"

QUERY_RE = re.compile(r"dnsmasq\[\d+\]:\s+(\d+)\s+\S+\s+query\[[^]]+\]\s+(\S+)\s+from")
ANSWER_RE = re.compile(r"dnsmasq\[\d+\]:\s+(\d+)\s+\S+\s+(?:reply|cached)\s+(\S+)\s+is\s+(\S+)")
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def setup_logging():
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )


def normalized(name):
    return name.rstrip(".").lower()


def load_suffixes():
    suffixes = {"cn"}
    with open(DNSMASQ_CONFIG, "r", encoding="utf-8") as config:
        for line in config:
            line = line.strip()
            if not line.startswith("server=/"):
                continue
            parts = line.split("/")
            if len(parts) >= 3 and parts[1]:
                suffixes.add(normalized(parts[1]))
    return suffixes


def is_domestic(name, suffixes):
    name = normalized(name)
    return any(name == suffix or name.endswith("." + suffix) for suffix in suffixes)


def route_is_ethernet(ip):
    try:
        result = subprocess.run(
            ["/sbin/route", "-n", "get", ip],
            capture_output=True,
            text=True,
            timeout=1,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return f"gateway: {ETH_GATEWAY}" in result.stdout and f"interface: {ETH_INTERFACE}" in result.stdout


def bind_ethernet_route(domain, ip):
    if route_is_ethernet(ip):
        return
    try:
        subprocess.run(["/sbin/route", "-n", "delete", "-host", ip], capture_output=True, timeout=1, check=False)
        result = subprocess.run(
            ["/sbin/route", "-n", "add", "-host", ip, ETH_GATEWAY, "-ifp", ETH_INTERFACE],
            capture_output=True,
            text=True,
            timeout=1,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        logging.error("route command failed domain=%s ip=%s", domain, ip)
        return
    if route_is_ethernet(ip):
        logging.info("route bound domain=%s ip=%s", domain, ip)
    else:
        logging.error("route bind failed domain=%s ip=%s exit=%s error=%s", domain, ip, result.returncode, result.stderr.strip())


def follow_alias(name, aliases):
    name = normalized(name)
    seen = set()
    while name in aliases and name not in seen:
        seen.add(name)
        name = aliases[name]
    return name


def process_line(line, suffixes, aliases, domestic_queries):
    query = QUERY_RE.search(line)
    if query:
        query_id, domain = query.groups()
        domain = normalized(domain)
        if is_domestic(domain, suffixes):
            domestic_queries[query_id] = (domain, time.monotonic())
        return

    match = ANSWER_RE.search(line)
    if not match:
        return
    query_id, name, value = match.groups()
    name, value = normalized(name), normalized(value)
    origin = domestic_queries.get(query_id, (follow_alias(name, aliases), 0))[0]
    if IPV4_RE.match(value):
        if is_domestic(name, suffixes) or is_domestic(origin, suffixes):
            bind_ethernet_route(origin, value)
        return
    # dnsmasq emits CNAME replies in the same form; retain only domestic chains.
    if is_domestic(name, suffixes) or is_domestic(origin, suffixes):
        aliases[value] = origin


def main():
    setup_logging()
    suffixes = load_suffixes()
    config_mtime = os.path.getmtime(DNSMASQ_CONFIG)
    aliases = {}
    domestic_queries = {}
    inode = None
    stream = None
    position = 0
    logging.info("started suffixes=%s", len(suffixes))

    while True:
        try:
            current_mtime = os.path.getmtime(DNSMASQ_CONFIG)
            if current_mtime != config_mtime:
                suffixes = load_suffixes()
                config_mtime = current_mtime
                aliases.clear()
                logging.info("reloaded suffixes=%s", len(suffixes))

            stat = os.stat(DNSMASQ_LOG)
            if stream is None or inode != stat.st_ino or stat.st_size < position:
                if stream is not None:
                    stream.close()
                stream = open(DNSMASQ_LOG, "r", encoding="utf-8", errors="replace")
                stream.seek(0, os.SEEK_END)
                position = stream.tell()
                inode = stat.st_ino

            line = stream.readline()
            if not line:
                if position >= MAX_DNSMASQ_LOG_BYTES:
                    stream.close()
                    stream = None
                    inode = None
                    os.truncate(DNSMASQ_LOG, 0)
                    position = 0
                    logging.info("query log compacted limit_bytes=%s", MAX_DNSMASQ_LOG_BYTES)
                    continue
                time.sleep(0.05)
                continue
            position = stream.tell()
            process_line(line, suffixes, aliases, domestic_queries)
            now = time.monotonic()
            for query_id, (_, seen_at) in list(domestic_queries.items()):
                if now - seen_at > 30:
                    del domestic_queries[query_id]
        except FileNotFoundError:
            time.sleep(0.2)
        except Exception as error:
            logging.exception("observer error=%s", error)
            time.sleep(0.2)


if __name__ == "__main__":
    main()
