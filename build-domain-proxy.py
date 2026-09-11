#!/usr/bin/env python3
"""Build automatic, connection-scoped routing with explicit policy precedence."""
import argparse
import json
import ipaddress
from pathlib import Path

RULES_DIRECTORY = Path("/usr/local/etc/network-domain-rules")
CACHE_PATH = "/var/db/network-domain-proxy/cache.db"
RULE_SOURCES = {
    "geosite-geolocation-cn": "sing-geosite",
    "geosite-geolocation-!cn": "sing-geosite",
    "geoip-cn": "sing-geoip",
}
FOREIGN_PROTECTED = [
    "github.com", "githubusercontent.com", "githubassets.com", "githubcopilot.com",
    "claude.ai", "claude.com", "anthropic.com", "openai.com", "chatgpt.com",
    "oaistatic.com", "oaiusercontent.com", "google.com", "googleapis.com",
    "gstatic.com", "youtube.com", "googlevideo.com", "ytimg.com", "tiktok.com",
]


def build(root, rules_directory=RULES_DIRECTORY, cache_path=CACHE_PATH):
    hosts = [line.split("#", 1)[0].strip() for line in
             (root / "domestic_proxy_hosts.conf").read_text().splitlines()]
    hosts = sorted({host.lower().rstrip(".") for host in hosts if host})
    suffixes = set()
    for line in (root / "dnsmasq-network-split.conf").read_text().splitlines():
        if line.startswith("server=/"):
            _, domain, server = line.split("/", 2)
            if server in ("223.5.5.5", "119.29.29.29"):
                suffixes.add(domain.lower().rstrip("."))
    for line in (root / "domestic_domains.conf").read_text().splitlines():
        domain = line.split("#", 1)[0].strip().lower().rstrip(".")
        if domain:
            suffixes.add(domain)
    if "douyinvod.com" not in suffixes or "cn" not in suffixes:
        raise ValueError("Incomplete domestic domain policy")
    networks = []
    for name in ("china_ip_list.txt", "domestic_extra_routes.txt"):
        for line in (root / name).read_text().splitlines():
            value = line.split("#", 1)[0].strip()
            if value:
                networks.append(str(ipaddress.IPv4Network(value)))
    local_domains = {"domain": hosts, "domain_suffix": sorted(suffixes)}
    foreign_domains = {"domain_suffix": FOREIGN_PROTECTED}
    remote_sets = [{
        "type": "remote", "tag": tag, "format": "binary",
        "url": f"https://raw.githubusercontent.com/SagerNet/{repo}/rule-set/{tag}.srs",
        "initial_path": str(Path(rules_directory) / (tag + ".srs")),
        "http_client": {"bind_interface": "en1", "domain_resolver": "rules-bootstrap", "connect_timeout": "10s"},
        "update_interval": "1h",
    } for tag, repo in RULE_SOURCES.items()]
    return {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"type": "https", "tag": "domestic-dns", "server": "223.5.5.5",
                 "tls": {"enabled": True, "server_name": "dns.alidns.com"},
                 "bind_interface": "en0", "connect_timeout": "5s"},
                {"type": "https", "tag": "foreign-dns", "server": "1.1.1.1",
                 "tls": {"enabled": True, "server_name": "cloudflare-dns.com"},
                 "bind_interface": "en1", "connect_timeout": "5s"},
                # Bootstrap updates independently of the new DoH transport startup.
                {"type": "udp", "tag": "rules-bootstrap", "server": "127.0.0.1"},
            ],
            "strategy": "ipv4_only",
            "final": "foreign-dns",
            "rules": [
                {**foreign_domains, "action": "route", "server": "foreign-dns"},
                {**local_domains, "action": "route", "server": "domestic-dns"},
                {"rule_set": ["geosite-geolocation-!cn"], "action": "route", "server": "foreign-dns"},
                {"rule_set": ["geosite-geolocation-cn"], "action": "route", "server": "domestic-dns"},
            ],
        },
        "inbounds": [{"type": "mixed", "tag": "browser", "listen": "127.0.0.1", "listen_port": 17890}],
        "outbounds": [
            {"type": "direct", "tag": "foreign-wifi", "bind_interface": "en1", "domain_resolver": "foreign-dns", "connect_timeout": "10s"},
            {"type": "direct", "tag": "domestic-wired", "bind_interface": "en0", "domain_resolver": "domestic-dns", "connect_timeout": "10s"},
        ],
        "route": {
            "rules": [
                {**foreign_domains, "action": "route", "outbound": "foreign-wifi"},
                {**local_domains, "action": "route", "outbound": "domestic-wired"},
                {"rule_set": ["geosite-geolocation-!cn"], "action": "route", "outbound": "foreign-wifi"},
                {"rule_set": ["geosite-geolocation-cn"], "action": "route", "outbound": "domestic-wired"},
                # Only unclassified hostnames reach IP inference. No global route is learned.
                {"domain_regex": [".+"], "action": "resolve", "server": "domestic-dns", "strategy": "ipv4_only", "timeout": "5s"},
                {"ip_is_private": True, "action": "reject"},
                {"rule_set": ["geoip-cn"], "action": "route", "outbound": "domestic-wired"},
                {"ip_cidr": networks, "action": "route", "outbound": "domestic-wired"},
            ],
            "rule_set": remote_sets,
            "final": "foreign-wifi",
            "default_domain_resolver": "foreign-dns",
        },
        "experimental": {"cache_file": {"enabled": True, "path": str(cache_path), "store_dns": False}},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--rules-directory", type=Path, default=RULES_DIRECTORY)
    parser.add_argument("--cache-path", default=CACHE_PATH)
    args = parser.parse_args()
    args.output.write_text(json.dumps(build(Path(__file__).resolve().parent, args.rules_directory, args.cache_path), indent=2) + "\n")
