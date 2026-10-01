#!/usr/bin/env python3
"""Build automatic, connection-scoped routing with explicit policy precedence."""
import argparse
import json
import ipaddress
from pathlib import Path

RULES_DIRECTORY = Path("/usr/local/etc/network-domain-rules-independent")
CACHE_DIRECTORY = "/var/db/network-domain-proxy/independent-cache"
FOREIGN_PROTECTED = [
    "github.com", "githubusercontent.com", "githubassets.com", "githubcopilot.com",
    "claude.ai", "claude.com", "anthropic.com", "openai.com", "chatgpt.com",
    "oaistatic.com", "oaiusercontent.com", "google.com", "googleapis.com",
    "gstatic.com", "youtube.com", "googlevideo.com", "ytimg.com", "tiktok.com",
]


def load_policy(root):
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
    return local_domains, foreign_domains, networks


def build_independent(root, rules_directory=None, cache_directory=None):
    local_domains, foreign_domains, networks = load_policy(root)
    rules_directory = Path(rules_directory or RULES_DIRECTORY)
    return {
        "version": 1, "listen": "127.0.0.1:17890", "max_clients": 512,
        "domestic": {"interface": "en0", "dns": {"address": "223.5.5.5", "server_name": "dns.alidns.com"}},
        "foreign": {"interface": "en1", "dns": {"address": "1.1.1.1", "server_name": "cloudflare-dns.com"}},
        "protected_foreign": foreign_domains, "local_domestic": local_domains,
        "china_cidr": networks,
        "cache_directory": str(cache_directory or CACHE_DIRECTORY),
        "rule_sources": [{
            "kind": kind,
            "url": f"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/{path}.json",
            "seed": str(rules_directory / (kind + ".json")), "interval": "1h",
        } for kind, path in (
            ("domestic", "geo/geosite/geolocation-cn"),
            ("foreign", "geo/geosite/geolocation-!cn"),
            ("china", "geo/geoip/cn"),
        )],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--rules-directory", type=Path)
    parser.add_argument("--cache-path")
    args = parser.parse_args()
    policy_dir = Path(__file__).resolve().parents[1] / "config"
    config = build_independent(policy_dir, args.rules_directory, args.cache_path)
    args.output.write_text(json.dumps(config, indent=2) + "\n")
