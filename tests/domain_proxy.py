"""Configuration regressions for connection-scoped domain routing."""
import importlib.util
from pathlib import Path
import unittest
import ipaddress

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("builder", ROOT / "build-domain-proxy.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class DomainProxyTests(unittest.TestCase):
    def setUp(self):
        self.config = builder.build(ROOT)
        self.suffixes = self.config["route"]["rules"][1]["domain_suffix"]

    def domestic(self, name):
        return name in self.config["route"]["rules"][1]["domain"] or any(name == s or name.endswith("." + s) for s in self.suffixes)

    def test_media_and_foreign_cdn_keep_domain_classification(self):
        for name in ("v26-web-prime.douyinvod.com", "billing.console.aliyun.com",
                     "player-gw-s.aliyuncs.com", "api.smoot.apple.cn", "alsay.net",
                     "vc-gate-edge.ndcpp.com", "lf-cdn-tos.bytescm.com"):
            self.assertTrue(self.domestic(name), name)

    def test_foreign_and_suffix_confusion(self):
        for name in ("github.com", "claude.ai", "douyin.com.attacker.test", "notdouyin.com",
                     "other.ndcpp.com", "tiktok.com", "x.vc-gate-edge.ndcpp.com"):
            self.assertFalse(self.domestic(name), name)

    def test_interface_pinning_and_no_fallback(self):
        self.assertEqual(self.config["route"]["final"], "foreign-wifi")
        routes = {o["tag"]: o for o in self.config["outbounds"]}
        self.assertEqual(routes["foreign-wifi"]["bind_interface"], "en1")
        self.assertEqual(routes["domestic-wired"]["bind_interface"], "en0")
        self.assertTrue(all(o["type"] == "direct" for o in routes.values()))
        self.assertEqual(self.config["inbounds"][0]["listen"], "127.0.0.1")
        self.assertNotIn("set_system_proxy", self.config["inbounds"][0])
        self.assertEqual(set(self.config["experimental"]), {"cache_file"})

    def test_known_foreign_precedes_unknown_ip_inference(self):
        rules = self.config["route"]["rules"]
        self.assertIn("github.com", rules[0]["domain_suffix"])
        self.assertEqual(rules[2]["rule_set"], ["geosite-geolocation-!cn"])
        self.assertEqual(rules[2]["outbound"], "foreign-wifi")
        self.assertEqual(rules[4]["action"], "resolve")
        self.assertEqual(rules[4]["server"], "domestic-dns")
        self.assertEqual(rules[5], {"ip_is_private": True, "action": "reject"})
        self.assertEqual(rules[6]["rule_set"], ["geoip-cn"])
        networks = [ipaddress.ip_network(n) for n in rules[7]["ip_cidr"]]
        self.assertTrue(any(ipaddress.ip_address("223.5.5.5") in n for n in networks))
        self.assertFalse(any(ipaddress.ip_address("1.1.1.1") in n for n in networks))

    def test_updates_are_cached_and_pinned_without_new_daemon(self):
        for rule_set in self.config["route"]["rule_set"]:
            self.assertTrue(rule_set["url"].startswith("https://raw.githubusercontent.com/SagerNet/"))
            self.assertEqual(rule_set["http_client"]["bind_interface"], "en1")
            self.assertEqual(rule_set["update_interval"], "1h")
            self.assertEqual(rule_set["http_client"]["domain_resolver"], "rules-bootstrap")
            self.assertTrue(rule_set["initial_path"].startswith("/usr/local/etc/network-domain-rules/"))
        self.assertTrue(self.config["experimental"]["cache_file"]["enabled"])
        self.assertFalse(self.config["experimental"]["cache_file"]["store_dns"])

    def test_dns_is_encrypted_and_independent_per_interface(self):
        servers = {s["tag"]: s for s in self.config["dns"]["servers"]}
        for tag, interface in (("domestic-dns", "en0"), ("foreign-dns", "en1")):
            server = servers[tag]
            self.assertEqual(server["type"], "https")
            self.assertEqual(server["bind_interface"], interface)
            self.assertTrue(server["tls"]["enabled"])
            self.assertFalse(server["tls"].get("insecure", False))
            ipaddress.ip_address(server["server"])


if __name__ == "__main__":
    unittest.main()
