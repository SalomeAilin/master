"""Policy regressions for the independent, connection-scoped routing engine."""
import importlib.util
import ipaddress
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("builder", ROOT / "scripts/build-domain-proxy.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class DomainProxyTests(unittest.TestCase):
    def setUp(self):
        self.config = builder.build_independent(ROOT / "config")
        self.local = self.config["local_domestic"]

    def domestic(self, name):
        return name in self.local["domain"] or any(name == s or name.endswith("." + s)
                                                   for s in self.local["domain_suffix"])

    def test_media_and_foreign_cdn_keep_domain_classification(self):
        for name in ("v26-web-prime.douyinvod.com", "billing.console.aliyun.com",
                     "player-gw-s.aliyuncs.com", "api.smoot.apple.cn",
                     "vc-gate-edge.ndcpp.com", "lf-cdn-tos.bytescm.com"):
            self.assertTrue(self.domestic(name), name)

    def test_foreign_and_suffix_confusion(self):
        for name in ("github.com", "claude.ai", "douyin.com.attacker.test", "notdouyin.com",
                     "other.ndcpp.com", "tiktok.com", "x.vc-gate-edge.ndcpp.com"):
            self.assertFalse(self.domestic(name), name)

    def test_interfaces_are_separate_without_fallback(self):
        self.assertEqual(self.config["foreign"]["interface"], "en1")
        self.assertEqual(self.config["domestic"]["interface"], "en0")
        self.assertEqual(self.config["listen"], "127.0.0.1:17890")
        self.assertNotIn("fallback", self.config)

    def test_known_foreign_is_protected_from_ip_inference(self):
        protected = self.config["protected_foreign"]["domain_suffix"]
        for domain in ("github.com", "claude.ai", "tiktok.com", "google.com"):
            self.assertIn(domain, protected)
        networks = [ipaddress.ip_network(n) for n in self.config["china_cidr"]]
        self.assertTrue(any(ipaddress.ip_address("223.5.5.5") in n for n in networks))
        self.assertFalse(any(ipaddress.ip_address("1.1.1.1") in n for n in networks))

    def test_json_rule_data_is_cached_without_an_engine_dependency(self):
        self.assertEqual({s["kind"] for s in self.config["rule_sources"]}, {"domestic", "foreign", "china"})
        for source in self.config["rule_sources"]:
            self.assertTrue(source["url"].startswith("https://"))
            self.assertTrue(source["url"].endswith(".json"))
            self.assertEqual(source["interval"], "1h")
            self.assertTrue(source["seed"].startswith(str(builder.RULES_DIRECTORY)))
        self.assertEqual(self.config["cache_directory"], builder.CACHE_DIRECTORY)
        self.assertNotIn("experimental", self.config)
        self.assertNotIn("outbounds", self.config)

    def test_doh_endpoints_are_literals_with_certificate_names(self):
        for kind, address, name in (("domestic", "223.5.5.5", "dns.alidns.com"),
                                    ("foreign", "1.1.1.1", "cloudflare-dns.com")):
            dns = self.config[kind]["dns"]
            self.assertEqual(dns, {"address": address, "server_name": name})
            self.assertTrue(ipaddress.ip_address(dns["address"]).is_global)


if __name__ == "__main__":
    unittest.main()
