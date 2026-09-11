"""Offline regression tests; all route commands are mocked."""

import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import mock_open, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import network_split_policy as policy


def module(filename):
    spec = importlib.util.spec_from_file_location(filename, ROOT / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


event = module("network-split-dns-event-route-agent.py")
proxy = module("network-split-dns-route-agent.py")


class SecurityTests(unittest.TestCase):
    def setUp(self):
        policy.POLICY_FILES = tuple(str(ROOT / name) for name in (
            "china_ip_list.txt", "domestic_extra_routes.txt"))
        policy._signature = None

    def test_approved_domestic_and_explicit_cdn(self):
        for ip in ("223.5.5.5", "119.29.29.29", "128.14.180.34"):
            self.assertTrue(policy.allowed(ip), ip)

    def test_foreign_special_and_alternate_forms_denied(self):
        for ip in ("1.1.1.1", "8.8.8.8", "127.0.0.1", "192.168.1.1",
                   "224.0.0.1", "::1", "0x08080808", "008.008.008.008", "999.1.1.1"):
            self.assertFalse(policy.allowed(ip), ip)

    def test_missing_and_invalid_policy_fail_closed(self):
        self.assertTrue(policy.allowed("223.5.5.5"))
        with patch.object(policy.os, "stat", side_effect=OSError):
            self.assertFalse(policy.allowed("223.5.5.5"))
        with patch("builtins.open", mock_open(read_data="invalid\n")):
            self.assertFalse(policy.allowed("223.5.5.5"))

    def test_hostile_dns_and_alias_do_not_touch_routes(self):
        with patch.object(event.subprocess, "run") as run:
            queries, aliases = {}, {}
            event.process_line("dnsmasq[1]: 7 client query[A] evil.cn from client", {"cn"}, aliases, queries)
            for line in ("dnsmasq[1]: 7 client reply evil.cn is 8.8.8.8",
                         "dnsmasq[1]: 7 client reply alias.example is 1.1.1.1"):
                event.process_line(line, {"cn"}, aliases, queries)
            run.assert_not_called()

    def test_both_sinks_enforce_policy_before_route_lookup(self):
        for agent, call in ((event, lambda: event.bind_ethernet_route("evil.cn", "8.8.8.8")),
                            (proxy, lambda: proxy.bind_route("8.8.8.8"))):
            with patch.object(agent.subprocess, "run") as run:
                call()
                run.assert_not_called()

    def test_legitimate_bind_still_uses_ifp(self):
        for agent, call in ((event, lambda: event.bind_ethernet_route("good.cn", "223.5.5.5")),
                            (proxy, lambda: proxy.bind_route("223.5.5.5"))):
            with patch.object(agent, "route_is_ethernet", side_effect=[False, True]), patch.object(agent.subprocess, "run") as run:
                run.return_value.returncode = 0
                call()
                self.assertIn(["/sbin/route", "-n", "add", "-host", "223.5.5.5", "192.168.1.1", "-ifp", "en0"], [c.args[0] for c in run.call_args_list])

    def test_proxy_preserves_dns_without_unauthorized_route(self):
        with patch.object(proxy, "forward", return_value=b"response"), patch.object(proxy, "ipv4_answers", return_value=[("8.8.8.8", 60)]), patch.object(proxy, "bind_route") as bind:
            self.assertEqual(proxy.handle(b"query", {}), b"response")
            bind.assert_not_called()

    def test_coordination_and_log_permissions(self):
        china = (ROOT / "china-route.sh").read_text()
        guard = (ROOT / "network-split-guard.sh").read_text()
        self.assertNotIn('/tmp/china-route', china + guard)
        self.assertIn('zsystem flock -t 0 -f lock_fd "$LOCK_FILE"', china)
        for script in (china, guard):
            self.assertIn('FORCE_REBUILD_FILE="/var/db/china-route-force-rebuild"', script)
        installer = (ROOT / "install-network-split-dns-event-route-agent.sh").read_text()
        self.assertIn('/bin/chmod 660 "$DNS_LOG"', installer)
        self.assertNotIn('/bin/chmod 644 "$DNS_LOG"', installer)


if __name__ == "__main__":
    unittest.main()
