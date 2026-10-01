"""Offline regression tests; all route commands are mocked."""

import importlib.util
import ipaddress
import logging
import os
from pathlib import Path
import random
import sys
import tempfile
import unittest
from unittest.mock import mock_open, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import network_split_policy as policy


def module(filename):
    spec = importlib.util.spec_from_file_location(filename, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


event = module("network-split-dns-event-route-agent.py")


class IndexedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "policy.conf"
        self.path.write_text("", encoding="ascii")
        self.files = patch.object(policy, "POLICY_FILES", (str(self.path),))
        self.files.start()
        self.addCleanup(self.files.stop)
        policy._signature = None

    def test_overlaps_adjacency_duplicates_and_gaps(self):
        self.path.write_text("8.8.9.0/24\n8.8.8.0/25\n8.8.8.64/26\n"
                             "8.8.8.128/26\n8.8.10.0/24\n8.8.9.0/24\n")
        for ip in ("8.8.8.0", "8.8.8.127", "8.8.8.128", "8.8.8.191", "8.8.9.0", "8.8.10.255"):
            self.assertTrue(policy.allowed(ip), ip)
        for ip in ("8.8.7.255", "8.8.8.192", "8.8.8.255", "8.8.11.0"):
            self.assertFalse(policy.allowed(ip), ip)
        self.assertEqual(len(policy._starts), 2)

    def test_empty_policy_denies_everything(self):
        self.assertFalse(policy.allowed("8.8.8.8"))
        self.assertEqual(policy._starts, ())

    def test_catch_all_still_denies_special_addresses(self):
        self.path.write_text("0.0.0.0/0\n")
        self.assertTrue(policy.allowed("8.8.8.8"))
        for ip in ("0.0.0.0", "127.0.0.1", "10.0.0.1", "224.0.0.1", "255.255.255.255"):
            self.assertFalse(policy.allowed(ip), ip)

    def test_atomic_replacement_with_same_size_and_mtime_revokes_old_rules(self):
        self.path.write_text("8.8.8.8/32\n")
        self.assertTrue(policy.allowed("8.8.8.8"))
        before = self.path.stat()
        replacement = self.path.with_suffix(".new")
        replacement.write_text("1.1.1.1/32\n")
        os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
        replacement.replace(self.path)
        self.assertEqual(self.path.stat().st_size, before.st_size)
        self.assertEqual(self.path.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertFalse(policy.allowed("8.8.8.8"))
        self.assertTrue(policy.allowed("1.1.1.1"))

    def test_invalid_replacement_does_not_keep_partial_or_previous_index(self):
        self.path.write_text("8.8.8.8/32\n")
        self.assertTrue(policy.allowed("8.8.8.8"))
        self.path.write_text("1.1.1.1/32\ninvalid\n")
        for ip in ("8.8.8.8", "1.1.1.1"):
            self.assertFalse(policy.allowed(ip))
        self.assertEqual(policy._starts, ())
        self.path.write_text("1.1.1.1/32\n")
        self.assertTrue(policy.allowed("1.1.1.1"))
        self.path.unlink()
        self.assertFalse(policy.allowed("1.1.1.1"))

    def test_index_matches_linear_reference_at_all_generated_boundaries(self):
        rng = random.Random(20260926)
        networks = [ipaddress.IPv4Network((rng.getrandbits(32), rng.randrange(8, 33)), strict=False)
                    for _ in range(128)]
        self.path.write_text("\n".join(str(n) for n in networks) + "\n")
        values = {rng.getrandbits(32) for _ in range(512)}
        for network in networks:
            for value in (int(network.network_address), int(network.broadcast_address)):
                values.update(v for v in (value - 1, value, value + 1) if 0 <= v <= 0xffffffff)
        for value in sorted(values):
            address = ipaddress.IPv4Address(value)
            expected = address.is_global and not address.is_multicast and any(address in n for n in networks)
            self.assertEqual(policy.allowed(str(address)), expected, str(address))


class LogRotationTests(unittest.TestCase):
    def test_event_log_follows_new_file_after_external_rotation(self):
        root = logging.getLogger()
        previous_handlers, previous_level = root.handlers[:], root.level
        root.handlers = []
        try:
            with tempfile.TemporaryDirectory() as directory:
                current = Path(directory) / "event.log"
                archive = Path(directory) / "event.log.0"
                with patch.object(event, "LOG_FILE", str(current)):
                    event.setup_logging()
                    logging.info("before rotation")
                    current.rename(archive)
                    current.touch()
                    logging.info("after rotation")
                self.assertIn("before rotation", archive.read_text())
                self.assertNotIn("after rotation", archive.read_text())
                self.assertIn("after rotation", current.read_text())
        finally:
            for handler in root.handlers:
                handler.close()
            root.handlers, root.level = previous_handlers, previous_level


class QueryCorrelationTests(unittest.TestCase):
    def setUp(self):
        self.queries = {}
        self.now = 100
        self.clock = patch.object(event.time, "monotonic", side_effect=lambda: self.now)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.bind = patch.object(event, "bind_ethernet_route")
        self.sink = self.bind.start()
        self.addCleanup(self.bind.stop)

    def line(self, value, pid="1", query_id="7", client="client"):
        event.process_line(f"dnsmasq[{pid}]: {query_id} {client} {value}", {"cn"}, self.queries)

    def test_cname_chain_stays_with_its_query_not_shared_cdn(self):
        self.line("query[A] good.cn from client")
        self.line("reply good.cn is shared.example")
        self.line("reply shared.example is 223.5.5.5")
        self.sink.assert_called_once_with("good.cn", "223.5.5.5")
        self.sink.reset_mock()
        self.line("query[A] foreign.example from client", query_id="8")
        self.line("reply shared.example is 223.5.5.5", query_id="8")
        self.sink.assert_not_called()

    def test_reused_query_id_is_not_inherited_by_foreign_query(self):
        self.line("query[A] good.cn from client")
        self.line("query[A] foreign.example from client")
        self.line("reply shared.example is 223.5.5.5")
        self.sink.assert_not_called()
        self.assertEqual(self.queries, {})

    def test_pid_and_client_are_part_of_query_identity(self):
        self.line("query[A] good.cn from client")
        self.line("reply shared.example is 223.5.5.5", pid="2")
        self.line("reply shared.example is 223.5.5.5", client="other")
        self.sink.assert_not_called()

    def test_expired_query_cannot_classify_a_late_cname_answer(self):
        self.line("query[A] good.cn from client")
        self.now += event.QUERY_TTL_SECONDS
        self.line("reply shared.example is 223.5.5.5")
        self.sink.assert_not_called()
        self.assertEqual(self.queries, {})

    def test_cache_is_bounded_and_updated_queries_expire_in_order(self):
        with patch.object(event, "MAX_PENDING_QUERIES", 2):
            for query_id in ("1", "2", "1", "3"):
                self.line("query[A] good.cn from client", query_id=query_id)
                self.now += 1
            self.assertEqual(list(self.queries), [("1", "1", "client"), ("1", "3", "client")])
            self.now = 132
            self.line("reply shared.example is 223.5.5.5", query_id="1")
            self.sink.assert_not_called()
            self.assertEqual(len(self.queries), 1)


class SecurityTests(unittest.TestCase):
    def setUp(self):
        policy.POLICY_FILES = tuple(str(ROOT / "config" / name) for name in (
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
            queries = {}
            event.process_line("dnsmasq[1]: 7 client query[A] evil.cn from client", {"cn"}, queries)
            for line in ("dnsmasq[1]: 7 client reply evil.cn is 8.8.8.8",
                         "dnsmasq[1]: 7 client reply alias.example is 1.1.1.1"):
                event.process_line(line, {"cn"}, queries)
            run.assert_not_called()

    def test_event_sink_enforces_policy_before_route_lookup(self):
        for ip in ("8.8.8.8", "127.0.0.1", "999.1.1.1"):
            with self.subTest(ip=ip), patch.object(event, "route_is_ethernet") as lookup, patch.object(event.subprocess, "run") as run:
                event.bind_ethernet_route("evil.cn", ip)
                lookup.assert_not_called()
                run.assert_not_called()

    def test_legitimate_bind_still_uses_ifp(self):
        with patch.object(event, "route_is_ethernet", side_effect=[False, True]), patch.object(event.subprocess, "run") as run:
            run.return_value.returncode = 0
            event.bind_ethernet_route("good.cn", "223.5.5.5")
            self.assertIn(["/sbin/route", "-n", "add", "-host", "223.5.5.5", "192.168.1.1", "-ifp", "en0"], [c.args[0] for c in run.call_args_list])

    def test_denied_answer_does_not_block_later_domestic_answer(self):
        with patch.object(event, "route_is_ethernet", return_value=True) as lookup, patch.object(event.subprocess, "run") as run:
            queries = {}
            event.process_line("dnsmasq[1]: 7 client query[A] good.cn from client", {"cn"}, queries)
            event.process_line("dnsmasq[1]: 7 client reply good.cn is 8.8.8.8", {"cn"}, queries)
            lookup.assert_not_called()
            run.assert_not_called()
            self.assertEqual(queries[("1", "7", "client")][0], "good.cn")
            event.process_line("dnsmasq[1]: 7 client reply good.cn is 223.5.5.5", {"cn"}, queries)
            lookup.assert_called_once_with("223.5.5.5")
            run.assert_not_called()

    def test_coordination_and_log_permissions(self):
        china = (ROOT / "scripts" / "china-route.sh").read_text()
        guard = (ROOT / "scripts" / "network-split-guard.sh").read_text()
        self.assertNotIn('/tmp/china-route', china + guard)
        self.assertIn('zsystem flock -t 0 -f lock_fd "$LOCK_FILE"', china)
        for script in (china, guard):
            self.assertIn('FORCE_REBUILD_FILE="/var/db/china-route-force-rebuild"', script)
        installer = (ROOT / "scripts" / "install-network-split-dns-event-route-agent.sh").read_text()
        self.assertIn('/bin/chmod 660 "$DNS_LOG"', installer)
        self.assertNotIn('/bin/chmod 644 "$DNS_LOG"', installer)


if __name__ == "__main__":
    unittest.main()
