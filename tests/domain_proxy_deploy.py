"""Activation rollback checks without changing system services or files."""
import importlib.util
import hashlib
from contextlib import nullcontext
from pathlib import Path
import plistlib
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("deploy", ROOT / "scripts" / "deploy-domain-proxy.py")
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


class DeploymentTests(unittest.TestCase):
    def test_atomic_install_cleans_staging_on_success_and_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / "source", root / "target"
            source.write_bytes(b"new")
            target.write_bytes(b"old")
            with patch.object(deploy.os, "fchown"):
                with patch.object(deploy.os, "replace", side_effect=OSError("simulated rename")):
                    with self.assertRaisesRegex(OSError, "simulated"):
                        deploy.install_file(source, target, 0o600)
                self.assertEqual(target.read_bytes(), b"old")
                self.assertEqual(sorted(p.name for p in root.iterdir()), ["source", "target"])
                deploy.install_file(source, target, 0o600)
            self.assertEqual(target.read_bytes(), b"new")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(sorted(p.name for p in root.iterdir()), ["source", "target"])

    def test_deployment_lock_excludes_overlap_and_releases_after_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deploy.lock"
            with patch.object(deploy, "DEPLOY_LOCK", path):
                with self.assertRaisesRegex(ValueError, "simulated"):
                    with deploy.deployment_lock():
                        with self.assertRaisesRegex(RuntimeError, "Another"):
                            with deploy.deployment_lock():
                                self.fail("overlapping deployment admitted")
                        raise ValueError("simulated failure")
                with deploy.deployment_lock():
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_deployment_lock_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private"
            target.write_text("unchanged")
            link = Path(directory) / "lock"
            link.symlink_to(target)
            with patch.object(deploy, "DEPLOY_LOCK", link):
                with self.assertRaises(OSError):
                    with deploy.deployment_lock():
                        self.fail("symlink accepted")
            self.assertEqual(target.read_text(), "unchanged")

    def test_stop_waits_for_writer_exit(self):
        with patch.object(deploy, "run", side_effect=["pid = 123\n", ""]) as run, \
                patch.object(deploy.os, "kill", side_effect=[None, ProcessLookupError]) as kill, \
                patch.object(deploy.time, "sleep"):
            deploy.stop_service()
            self.assertEqual(kill.call_count, 2)
            self.assertEqual(run.call_args.args, ("/bin/launchctl", "bootout", deploy.LABEL))

    def test_candidate_stop_does_not_ignore_unknown_launchd_error(self):
        for code in (5, 113):
            with self.subTest(code=code), patch.object(deploy, "run", side_effect=
                    deploy.subprocess.CalledProcessError(code, ["launchctl"])):
                if code == 113:
                    deploy.stop_candidate()
                else:
                    with self.assertRaises(deploy.subprocess.CalledProcessError):
                        deploy.stop_candidate()

    def test_backup_restores_rules_and_removes_only_new_known_seeds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup, rules = root / "backup", root / "rules"
            (backup / "rules").mkdir(parents=True)
            rules.mkdir()
            (backup / "config.json").write_text("old config")
            (backup / "cache.db").write_text("old cache")
            (backup / "rules" / (deploy.RULE_NAMES[0] + ".srs")).write_text("old rule")
            for name in deploy.RULE_NAMES:
                (rules / (name + ".srs")).write_text("new rule")
            (rules / "unrelated").write_text("keep")
            with patch.object(deploy, "CONFIG", root / "active.json"), \
                    patch.object(deploy, "CACHE", root / "active.db"), \
                    patch.object(deploy, "RULES", rules), \
                    patch.object(deploy.shutil, "chown"), \
                    patch.object(deploy, "install_file", side_effect=lambda s, d, m: shutil.copyfile(s, d)):
                deploy.restore_automatic_backup(backup)
            self.assertEqual((root / "active.json").read_text(), "old config")
            self.assertEqual((root / "active.db").read_text(), "old cache")
            self.assertEqual((rules / (deploy.RULE_NAMES[0] + ".srs")).read_text(), "old rule")
            self.assertEqual((rules / "unrelated").read_text(), "keep")
            self.assertEqual(len(list(rules.iterdir())), 2)

    def test_stop_timeout_is_bounded_and_never_kills_arbitrary_process(self):
        with patch.object(deploy, "run", side_effect=["pid = 123\n", ""]), \
                patch.object(deploy.time, "monotonic", side_effect=[0, 16]), \
                patch.object(deploy.os, "kill") as kill:
            with self.assertRaisesRegex(RuntimeError, "still exiting"):
                deploy.stop_service()
            kill.assert_not_called()

    def test_launchd_unload_race_is_retried(self):
        error = deploy.subprocess.CalledProcessError(5, ["launchctl", "bootstrap"])
        with patch.object(deploy, "run", side_effect=[error, "started"]) as command, \
                patch.object(deploy.time, "sleep"):
            self.assertEqual(deploy.start_service(), "started")
            self.assertEqual(command.call_count, 2)

    def exercise(self, fail, existing_cache=False, failed_stop=False, failed_preflight=False, failed_cache_copy=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "active.json"
            config.write_text("old")
            (root / "config.json").write_text("new")
            backup = root / "backup"
            backup.mkdir()
            warmed = root / "warmed-cache.db"
            warmed.write_bytes(b"fixture")
            cache = root / "runtime-cache.db"
            if existing_cache:
                cache.write_bytes(b"old cache")
            original_copy = shutil.copy2

            def copy(source, target):
                if source == cache and failed_cache_copy:
                    raise OSError("simulated cache backup failure")
                return original_copy(source, target)

            def run(*args):
                if fail and args[0] == "/usr/bin/curl":
                    raise RuntimeError("simulated activation probe failure")
                return ""

            with patch.object(deploy, "CONFIG", config), \
                    patch.object(deploy, "CACHE", cache), \
                    patch.object(deploy, "RULES", root / "absent-rules"), \
                    patch.object(deploy, "prepare_automatic_data"), \
                    patch.object(deploy, "warm_rule_cache", return_value=warmed,
                                 side_effect=RuntimeError("simulated preflight") if failed_preflight else None), \
                    patch.object(deploy, "stop_service", side_effect=RuntimeError("simulated stop") if failed_stop else None) as stop, \
                    patch.object(deploy, "stop_candidate") as stop_candidate, \
                    patch.object(deploy.tempfile, "TemporaryDirectory", return_value=nullcontext(str(root))), \
                    patch.object(deploy.tempfile, "mkdtemp", return_value=str(backup)), \
                    patch.object(deploy.shutil, "chown"), \
                    patch.object(deploy.shutil, "copy2", side_effect=copy), \
                    patch.object(deploy.subprocess, "run"), \
                    patch.object(deploy.time, "sleep"), \
                    patch.object(deploy, "install_file", side_effect=lambda src, dst, mode: shutil.copyfile(src, dst)), \
                    patch.object(deploy, "run", side_effect=run) as commands:
                if fail or failed_stop or failed_preflight or failed_cache_copy:
                    with self.assertRaisesRegex((RuntimeError, OSError), "simulated"):
                        deploy.update_automatic(root)
                else:
                    deploy.update_automatic(root)
                unchanged = fail or failed_stop or failed_preflight or failed_cache_copy
                self.assertEqual(config.read_text(), "old" if unchanged else "new")
                if failed_preflight:
                    stop.assert_not_called()
                    self.assertFalse((backup / "config.json").exists())
                    return
                if failed_stop:
                    self.assertFalse(backup.exists())
                    return
                if failed_cache_copy:
                    self.assertFalse(backup.exists())
                else:
                    self.assertEqual((backup / "config.json").read_text(), "old")
                if unchanged:
                    if existing_cache:
                        self.assertEqual(cache.read_bytes(), b"old cache")
                    else:
                        self.assertFalse(cache.exists())
                else:
                    self.assertEqual(cache.read_bytes(), b"fixture")
                self.assertFalse(any(c.args[0] == "/usr/sbin/networksetup" for c in commands.call_args_list))
                restarts = [c for c in commands.call_args_list if "bootstrap" in c.args]
                self.assertEqual(len(restarts), 2 if fail and not failed_cache_copy else 1)
                self.assertEqual(stop_candidate.call_count, 1 if fail and not failed_cache_copy else 0)

    def test_failed_activation_restores_previous_config(self):
        self.exercise(True)

    def test_success_preserves_backup_and_system_proxy_settings(self):
        self.exercise(False)

    def test_failed_activation_restores_old_cache_not_new_rule_decisions(self):
        self.exercise(True, existing_cache=True)

    def test_stop_failure_never_overwrites_live_files(self):
        self.exercise(False, existing_cache=True, failed_stop=True)

    def test_preflight_failure_leaves_no_backup_or_restart(self):
        self.exercise(False, existing_cache=True, failed_preflight=True)

    def test_cache_backup_failure_keeps_old_cache_and_restarts_old_service(self):
        self.exercise(False, existing_cache=True, failed_cache_copy=True)


class NativeDeploymentTests(unittest.TestCase):
    def exercise(self, failure=None, existing_cache=True):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary, plist, config, cache, runner = (root / name for name in
                                                    ("active-binary", "active.plist", "active.json", "cache.db", "runner.py"))
            binary.write_bytes(b"old binary")
            plist.write_bytes(b"old plist")
            config.write_text("unchanged config")
            runner.write_bytes(b"old runner")
            if existing_cache:
                cache.write_bytes(b"old cache")
            (root / "network-domain-engine").write_bytes(b"native binary")
            definition = {"Label": deploy.LABEL.removeprefix("system/"), "UserName": "nobody", "KeepAlive": True,
                          "ProgramArguments": [str(binary), "run", "--disable-color", "--log-file",
                                               "/var/log/network-domain-proxy/service.log", "--log-max-size", "2097152",
                                               "--log-max-backups", "3", "-c", str(config)]}
            (root / "com.local.network-domain-proxy.plist").write_bytes(plistlib.dumps(definition))
            events = []
            make_temporary = tempfile.mkdtemp

            def preflight(candidate):
                events.append("preflight")
                if failure == "preflight":
                    raise RuntimeError("simulated preflight failure")

            def stop():
                events.append("stop")
                if failure == "stop":
                    raise RuntimeError("simulated stop failure")

            def install(source, target, mode):
                if failure == "rollback" and Path(source).name == "binary":
                    raise RuntimeError("simulated rollback failure")
                shutil.copyfile(source, target)

            def command(*args):
                if args[0] == "/usr/bin/curl" and failure in ("activation", "rollback"):
                    cache.write_bytes(b"candidate cache")
                    raise RuntimeError("simulated activation failure")
                return f"program = {binary}\nstate = running\n"

            with patch.object(deploy, "BINARY", str(binary)), patch.object(deploy, "PLIST", str(plist)), \
                    patch.object(deploy, "CONFIG", config), patch.object(deploy, "CACHE", cache), \
                    patch.object(deploy, "LEGACY_RUNNER", runner), \
                    patch.object(deploy, "LEGACY_RUNNER_SHA256", hashlib.sha256(b"old runner").hexdigest()), \
                    patch.object(deploy, "preflight_native", side_effect=preflight), \
                    patch.object(deploy, "stop_service", side_effect=stop), \
                    patch.object(deploy, "stop_candidate") as stop_candidate, \
                    patch.object(deploy, "start_service") as start, \
                    patch.object(deploy, "run", side_effect=command) as run, \
                    patch.object(deploy, "install_file", side_effect=install), \
                    patch.object(deploy.shutil, "chown"), patch.object(deploy.time, "sleep"), \
                    patch.object(deploy.tempfile, "mkdtemp", side_effect=lambda **kw: make_temporary(dir=root)):
                if failure:
                    with self.assertRaisesRegex(RuntimeError, "simulated"):
                        deploy.upgrade_native(root)
                else:
                    backup = deploy.upgrade_native(root)
                    self.assertEqual((backup / "binary").read_bytes(), b"old binary")
                    self.assertEqual(binary.read_bytes(), b"native binary")
                    self.assertFalse(runner.exists())
                self.assertEqual(config.read_text(), "unchanged config")
                self.assertFalse(any(c.args[0] == "/usr/sbin/networksetup" for c in run.call_args_list))
                backups = [path for path in root.iterdir() if path.is_dir()]
                if failure != "rollback":
                    self.assertEqual(len(backups), 0 if failure else 1)
                    if failure:
                        self.assertEqual(binary.read_bytes(), b"old binary")
                        self.assertEqual(plist.read_bytes(), b"old plist")
                        self.assertEqual(runner.read_bytes(), b"old runner")
                    if existing_cache:
                        self.assertEqual(cache.read_bytes(), b"old cache")
                    else:
                        self.assertFalse(cache.exists())
                else:
                    self.assertEqual(len(backups), 1)
                self.assertEqual(events, ["preflight"] if failure == "preflight" else ["preflight", "stop"])
                self.assertEqual(start.call_count, 0 if failure in ("stop", "preflight") else
                                 1 if not failure or failure == "rollback" else 2)
                self.assertEqual(stop_candidate.call_count, 1 if failure in ("activation", "rollback") else 0)

    def test_native_activation_removes_only_reviewed_runner(self):
        self.exercise()

    def test_native_activation_failure_restores_binary_service_runner_and_cache(self):
        self.exercise("activation")

    def test_native_rollback_removes_only_new_cache_when_previously_absent(self):
        self.exercise("activation", existing_cache=False)

    def test_native_preflight_failure_leaves_live_files_untouched(self):
        self.exercise("preflight")

    def test_native_stop_failure_does_not_publish_candidate(self):
        self.exercise("stop")

    def test_native_rollback_failure_retains_recovery_backup(self):
        self.exercise("rollback")

if __name__ == "__main__":
    unittest.main()
