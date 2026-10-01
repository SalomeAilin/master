"""Activation rollback checks without changing system services or files."""
import importlib.util
import hashlib
from contextlib import ExitStack
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

    def test_stop_timeout_is_bounded_and_never_kills_arbitrary_process(self):
        with patch.object(deploy, "run", side_effect=["pid = 123\n", ""]), \
                patch.object(deploy.time, "monotonic", side_effect=[0, 16]), \
                patch.object(deploy.os, "kill") as kill, \
                patch.object(deploy, "start_service") as restart:
            with self.assertRaisesRegex(RuntimeError, "still exiting"):
                deploy.stop_service()
            kill.assert_not_called()
            restart.assert_called_once_with()

    def test_bootout_failure_does_not_duplicate_service(self):
        error = deploy.subprocess.CalledProcessError(5, ["launchctl", "bootout"])
        with patch.object(deploy, "run", side_effect=["pid = 123\n", error]), \
                patch.object(deploy, "start_service") as restart:
            with self.assertRaises(deploy.subprocess.CalledProcessError):
                deploy.stop_service()
            restart.assert_not_called()

    def test_stop_timeout_reports_registration_recovery_failure(self):
        with patch.object(deploy, "run", side_effect=["pid = 123\n", ""]), \
                patch.object(deploy.time, "monotonic", side_effect=[0, 16]), \
                patch.object(deploy, "start_service", side_effect=RuntimeError("bootstrap failure")):
            with self.assertRaisesRegex(RuntimeError, "registration recovery failed"):
                deploy.stop_service()

    def test_launchd_unload_race_is_retried(self):
        error = deploy.subprocess.CalledProcessError(5, ["launchctl", "bootstrap"])
        with patch.object(deploy, "run", side_effect=[error, "started"]) as command, \
                patch.object(deploy.time, "sleep"):
            self.assertEqual(deploy.start_service(), "started")
            self.assertEqual(command.call_count, 2)


class IndependentDeploymentTests(unittest.TestCase):
    def exercise(self, failure=None, already_independent=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary, legacy, plist, config, installer = (root / name for name in
                ("active-binary", "legacy-binary", "active.plist", "active.json", "active-installer.py"))
            rules, cache, logs = (root / name for name in ("rules", "cache", "logs"))
            for directory in (rules, cache, logs):
                directory.mkdir(mode=0o700)
            legacy.write_bytes(b"legacy binary")
            if already_independent:
                binary.write_bytes(b"old independent binary")
            plist.write_bytes(b"old plist")
            config.write_text("old config")
            installer.write_bytes(b"old installer")
            for name in deploy.RULE_NAMES:
                (rules / (name + ".json")).write_bytes(b"old seed")
                (cache / (name + ".json")).write_bytes(b"old cache")
                (root / (name + ".json")).write_bytes(b"new seed")
            for name, data in (("network-domain-engine", b"new binary"),
                               ("com.local.network-domain-proxy.plist", b"new plist"),
                               ("config.json", b"new config"), ("deploy-domain-proxy.py", b"new installer")):
                (root / name).write_bytes(data)
            old_program = binary if already_independent else legacy
            make_temporary = tempfile.mkdtemp
            original_snapshot = deploy.snapshot
            original_restore = deploy.restore_snapshot
            original_values = {str(p): p.read_bytes() for p in (plist, config, installer)}
            if already_independent:
                original_values[str(binary)] = binary.read_bytes()

            def preflight(*args):
                if failure == "preflight":
                    raise RuntimeError("simulated preflight failure")

            def command(*args):
                if args[0] == "/usr/bin/curl" and failure in ("activation", "rollback"):
                    (cache / "domestic.json").write_bytes(b"candidate cache")
                    raise RuntimeError("simulated activation failure")
                return f"program = {old_program if command.calls == 0 else binary}\nstate = running\n"
            command.calls = 0

            def run(*args):
                result = command(*args)
                command.calls += 1
                return result

            def snapshot(*args):
                if failure == "snapshot":
                    raise RuntimeError("simulated snapshot failure")
                return original_snapshot(*args)

            def restore(*args):
                if failure == "rollback":
                    raise RuntimeError("simulated rollback failure")
                return original_restore(*args)

            with ExitStack() as stack:
                for name, value in {"BINARY": binary, "LEGACY_BINARY": legacy, "PLIST": plist,
                                    "CONFIG": config, "DEPLOY": installer, "RULES": rules,
                                    "CACHE": cache, "LOGDIR": logs}.items():
                    stack.enter_context(patch.object(deploy, name, value))
                stack.enter_context(patch.object(deploy, "validate_stage", return_value={}))
                stack.enter_context(patch.object(deploy, "preflight", side_effect=preflight))
                stack.enter_context(patch.object(deploy, "snapshot", side_effect=snapshot))
                stack.enter_context(patch.object(deploy, "restore_snapshot", side_effect=restore))
                stack.enter_context(patch.object(deploy, "ensure_directory"))
                stack.enter_context(patch.object(deploy.os, "fchown"))
                stack.enter_context(patch.object(deploy.os, "chown"))
                stop = stack.enter_context(patch.object(deploy, "stop_service",
                    side_effect=RuntimeError("simulated stop failure") if failure == "stop" else None))
                stop_candidate = stack.enter_context(patch.object(deploy, "stop_candidate"))
                start = stack.enter_context(patch.object(deploy, "start_service"))
                commands = stack.enter_context(patch.object(deploy, "run", side_effect=run))
                stack.enter_context(patch.object(deploy.tempfile, "mkdtemp",
                    side_effect=lambda **kw: make_temporary(dir=root)))
                if failure:
                    with self.assertRaisesRegex(RuntimeError, "simulated"):
                        deploy.upgrade(root)
                else:
                    backup = deploy.upgrade(root)
                    self.assertTrue((backup / "manifest.json").exists())
                    self.assertEqual(binary.read_bytes(), b"new binary")
                    self.assertEqual(config.read_bytes(), b"new config")
                    self.assertEqual(installer.read_bytes(), b"new installer")
                self.assertEqual(legacy.read_bytes(), b"legacy binary")
                self.assertFalse(any(c.args[0] == "/usr/sbin/networksetup" for c in commands.call_args_list))
                backups = [p for p in root.iterdir() if p.is_dir() and p not in (rules, cache, logs)]
                self.assertEqual(len(backups), 1 if not failure or failure == "rollback" else 0)
                if failure and failure != "rollback":
                    for path, value in original_values.items():
                        self.assertEqual(Path(path).read_bytes(), value)
                    if not already_independent:
                        self.assertFalse(binary.exists())
                    for name in deploy.RULE_NAMES:
                        self.assertEqual((rules / (name + ".json")).read_bytes(), b"old seed")
                        self.assertEqual((cache / (name + ".json")).read_bytes(), b"old cache")
                self.assertEqual(start.call_count, 0 if failure in ("preflight", "stop") else
                                 2 if failure == "activation" else 1)
                self.assertEqual(stop.call_count, 0 if failure == "preflight" else 1)
                self.assertEqual(stop_candidate.call_count, 1 if failure in ("activation", "rollback") else 0)

    def test_migration_success_keeps_old_binary_until_socket_acceptance(self):
        self.exercise()

    def test_preflight_failure_does_not_stop_or_write(self):
        self.exercise("preflight")

    def test_stop_failure_does_not_replace_files(self):
        self.exercise("stop")

    def test_snapshot_failure_restarts_unchanged_service(self):
        self.exercise("snapshot")

    def test_activation_failure_restores_files_and_cache(self):
        self.exercise("activation")

    def test_independent_upgrade_rolls_back_existing_binary(self):
        self.exercise("activation", already_independent=True)

    def test_rollback_failure_retains_private_backup(self):
        self.exercise("rollback")

    def test_stage_rejects_wrong_interface_before_preflight(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "config.json").write_text('{"version":1,"listen":"0.0.0.0:17890"}')
            with self.assertRaisesRegex(RuntimeError, "configuration"):
                deploy.validate_stage(root, False)

    def test_snapshot_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original"
            original.write_bytes(b"unchanged")
            link = root / "link"
            link.symlink_to(original)
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                deploy.snapshot(root, [link])
            self.assertEqual(original.read_bytes(), b"unchanged")


if __name__ == "__main__":
    unittest.main()
