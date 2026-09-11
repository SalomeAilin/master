"""Activation rollback checks without changing system services or files."""
import importlib.util
from contextlib import nullcontext
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("deploy", ROOT / "deploy-domain-proxy.py")
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


class DeploymentTests(unittest.TestCase):
    def test_launchd_unload_race_is_retried(self):
        error = deploy.subprocess.CalledProcessError(5, ["launchctl", "bootstrap"])
        with patch.object(deploy, "run", side_effect=[error, "started"]) as command, \
                patch.object(deploy.time, "sleep"):
            self.assertEqual(deploy.start_service(), "started")
            self.assertEqual(command.call_count, 2)

    def exercise(self, fail):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "active.json"
            config.write_text("old")
            (root / "config.json").write_text("new")
            backup = root / "backup"
            backup.mkdir()
            warmed = root / "warmed-cache.db"
            warmed.write_bytes(b"fixture")

            def run(*args):
                if fail and args[0] == "/usr/bin/curl":
                    raise RuntimeError("simulated activation probe failure")
                return ""

            with patch.object(deploy, "CONFIG", config), \
                    patch.object(deploy, "CACHE", root / "runtime-cache.db"), \
                    patch.object(deploy, "RULES", root / "absent-rules"), \
                    patch.object(deploy, "prepare_automatic_data"), \
                    patch.object(deploy, "warm_rule_cache", return_value=warmed), \
                    patch.object(deploy.tempfile, "TemporaryDirectory", return_value=nullcontext(str(root))), \
                    patch.object(deploy.tempfile, "mkdtemp", return_value=str(backup)), \
                    patch.object(deploy.shutil, "chown"), \
                    patch.object(deploy.subprocess, "run"), \
                    patch.object(deploy.time, "sleep"), \
                    patch.object(deploy, "install_file", side_effect=lambda src, dst, mode: shutil.copyfile(src, dst)), \
                    patch.object(deploy, "run", side_effect=run) as commands:
                if fail:
                    with self.assertRaisesRegex(RuntimeError, "simulated"):
                        deploy.update_automatic(root)
                else:
                    deploy.update_automatic(root)
                self.assertEqual(config.read_text(), "old" if fail else "new")
                self.assertEqual((backup / "config.json").read_text(), "old")
                self.assertFalse(any(c.args[0] == "/usr/sbin/networksetup" for c in commands.call_args_list))
                restarts = [c for c in commands.call_args_list if "bootstrap" in c.args]
                self.assertEqual(len(restarts), 2 if fail else 1)

    def test_failed_activation_restores_previous_config(self):
        self.exercise(True)

    def test_success_preserves_backup_and_system_proxy_settings(self):
        self.exercise(False)


if __name__ == "__main__":
    unittest.main()
