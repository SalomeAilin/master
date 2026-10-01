#!/usr/bin/env python3
"""Install separately from activation; restore the exact prior proxy settings."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import socket
import stat
import subprocess
import tempfile
import time

STATE = Path("/var/db/network-domain-proxy.previous.json")
LABEL = "system/com.local.network-domain-proxy"
PLIST = "/Library/LaunchDaemons/com.local.network-domain-proxy.plist"
SERVICES = ("Wi-Fi", "Ethernet")
KINDS = ("webproxy", "securewebproxy")
CONFIG = Path("/usr/local/etc/network-domain-proxy.json")
CACHE = Path("/var/db/network-domain-proxy/cache.db")
RULES = Path("/usr/local/etc/network-domain-rules")
BINARY = "/usr/local/libexec/network-domain-sing-box"
LEGACY_RUNNER = Path("/usr/local/sbin/network-domain-proxy-run.py")
LEGACY_RUNNER_SHA256 = "a7d519955bb8594ef1f91f9b1eb017faeffd76477d2053319c4d49539e95c1de"
DEPLOY_LOCK = Path("/var/db/network-domain-proxy.deploy.lock")
RULE_NAMES = ("geosite-geolocation-cn", "geosite-geolocation-!cn", "geoip-cn")


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=30)


@contextmanager
def deployment_lock():
    fd = os.open(DEPLOY_LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "rb") as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise RuntimeError("Unsafe deployment lock")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another proxy deployment is active") from None
        yield


def start_service():
    # launchd can still be removing a booted-out job when bootstrap first runs.
    for attempt in range(10):
        try:
            return run("/bin/launchctl", "bootstrap", "system", PLIST)
        except subprocess.CalledProcessError as error:
            if error.returncode != 5 or attempt == 9:
                raise
            time.sleep(0.5)


def stop_service():
    details = run("/bin/launchctl", "print", LABEL)
    pid = next((int(line.split("=", 1)[1]) for line in details.splitlines()
                if line.strip().startswith("pid = ")), None)
    run("/bin/launchctl", "bootout", LABEL)
    if pid is not None:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.1)
        raise RuntimeError("Service is still exiting; refusing to replace live files")


def stop_candidate():
    try:
        run("/bin/launchctl", "print", LABEL)
    except subprocess.CalledProcessError as error:
        if error.returncode == 113:
            return
        raise
    stop_service()


def settings():
    saved = {}
    for service in SERVICES:
        saved[service] = {}
        for kind in KINDS:
            raw = run("/usr/sbin/networksetup", "-get" + kind, service)
            values = dict(line.split(": ", 1) for line in raw.splitlines() if ": " in line)
            if values.get("Authenticated Proxy Enabled") != "0":
                raise RuntimeError("Authenticated proxy present; refusing to overwrite")
            saved[service][kind] = values
    return saved


def restore(saved):
    for service, kinds in saved.items():
        for kind, values in kinds.items():
            if values["Server"] and int(values["Port"]) > 0:
                run("/usr/sbin/networksetup", "-set" + kind, service, values["Server"], values["Port"])
            enabled = "on" if values["Enabled"] == "Yes" else "off"
            run("/usr/sbin/networksetup", "-set" + kind + "state", service, enabled)


def install_file(source, target, mode):
    target = Path(target)
    fd, temporary = tempfile.mkstemp(prefix="." + target.name + ".", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as output, Path(source).open("rb") as data:
            shutil.copyfileobj(data, output)
            output.flush()
            os.fchmod(output.fileno(), mode)
            os.fchown(output.fileno(), 0, 0)
            os.fsync(output.fileno())
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)


def prepare_automatic_data(root):
    for name in RULE_NAMES:
        run(BINARY, "rule-set", "decompile", str(root / (name + ".srs")), "-o", "/dev/null")
    if RULES.exists():
        if RULES.is_symlink() or RULES.stat().st_uid != 0 or RULES.stat().st_mode & 0o022:
            raise RuntimeError("Unsafe rule seed directory")
    else:
        RULES.mkdir(mode=0o755)
        RULES.chmod(0o755)
    cache = Path("/var/db/network-domain-proxy")
    if cache.is_symlink():
        raise RuntimeError("Unsafe cache directory")
    if not cache.exists():
        cache.mkdir(mode=0o700)
        shutil.chown(cache, user="nobody", group="wheel")
    for name in RULE_NAMES:
        install_file(root / (name + ".srs"), RULES / (name + ".srs"), 0o644)


def warm_rule_cache(root, directory):
    config = json.loads((root / "config.json").read_text())
    config["experimental"]["cache_file"]["path"] = str(directory / "cache.db")
    # Synchronous initial downloads must complete before the candidate can listen.
    for rule_set in config["route"]["rule_set"]:
        rule_set.pop("initial_path", None)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        config["inbounds"][0]["listen_port"] = reservation.getsockname()[1]
    path = directory / "candidate.json"
    path.write_text(json.dumps(config))
    shutil.chown(path, user="nobody", group="wheel")
    for _ in range(3):
        with (directory / "candidate.log").open("w+") as output:
            process = subprocess.Popen([
                "/usr/bin/sudo", "-u", "nobody", BINARY, "run", "--disable-color", "-c", str(path),
            ], stdout=output, stderr=output)
            try:
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline and process.poll() is None:
                    output.seek(0)
                    if " started (" in output.read():
                        print("All automatic rule sets cached before activation", flush=True)
                        return directory / "cache.db"
                    time.sleep(0.1)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    raise RuntimeError("Rule cache preflight failed; live configuration was not changed")


def restore_automatic_backup(backup):
    install_file(backup / "config.json", CONFIG, 0o644)
    for name in RULE_NAMES:
        previous = backup / "rules" / (name + ".srs")
        if previous.exists():
            install_file(previous, RULES / previous.name, 0o644)
        else:
            (RULES / previous.name).unlink(missing_ok=True)
    if not (backup / "rules").exists() and RULES.exists():
        RULES.rmdir()
    if (backup / "cache.db").exists():
        install_file(backup / "cache.db", CACHE, 0o600)
        shutil.chown(CACHE, user="nobody", group="wheel")
    else:
        CACHE.unlink(missing_ok=True)


def update_automatic(root):
    run(BINARY, "check", "-c", str(root / "config.json"))
    if RULES.is_symlink() or (RULES.exists() and
            (RULES.stat().st_uid != 0 or RULES.stat().st_mode & 0o022)):
        raise RuntimeError("Unsafe rule seed directory")
    with tempfile.TemporaryDirectory(prefix="network-domain-preflight.", dir="/var/db") as temporary:
        directory = Path(temporary)
        shutil.chown(directory, user="nobody", group="wheel")
        warmed_cache = warm_rule_cache(root, directory)
        for name in RULE_NAMES:
            run(BINARY, "rule-set", "decompile", str(root / (name + ".srs")), "-o", "/dev/null")
        backup = Path(tempfile.mkdtemp(prefix="network-domain-auto-backup.", dir="/var/db"))
        try:
            shutil.copy2(CONFIG, backup / "config.json")
            if RULES.exists():
                shutil.copytree(RULES, backup / "rules")
        except BaseException:
            shutil.rmtree(backup)
            raise
        stopped = False
        files_changed = False
        try:
            stop_service()
            stopped = True
            # The engine owns the cache: snapshot it only after its writer stops.
            if CACHE.exists():
                shutil.copy2(CACHE, backup / "cache.db")
            files_changed = True
            prepare_automatic_data(root)
            install_file(root / "config.json", CONFIG, 0o644)
            install_file(warmed_cache, CACHE, 0o600)
            shutil.chown(CACHE, user="nobody", group="wheel")
            start_service()
            time.sleep(2)
            for url in ("https://www.douyin.com/", "https://github.com/"):
                run("/usr/bin/curl", "--proxy", "http://127.0.0.1:17890", "--noproxy", "", "-fsS", "-o", "/dev/null", "--max-time", "15", url)
            run("/bin/launchctl", "print", LABEL)
        except BaseException:
            if stopped:
                try:
                    if files_changed:
                        # Never replace a cache that a running candidate can still write.
                        stop_candidate()
                        restore_automatic_backup(backup)
                    start_service()
                except BaseException:
                    print("Rollback incomplete; recovery backup retained:", backup, flush=True)
                    raise
                if files_changed:
                    print("Activation failed; previous proxy configuration and cache restored. Backup:", backup, flush=True)
                else:
                    shutil.rmtree(backup)
                    print("Backup failed; live files unchanged and previous service restarted", flush=True)
            else:
                shutil.rmtree(backup)
                print("Could not stop service; live files were not changed", flush=True)
            raise
    print("Automatic classification active; backup:", backup)


def preflight_native(binary):
    config = json.loads(CONFIG.read_text())
    if config.get("log", {}).get("output"):
        raise RuntimeError("Explicit log output would bypass native bounded logging")
    run(str(binary), "check", "-c", str(CONFIG))
    with tempfile.TemporaryDirectory(prefix="network-domain-native-preflight.", dir="/var/db") as temporary:
        directory = Path(temporary)
        shutil.chown(directory, user="nobody", group="wheel")
        config["experimental"]["cache_file"]["path"] = str(directory / "cache.db")
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        config["inbounds"][0]["listen_port"] = port
        path, log_path = directory / "config.json", directory / "service.log"
        path.write_text(json.dumps(config))
        shutil.chown(path, user="nobody", group="wheel")
        with (directory / "startup.log").open("wb") as output:
            process = subprocess.Popen([
                str(binary), "run", "--disable-color", "--log-file", str(log_path),
                "--log-max-size", "2097152", "--log-max-backups", "3", "-c", str(path),
            ], stdout=output, stderr=output, user="nobody", group="wheel", extra_groups=[],
                env={key: value for key, value in os.environ.items()
                     if key not in ("SUDO_USER", "SUDO_UID", "SUDO_GID")})
            try:
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline and process.poll() is None:
                    if log_path.exists() and " started (" in log_path.read_text():
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError("Native preflight did not start")
                for url in ("https://www.douyin.com/", "https://github.com/"):
                    run("/usr/bin/curl", "--proxy", f"http://127.0.0.1:{port}", "--noproxy", "",
                        "-fsS", "-o", "/dev/null", "--max-time", "15", url)
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def upgrade_native(root):
    binary, plist = root / "network-domain-engine", root / "com.local.network-domain-proxy.plist"
    arguments = [BINARY, "run", "--disable-color", "--log-file", "/var/log/network-domain-proxy/service.log",
                 "--log-max-size", "2097152", "--log-max-backups", "3", "-c", str(CONFIG)]
    candidate = plistlib.loads(plist.read_bytes())
    if (candidate.get("Label") != LABEL.removeprefix("system/") or candidate.get("UserName") != "nobody"
            or candidate.get("ProgramArguments") != arguments or not candidate.get("KeepAlive")):
        raise RuntimeError("Unexpected native service definition")
    if LEGACY_RUNNER.is_symlink() or (LEGACY_RUNNER.exists() and
            hashlib.sha256(LEGACY_RUNNER.read_bytes()).hexdigest() != LEGACY_RUNNER_SHA256):
        raise RuntimeError("Legacy runner differs from the reviewed version")
    preflight_native(binary)
    backup = Path(tempfile.mkdtemp(prefix="network-domain-native-backup.", dir="/var/db"))
    try:
        for source, name in ((Path(BINARY), "binary"), (Path(PLIST), "service.plist"), (CONFIG, "config.json")):
            shutil.copy2(source, backup / name)
        if LEGACY_RUNNER.exists():
            shutil.copy2(LEGACY_RUNNER, backup / "runner.py")
    except BaseException:
        shutil.rmtree(backup)
        raise
    stopped = False
    changed = False
    try:
        stop_service()
        stopped = True
        if CACHE.exists():
            shutil.copy2(CACHE, backup / "cache.db")
        changed = True
        install_file(binary, BINARY, 0o755)
        install_file(plist, PLIST, 0o644)
        start_service()
        time.sleep(1)
        for url in ("https://www.douyin.com/", "https://github.com/"):
            run("/usr/bin/curl", "--proxy", "http://127.0.0.1:17890", "--noproxy", "",
                "-fsS", "-o", "/dev/null", "--max-time", "15", url)
        details = run("/bin/launchctl", "print", LABEL)
        if f"program = {BINARY}" not in details or "state = running" not in details:
            raise RuntimeError("launchd is not running the native engine directly")
        LEGACY_RUNNER.unlink(missing_ok=True)
    except BaseException:
        if stopped:
            try:
                if changed:
                    stop_candidate()
                    install_file(backup / "binary", BINARY, 0o755)
                    install_file(backup / "service.plist", PLIST, 0o644)
                    install_file(backup / "config.json", CONFIG, 0o644)
                    if (backup / "runner.py").exists():
                        install_file(backup / "runner.py", LEGACY_RUNNER, 0o755)
                    if (backup / "cache.db").exists():
                        install_file(backup / "cache.db", CACHE, 0o600)
                        shutil.chown(CACHE, user="nobody", group="wheel")
                    else:
                        CACHE.unlink(missing_ok=True)
                start_service()
            except BaseException:
                print("Native rollback incomplete; recovery backup retained:", backup, flush=True)
                raise
        shutil.rmtree(backup)
        raise
    print("Native engine active; legacy runner removed. Acceptance backup:", backup, flush=True)
    return backup


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("install", "enable", "rollback", "update-auto", "upgrade-native"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Administrator authorization required")
    os.umask(0o077)
    root = Path(__file__).resolve().parent
    with deployment_lock():
        apply_action(args.action, root)


def apply_action(action, root):
    if action == "upgrade-native":
        upgrade_native(root)
    elif action == "update-auto":
        update_automatic(root)
    elif action == "install":
        if Path(PLIST).exists():
            raise RuntimeError("Service already installed; refusing implicit replacement")
        binary = root / "network-domain-engine"
        run(str(binary), "check", "-c", str(root / "config.json"))
        libexec = Path("/usr/local/libexec")
        if not libexec.exists():
            libexec.mkdir(mode=0o755)
            libexec.chmod(0o755)
        install_file(binary, "/usr/local/libexec/network-domain-sing-box", 0o755)
        prepare_automatic_data(root)
        with tempfile.TemporaryDirectory(prefix="network-domain-preflight.", dir="/var/db") as temporary:
            directory = Path(temporary)
            shutil.chown(directory, user="nobody", group="wheel")
            install_file(warm_rule_cache(root, directory), CACHE, 0o600)
            shutil.chown(CACHE, user="nobody", group="wheel")
        install_file(root / "config.json", "/usr/local/etc/network-domain-proxy.json", 0o644)
        install_file(root / "com.local.network-domain-proxy.plist", PLIST, 0o644)
        logdir = Path("/var/log/network-domain-proxy")
        logdir.mkdir(mode=0o700)
        shutil.chown(logdir, user="nobody", group="wheel")
        start_service()
        print("Service installed; system proxy settings unchanged")
    elif action == "enable":
        run("/bin/launchctl", "print", LABEL)
        for url in ("https://www.douyin.com/", "https://github.com/"):
            run("/usr/bin/curl", "--proxy", "http://127.0.0.1:17890", "--noproxy", "", "-f", "-sS", "-o", "/dev/null", "--max-time", "15", url)
        saved = settings()
        with STATE.open("x") as output:
            json.dump(saved, output, indent=2)
        try:
            for service in SERVICES:
                for kind in KINDS:
                    run("/usr/sbin/networksetup", "-set" + kind, service, "127.0.0.1", "17890")
                    run("/usr/sbin/networksetup", "-set" + kind + "state", service, "on")
            print(json.dumps(settings(), indent=2))
        except BaseException:
            restore(saved)
            raise
    else:
        restore(json.loads(STATE.read_text()))
        print("Prior HTTP/HTTPS proxy settings restored; bypass lists untouched")


if __name__ == "__main__":
    main()
