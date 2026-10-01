#!/usr/bin/env python3
"""Transactional installation of the independent, interface-bound proxy."""
import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import plistlib
import pwd
import shutil
import socket
import stat
import subprocess
import tempfile
import time

STATE = Path("/var/db/network-domain-proxy.previous.json")
LABEL = "system/com.local.network-domain-proxy"
PLIST = Path("/Library/LaunchDaemons/com.local.network-domain-proxy.plist")
SERVICES = ("Wi-Fi", "Ethernet")
KINDS = ("webproxy", "securewebproxy")
CONFIG = Path("/usr/local/etc/network-domain-proxy.json")
BINARY = Path("/usr/local/libexec/network-domain-engine")
LEGACY_BINARY = Path("/usr/local/libexec/network-domain-sing-box")
DEPLOY = Path("/usr/local/sbin/network-domain-proxy-deploy.py")
RULES = Path("/usr/local/etc/network-domain-rules-independent")
CACHE = Path("/var/db/network-domain-proxy/independent-cache")
LOGDIR = Path("/var/log/network-domain-proxy")
RULE_NAMES = ("domestic", "foreign", "china")
DEPLOY_LOCK = Path("/var/db/network-domain-proxy.deploy.lock")


def run(*args):
    return subprocess.check_output(tuple(map(str, args)), text=True, stderr=subprocess.STDOUT, timeout=30)


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
    try:
        if pid is not None:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    return
                time.sleep(0.1)
            raise RuntimeError("Service is still exiting; live files were not replaced")
    except BaseException:
        # bootout already removed the job; retain its unchanged registration.
        try:
            start_service()
        except BaseException as recovery_error:
            raise RuntimeError("Service stop failed and registration recovery failed; "
                               "live files remain unchanged") from recovery_error
        raise


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
            run("/usr/sbin/networksetup", "-set" + kind + "state", service,
                "on" if values["Enabled"] == "Yes" else "off")


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


def arguments():
    return [str(BINARY), "run", "--disable-color", "--log-file", str(LOGDIR / "service.log"),
            "--log-max-size", "2097152", "--log-max-backups", "3", "-c", str(CONFIG)]


def validate_stage(root, migrating):
    config = json.loads((root / "config.json").read_text())
    if (config.get("version") != 1 or config.get("listen") != "127.0.0.1:17890"
            or config.get("cache_directory") != str(CACHE)
            or config.get("domestic", {}).get("interface") != "en0"
            or config.get("foreign", {}).get("interface") != "en1"):
        raise RuntimeError("Unexpected independent production configuration")
    sources = config.get("rule_sources", [])
    if ({s.get("kind") for s in sources} != set(RULE_NAMES) or len(sources) != 3 or
            any(s.get("seed") != str(RULES / (s["kind"] + ".json")) or
                s.get("interval") != "1h" or not s.get("url", "").startswith("https://")
                for s in sources)):
        raise RuntimeError("Unexpected independent rule source")
    candidate = plistlib.loads((root / "com.local.network-domain-proxy.plist").read_bytes())
    if (candidate.get("Label") != LABEL.removeprefix("system/") or
            candidate.get("UserName") != "nobody" or candidate.get("ProgramArguments") != arguments()
            or candidate.get("KeepAlive") is not True or candidate.get("RunAtLoad") is not True):
        raise RuntimeError("Unexpected independent service definition")
    if PLIST.exists():
        previous = plistlib.loads(PLIST.read_bytes())
        previous.pop("ProgramArguments", None)
        unchanged = candidate.copy()
        unchanged.pop("ProgramArguments", None)
        if previous != unchanged:
            raise RuntimeError("Service settings other than engine arguments would change")
    if migrating:
        previous = json.loads(CONFIG.read_text())
        policies = previous["route"]["rules"]
        local = {key: policies[1][key] for key in ("domain", "domain_suffix")}
        protected = {"domain_suffix": policies[0]["domain_suffix"]}
        if (config["local_domestic"] != local or config["protected_foreign"] != protected
                or set(config["china_cidr"]) != set(policies[-1]["ip_cidr"])):
            raise RuntimeError("Migration would change local routing policy")
    return config


def preflight(binary, config, root):
    with tempfile.TemporaryDirectory(prefix="network-domain-independent-preflight.", dir="/var/db") as temporary:
        directory = Path(temporary)
        shutil.chown(directory, user="nobody", group="wheel")
        candidate = json.loads(json.dumps(config))
        candidate["cache_directory"] = str(directory / "cache")
        for source in candidate["rule_sources"]:
            source["seed"] = str(root / (source["kind"] + ".json"))
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        candidate["listen"] = f"127.0.0.1:{port}"
        path, log_path = directory / "config.json", directory / "service.log"
        path.write_text(json.dumps(candidate))
        shutil.chown(path, user="nobody", group="wheel")
        run(binary, "check", "-c", path)
        with (directory / "startup.log").open("wb") as output:
            process = subprocess.Popen([
                str(binary), "run", "--log-file", str(log_path), "-c", str(path),
            ], stdout=output, stderr=output, user="nobody", group="wheel", extra_groups=[],
                env={key: value for key, value in os.environ.items()
                     if key not in ("SUDO_USER", "SUDO_UID", "SUDO_GID")})
            try:
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline and process.poll() is None:
                    if log_path.exists() and any(json.loads(line).get("event") == "started"
                                                 for line in log_path.read_text().splitlines()):
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError("Independent candidate did not start")
                health(port)
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def health(port=17890):
    for url in ("https://www.douyin.com/", "https://github.com/"):
        run("/usr/bin/curl", "--proxy", f"http://127.0.0.1:{port}", "--noproxy", "",
            "-fsS", "-o", "/dev/null", "--max-time", "15", url)


def snapshot(backup, targets):
    records = []
    for index, target in enumerate(targets):
        target = Path(target)
        record = {"target": str(target), "present": target.exists(), "copy": str(index)}
        if target.is_symlink():
            raise RuntimeError("Refusing to snapshot a symlink")
        if record["present"]:
            info = target.stat()
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError("Refusing to snapshot a non-file")
            shutil.copy2(target, backup / str(index))
            record.update(mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid)
        records.append(record)
    (backup / "manifest.json").write_text(json.dumps(records))
    return records


def restore_snapshot(backup, records):
    for record in records:
        target = Path(record["target"])
        if record["present"]:
            install_file(backup / record["copy"], target, record["mode"])
            os.chown(target, record["uid"], record["gid"])
        else:
            target.unlink(missing_ok=True)


def ensure_directory(path, mode, user):
    if path.is_symlink():
        raise RuntimeError("Refusing a symlink directory")
    if not path.exists():
        path.mkdir(mode=mode)
        path.chmod(mode)
        shutil.chown(path, user=user, group="wheel")
    info = path.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != pwd.getpwnam(user).pw_uid
            or info.st_mode & (0o077 if mode == 0o700 else 0o022)):
        raise RuntimeError("Unsafe installed directory")


def upgrade(root, fresh=False):
    if fresh and PLIST.exists():
        raise RuntimeError("Service already installed")
    details = "" if fresh else run("/bin/launchctl", "print", LABEL)
    current = next((line.split("=", 1)[1].strip() for line in details.splitlines()
                    if line.strip().startswith("program = ")), "")
    if not fresh and current not in (str(BINARY), str(LEGACY_BINARY)):
        raise RuntimeError("Unexpected active proxy program")
    config = validate_stage(root, current == str(LEGACY_BINARY))
    binary = root / "network-domain-engine"
    preflight(binary, config, root)
    targets = [BINARY, CONFIG, PLIST, DEPLOY]
    targets += [RULES / (name + ".json") for name in RULE_NAMES]
    targets += [CACHE / (name + ".json") for name in RULE_NAMES]
    backup = Path(tempfile.mkdtemp(prefix="network-domain-independent-backup.", dir="/var/db"))
    records = None
    stopped, changed = fresh, False
    directories = [path for path in (RULES, CACHE, LOGDIR) if not path.exists()]
    try:
        # Cache snapshots are taken only after the previous writer has exited.
        if not fresh:
            stop_service()
            stopped = True
        records = snapshot(backup, targets)
        changed = True
        ensure_directory(RULES, 0o755, "root")
        ensure_directory(CACHE, 0o700, "nobody")
        ensure_directory(LOGDIR, 0o700, "nobody")
        for name in RULE_NAMES:
            install_file(root / (name + ".json"), RULES / (name + ".json"), 0o644)
        install_file(binary, BINARY, 0o755)
        install_file(root / "config.json", CONFIG, 0o644)
        install_file(root / "com.local.network-domain-proxy.plist", PLIST, 0o644)
        install_file(root / "deploy-domain-proxy.py", DEPLOY, 0o755)
        start_service()
        health()
        details = run("/bin/launchctl", "print", LABEL)
        if f"program = {BINARY}" not in details or "state = running" not in details:
            raise RuntimeError("launchd is not running the independent engine")
    except BaseException:
        if stopped:
            try:
                if changed:
                    stop_candidate()
                    restore_snapshot(backup, records)
                    for directory in reversed(directories):
                        if directory.exists():
                            directory.rmdir()
                if not fresh:
                    start_service()
            except BaseException:
                print("Rollback incomplete; recovery backup retained:", backup, flush=True)
                raise
        shutil.rmtree(backup)
        raise
    print("Independent engine active. Acceptance backup:", backup, flush=True)
    return backup


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("install", "upgrade", "enable", "rollback"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Administrator authorization required")
    os.umask(0o077)
    root = Path(__file__).resolve().parent
    with deployment_lock():
        if args.action in ("install", "upgrade"):
            upgrade(root, fresh=args.action == "install")
        elif args.action == "enable":
            health()
            saved = settings()
            with STATE.open("x") as output:
                json.dump(saved, output, indent=2)
            try:
                for service in SERVICES:
                    for kind in KINDS:
                        run("/usr/sbin/networksetup", "-set" + kind, service, "127.0.0.1", "17890")
                        run("/usr/sbin/networksetup", "-set" + kind + "state", service, "on")
            except BaseException:
                restore(saved)
                raise
        else:
            restore(json.loads(STATE.read_text()))
            print("Prior HTTP/HTTPS proxy settings restored; bypass lists untouched")


if __name__ == "__main__":
    main()
