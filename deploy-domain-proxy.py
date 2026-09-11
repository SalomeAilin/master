#!/usr/bin/env python3
"""Install separately from activation; restore the exact prior proxy settings."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
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
RULE_NAMES = ("geosite-geolocation-cn", "geosite-geolocation-!cn", "geoip-cn")


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def start_service():
    # launchd can still be removing a booted-out job when bootstrap first runs.
    for attempt in range(10):
        try:
            return run("/bin/launchctl", "bootstrap", "system", PLIST)
        except subprocess.CalledProcessError as error:
            if error.returncode != 5 or attempt == 9:
                raise
            time.sleep(0.5)


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
    temporary = target.with_name(target.name + ".domain-new")
    if temporary.exists() or temporary.is_symlink():
        raise RuntimeError("Unexpected staging file: " + str(temporary))
    with temporary.open("xb") as output, Path(source).open("rb") as data:
        shutil.copyfileobj(data, output)
    os.chmod(temporary, mode)
    os.chown(temporary, 0, 0)
    os.replace(temporary, target)


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
                    if "sing-box started" in output.read():
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


def update_automatic(root):
    run(BINARY, "check", "-c", str(root / "config.json"))
    backup = Path(tempfile.mkdtemp(prefix="network-domain-auto-backup.", dir="/var/db"))
    shutil.copy2(CONFIG, backup / "config.json")
    if RULES.exists():
        if RULES.is_symlink() or RULES.stat().st_uid != 0 or RULES.stat().st_mode & 0o022:
            raise RuntimeError("Unsafe rule seed directory")
        shutil.copytree(RULES, backup / "rules")
    with tempfile.TemporaryDirectory(prefix="network-domain-preflight.", dir="/var/db") as temporary:
        directory = Path(temporary)
        shutil.chown(directory, user="nobody", group="wheel")
        warmed_cache = warm_rule_cache(root, directory)
        stopped = False
        try:
            prepare_automatic_data(root)
            run("/bin/launchctl", "bootout", LABEL)
            stopped = True
            install_file(root / "config.json", CONFIG, 0o644)
            install_file(warmed_cache, CACHE, 0o600)
            shutil.chown(CACHE, user="nobody", group="wheel")
            start_service()
            time.sleep(2)
            for url in ("https://www.douyin.com/", "https://github.com/"):
                run("/usr/bin/curl", "--proxy", "http://127.0.0.1:17890", "--noproxy", "", "-fsS", "-o", "/dev/null", "--max-time", "15", url)
            run("/bin/launchctl", "print", LABEL)
        except BaseException:
            install_file(backup / "config.json", CONFIG, 0o644)
            if (backup / "rules").exists():
                for name in RULE_NAMES:
                    install_file(backup / "rules" / (name + ".srs"), RULES / (name + ".srs"), 0o644)
            if stopped:
                subprocess.run(["/bin/launchctl", "bootout", LABEL], capture_output=True)
                start_service()
            print("Activation failed; previous proxy configuration restored. Backup:", backup, flush=True)
            raise
    print("Automatic classification active; backup:", backup)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("install", "enable", "rollback", "update-auto"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Administrator authorization required")
    os.umask(0o077)
    root = Path(__file__).resolve().parent
    if args.action == "update-auto":
        update_automatic(root)
    elif args.action == "install":
        if Path(PLIST).exists():
            raise RuntimeError("Service already installed; refusing implicit replacement")
        binary = root / "sing-box-1.14.0-darwin-arm64/sing-box"
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
        install_file(root / "network-domain-proxy-run.py", "/usr/local/sbin/network-domain-proxy-run.py", 0o755)
        install_file(root / "com.local.network-domain-proxy.plist", PLIST, 0o644)
        logdir = Path("/var/log/network-domain-proxy")
        logdir.mkdir(mode=0o700)
        shutil.chown(logdir, user="nobody", group="wheel")
        start_service()
        print("Service installed; system proxy settings unchanged")
    elif args.action == "enable":
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
