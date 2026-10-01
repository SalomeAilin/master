"""Native CLI log bounds, startup diagnostics and graceful process exit."""
import json
import importlib.util
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


def run(binary):
    with tempfile.TemporaryDirectory(prefix="network-native-test.") as directory:
        root = Path(directory)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        config = root / "config.json"
        repo = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location("builder", repo / "scripts/build-domain-proxy.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        candidate = builder.build_independent(repo / "config", root, root / "cache")
        candidate["listen"] = f"127.0.0.1:{port}"
        for source in candidate["rule_sources"]:
            rule = {"ip_cidr": ["223.5.5.0/24"]} if source["kind"] == "china" else {"domain": ["fixture.test"]}
            Path(source["seed"]).write_text(json.dumps({"version": 2, "rules": [rule]}))
        config.write_text(json.dumps(candidate))
        log_path = root / "service.log"
        command = [binary, "run", "--disable-color", "--log-file", str(log_path),
                   "--log-max-size", "1024", "--log-max-backups", "3", "-c", str(config)]
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise AssertionError(process.stderr.read().decode())
                if log_path.exists() and '"event":"started"' in log_path.read_text():
                    break
                time.sleep(0.05)
            else:
                raise AssertionError("Native engine did not start")
            for _ in range(40):
                with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                    connection.sendall(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
                    connection.recv(4096)
            time.sleep(0.1)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise AssertionError("Native engine did not exit on SIGTERM")
        assert process.returncode == 0, process.stderr.read().decode()
        process.stderr.close()
        logs = sorted(root.glob("service.log*"))
        assert len(logs) == 4, logs
        for path in logs:
            assert path.stat().st_size <= 1024, path
            assert path.stat().st_mode & 0o777 == 0o600, path
        assert any('"event":"rejected"' in path.read_text() for path in logs), logs
        print("PASS native process logs rotate within four private 1 KiB files and SIGTERM exits cleanly")
        config.write_text("{broken")
        result = subprocess.run(command, capture_output=True, timeout=5)
        assert result.returncode != 0, "Invalid configuration started"
        assert '"event":"startup_failed"' in log_path.read_text(), log_path.read_text()
        assert log_path.stat().st_size <= 1024
        print("PASS startup configuration errors reach the same bounded native log")


if __name__ == "__main__":
    run(sys.argv[1])
