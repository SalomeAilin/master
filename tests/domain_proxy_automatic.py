"""Exercise the actual engine with local DNS, rule updates and no external dials."""
import importlib.util
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("builder", ROOT / "build-domain-proxy.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def wait_for(predicate, timeout=6):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for engine evidence")


def run(binary):
    contents = {
        "geosite-geolocation-cn": {"version": 3, "rules": [{"domain": ["listed-cn.test"]}]},
        "geosite-geolocation-!cn": {"version": 3, "rules": [{"domain": ["listed-foreign.test"]}]},
        "geoip-cn": {"version": 3, "rules": [{"ip_cidr": ["223.5.5.0/24"]}]},
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            payload = contents[self.path[1:]]
            data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            config = builder.build(ROOT, directory, directory / "cache.db")
            config["log"]["level"] = "debug"
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            config["inbounds"][0]["listen_port"] = port
            # The unknown-IP test must use the remote GeoIP set, not the legacy list.
            config["route"]["rules"].pop()
            # Invalid interfaces expose the chosen outbound without sending traffic.
            for outbound in config["outbounds"]:
                outbound["bind_interface"] = "en999"
            names = {
                "github.com": ["223.5.5.5"],
                "www.douyin.com": ["1.1.1.1"],
                "listed-cn.test": ["1.1.1.1"],
                "listed-foreign.test": ["223.5.5.5"],
                "unknown-cn.test": ["223.5.5.5"],
                "unknown-foreign.test": ["1.1.1.1"],
                "updated-cn.test": ["1.1.1.1"],
                "private-rebind.test": ["127.0.0.1"],
            }
            config["dns"]["servers"] = [
                {"type": "hosts", "tag": tag, "predefined": names}
                for tag in ("domestic-dns", "foreign-dns")
            ]
            for rule_set in config["route"]["rule_set"]:
                tag = rule_set["tag"]
                initial = directory / (tag + ".json")
                initial.write_text(json.dumps(contents[tag]))
                rule_set.update({
                    "format": "source", "initial_path": str(initial),
                    "url": f"http://127.0.0.1:{server.server_port}/{tag}",
                    "http_client": {"bind_interface": "lo0"}, "update_interval": "500ms",
                })
            path = directory / "config.json"
            path.write_text(json.dumps(config))
            subprocess.run([binary, "check", "-c", str(path)], check=True)
            log_path = directory / "output.log"

            def engine_checks(cached=False):
                with log_path.open("w") as output:
                    process = subprocess.Popen([binary, "run", "--disable-color", "-c", str(path)], stdout=output, stderr=output)
                    try:
                        wait_for(lambda: "started" in log_path.read_text() or process.poll() is not None)
                        assert process.poll() is None, log_path.read_text()

                        def check(name, outbound):
                            start = len(log_path.read_text())
                            with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                                connection.sendall(f"CONNECT {name}:443 HTTP/1.1\r\nHost: {name}:443\r\n\r\n".encode())
                                connection.recv(4096)
                                expected = f"outbound/direct[{outbound}]: outbound connection to {name}:443"
                                wait_for(lambda: expected in log_path.read_text()[start:])
                            print("PASS", name, "->", outbound)

                        check("github.com", "foreign-wifi")
                        check("www.douyin.com", "domestic-wired")
                        check("listed-cn.test", "domestic-wired")
                        check("listed-foreign.test", "foreign-wifi")
                        check("unknown-cn.test", "domestic-wired")
                        check("unknown-foreign.test", "foreign-wifi")
                        start = len(log_path.read_text())
                        with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                            connection.sendall(b"CONNECT private-rebind.test:443 HTTP/1.1\r\nHost: private-rebind.test:443\r\n\r\n")
                            connection.recv(4096)
                            wait_for(lambda: "reject" in log_path.read_text()[start:])
                        assert "outbound/direct" not in log_path.read_text()[start:]
                        print("PASS unclassified private DNS answer is rejected")
                        if not cached:
                            check("updated-cn.test", "foreign-wifi")
                            contents["geosite-geolocation-cn"]["rules"][0]["domain"].append("updated-cn.test")
                            time.sleep(1.5)
                            check("updated-cn.test", "domestic-wired")
                            contents["geosite-geolocation-cn"] = b"corrupt-not-json"
                            wait_for(lambda: "fetch rule-set geosite-geolocation-cn" in log_path.read_text())
                            check("updated-cn.test", "domestic-wired")
                            print("PASS live update changes new connections; corrupt update retains last good rules")
                        else:
                            check("updated-cn.test", "domestic-wired")
                            print("PASS restart with unreachable update server and no seed uses persistent cache")
                    except BaseException:
                        print(log_path.read_text())
                        raise
                    finally:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()

            engine_checks()
            server.shutdown()
            server.server_close()
            for rule_set in config["route"]["rule_set"]:
                Path(rule_set["initial_path"]).unlink()
            engine_checks(cached=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    run(sys.argv[1])
