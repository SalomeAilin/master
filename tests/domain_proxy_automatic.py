"""Isolated native classification, hot updates and last-good cache recovery."""
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
spec = importlib.util.spec_from_file_location("builder", ROOT / "scripts/build-domain-proxy.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def wait_for(predicate, timeout=6):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for independent engine evidence")


def run(binary):
    contents = {
        "domestic": {"version": 2, "rules": [{"domain": ["listed-cn.test"]}]},
        "foreign": {"version": 2, "rules": [{"domain": ["listed-foreign.test"]}]},
        "china": {"version": 2, "rules": [{"ip_cidr": ["223.5.5.0/24"]}]},
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
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            config = builder.build_independent(ROOT / "config", directory, directory / "cache")
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            config["listen"] = f"127.0.0.1:{port}"
            config["china_cidr"] = []
            names = {
                "github.com": ["223.5.5.5"], "www.douyin.com": ["1.1.1.1"],
                "listed-cn.test": ["1.1.1.1"], "listed-foreign.test": ["223.5.5.5"],
                "unknown-cn.test": ["223.5.5.5"], "unknown-foreign.test": ["1.1.1.1"],
                "updated-cn.test": ["1.1.1.1"], "private-rebind.test": ["127.0.0.1"],
            }
            for kind, interface in (("domestic", "en998"), ("foreign", "en999")):
                config[kind]["interface"] = interface
                config[kind]["dns"] = {"address": "", "server_name": "", "hosts": names}
            for source in config["rule_sources"]:
                kind = source["kind"]
                Path(source["seed"]).write_text(json.dumps(contents[kind]))
                source.update(url=f"http://127.0.0.1:{server.server_port}/{kind}", interval="500ms")
            path = directory / "config.json"
            path.write_text(json.dumps(config))
            subprocess.run([binary, "check", "-c", str(path)], check=True)
            log_path = directory / "output.log"

            def engine_checks(cached=False):
                with log_path.open("w") as output:
                    process = subprocess.Popen([binary, "run", "-c", str(path)], stdout=output, stderr=output)
                    try:
                        wait_for(lambda: '"event":"started"' in log_path.read_text() or process.poll() is not None)
                        assert process.poll() is None, log_path.read_text()

                        def events(start, port):
                            records = []
                            for line in log_path.read_text()[start:].splitlines():
                                try:
                                    records.append(json.loads(line))
                                except json.JSONDecodeError:
                                    continue
                            incoming = next((event for event in records if event.get("event") == "incoming"
                                             and event.get("from") == f"127.0.0.1:{port}"), {})
                            return [event for event in records if incoming and event.get("id") == incoming["id"]]

                        def check(name, kind):
                            start = len(log_path.read_text())
                            with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                                local = connection.getsockname()[1]
                                connection.sendall(f"CONNECT {name}:443 HTTP/1.1\r\nHost: {name}:443\r\n\r\n".encode())
                                response = connection.recv(4096)
                                assert response.startswith(b"HTTP/1.1 502"), response
                                wait_for(lambda: any(event.get("event") == "route" and
                                                     event.get("outbound") == kind and
                                                     event.get("target") == f"{name}:443"
                                                     for event in events(start, local)))
                            print("PASS", name, "->", kind)

                        for name, kind in (("github.com", "foreign"), ("www.douyin.com", "domestic"),
                                           ("listed-cn.test", "domestic"), ("listed-foreign.test", "foreign"),
                                           ("unknown-cn.test", "domestic"), ("unknown-foreign.test", "foreign")):
                            check(name, kind)
                        start = len(log_path.read_text())
                        with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                            local = connection.getsockname()[1]
                            connection.sendall(b"CONNECT private-rebind.test:443 HTTP/1.1\r\nHost: private-rebind.test:443\r\n\r\n")
                            connection.recv(4096)
                            wait_for(lambda: any(event.get("event") == "rejected" for event in events(start, local)))
                        assert not any(event.get("event") == "route" for event in events(start, local))
                        print("PASS private DNS answer rejected before any outbound dial")
                        if not cached:
                            check("updated-cn.test", "foreign")
                            contents["domestic"]["rules"][0]["domain"].append("updated-cn.test")
                            time.sleep(1.5)
                            check("updated-cn.test", "domestic")
                            contents["domestic"] = b"corrupt-not-json"
                            wait_for(lambda: "rule_update_failed" in log_path.read_text())
                            check("updated-cn.test", "domestic")
                            print("PASS hot update and corrupt-update last-good retention")
                        else:
                            check("updated-cn.test", "domestic")
                            print("PASS cached restart with update server and seeds unavailable")
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
            for source in config["rule_sources"]:
                Path(source["seed"]).unlink()
            engine_checks(cached=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    run(sys.argv[1])
