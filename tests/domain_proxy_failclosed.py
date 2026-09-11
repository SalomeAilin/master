"""Isolated failure injection; never disconnect the host interfaces."""
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("builder", ROOT / "build-domain-proxy.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def run(binary, rules_directory=builder.RULES_DIRECTORY):
    with tempfile.TemporaryDirectory() as directory:
        config = builder.build(ROOT, rules_directory, Path(directory) / "cache.db")
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        config["inbounds"][0]["listen_port"] = port
        config["outbounds"][0]["bind_interface"] = "en999"
        config["dns"]["servers"][1]["bind_interface"] = "en999"
        for rule_set in config["route"]["rule_set"]:
            rule_set["http_client"]["bind_interface"] = "en999"
        path = Path(directory) / "config.json"
        path.write_text(json.dumps(config))
        with (Path(directory) / "output.log").open("w+") as output:
            process = subprocess.Popen([binary, "run", "-c", str(path)], stdout=output, stderr=output)
            try:
                for _ in range(50):
                    if process.poll() is not None:
                        raise RuntimeError("Fixture failed to start")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.1)
                common = ["curl", "--proxy", f"http://127.0.0.1:{port}", "--noproxy", "", "-fsS", "-o", "/dev/null", "--max-time", "12"]
                foreign = subprocess.run(common + ["https://github.com/"], capture_output=True)
                assert foreign.returncode != 0, "Foreign connection escaped invalid pinned interface"
                domestic = subprocess.run(common + ["https://www.douyin.com/"], capture_output=True)
                assert domestic.returncode == 0, domestic.stderr
                output.flush()
                output.seek(0)
                log = output.read()
                assert "no such network interface" in log, log
                print("PASS unavailable foreign data/DNS/update interface fails closed; domestic DoH and access still work")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    run(sys.argv[1], Path(sys.argv[2]) if len(sys.argv) > 2 else builder.RULES_DIRECTORY)
