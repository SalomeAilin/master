"""Read-only live TLS and kernel socket evidence; run as administrator for lsof."""
import argparse
import datetime
import json
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time


def connections(pid):
    result = subprocess.run(["/usr/sbin/lsof", "-nP", "-a", "-p", str(pid), "-iTCP", "-F", "n"], capture_output=True, text=True)
    return {line[1:] for line in result.stdout.splitlines() if line.startswith("n") and "->" in line}


def probe(pid, host, port=17890, log_path=Path("/var/log/network-domain-proxy/service.log")):
    before = connections(pid)
    started = time.monotonic()
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        local_port = connection.getsockname()[1]
        connection.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
        header = bytearray()
        while not header.endswith(b"\r\n\r\n") and len(header) < 8192:
            part = connection.recv(1)
            if not part:
                raise RuntimeError("Proxy closed CONNECT")
            header.extend(part)
        if not header.startswith(b"HTTP/1.1 200"):
            raise RuntimeError(header.decode(errors="replace"))
        with ssl.create_default_context().wrap_socket(connection, server_hostname=host) as tls:
            # Hold this TLS connection while inspecting the proxy's kernel sockets.
            after = connections(pid)
            candidates = sorted(n for n in after - before if
                                not n.startswith("127.0.0.1:") and n.endswith(":443") and
                                not n.split("->", 1)[1].startswith(("223.5.5.5:", "1.1.1.1:")))
            tls.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: network-split-verification/1\r\n\r\n".encode())
            response = bytearray()
            while b"\r\n\r\n" not in response and len(response) < 65536:
                part = tls.recv(4096)
                if not part:
                    break
                response.extend(part)
            status = bytes(response).split(b"\r\n", 1)[0].decode(errors="replace")
            elapsed = time.monotonic() - started
    raw = log_path.read_text()
    log = re.sub(r"\x1b\[[0-9;]*m", "", raw)
    events = []
    for line in log.splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # Historical logs predate the independent engine.
    incoming_index = next((index for index in range(len(events) - 1, -1, -1)
                           if events[index].get("event") == "incoming"
                           and events[index].get("from") == f"127.0.0.1:{local_port}"), None)
    incoming = events[incoming_index] if incoming_index is not None else {}
    recent = events[incoming_index + 1:] if incoming_index is not None else []
    decisions = [event for event in recent if incoming and event.get("id") == incoming["id"]
                 and event.get("event") in ("route", "connected")]
    exact = {event["source"] + "->" + event["destination"] for event in decisions
             if event.get("event") == "connected"}
    candidates = [candidate for candidate in candidates if candidate in exact]
    return {
        "host": host, "certificate_verified": True, "status": status,
        "seconds_to_response_headers_including_socket_inspection": round(elapsed, 3),
        "outbound_log": decisions,
        "new_external_tcp_sockets": candidates,
        "socket_attribution": "unique" if len(candidates) == 1 else "ambiguous; do not treat candidates as exact attribution",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    config = json.loads(Path("/usr/local/etc/network-domain-proxy.json").read_text())
    pids = subprocess.check_output(["/usr/bin/pgrep", "-f", "^/usr/local/libexec/network-domain-engine run( |$)"], text=True).split()
    if len(pids) != 1:
        raise RuntimeError("Expected exactly one production proxy engine")
    report = {"time": datetime.datetime.now().astimezone().isoformat(), "engine_pid": int(pids[0]), "probes": []}
    for host in ("www.douyin.com", "www.csdn.net", "github.com"):
        attempts = []
        for _ in range(3):
            result = probe(pids[0], host)
            attempts.append(result)
            if result["socket_attribution"] == "unique":
                break
        report["probes"].append({"host": host, "attempts": attempts})
    local = config["local_domestic"]
    report["csdn_in_manual_overrides"] = "www.csdn.net" in local["domain"] or any(
        "www.csdn.net" == suffix or "www.csdn.net".endswith("." + suffix) for suffix in local["domain_suffix"])
    report["limitations"] = ["Short live sample, not a video playback test", "Concurrent browser connections can make socket attribution ambiguous"]
    output = json.dumps(report, indent=2) + "\n"
    if args.output:
        with args.output.open("x") as target:
            target.write(output)
    print(output)


if __name__ == "__main__":
    main()
