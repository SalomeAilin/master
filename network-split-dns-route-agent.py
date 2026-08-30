#!/usr/bin/env python3
"""Bind domestic DNS answers to Ethernet before dnsmasq returns them."""

import json
import logging
import os
import socket
import struct
import subprocess
import tempfile
import time

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 5353
UPSTREAMS = (("223.5.5.5", 53), ("119.29.29.29", 53))
ETH_GATEWAY = "192.168.1.1"
ETH_INTERFACE = "en0"
STATE_FILE = "/var/db/network-split-dns-routes.json"
LOG_FILE = "/var/log/network-split-dns-route-agent.log"
MIN_TTL = 60
MAX_TTL = 3600
EXPIRY_GRACE = 300


def setup_logging():
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )


def skip_name(packet, offset):
    while offset < len(packet):
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        if length == 0:
            return offset + 1
        offset += length + 1
    raise ValueError("truncated DNS name")


def query_name(packet):
    if len(packet) < 13:
        return ""
    labels = []
    offset = 12
    while offset < len(packet):
        length = packet[offset]
        if length == 0:
            return ".".join(labels).lower()
        if length & 0xC0:
            return ""
        offset += 1
        if offset + length > len(packet):
            return ""
        labels.append(packet[offset : offset + length].decode("ascii", "ignore"))
        offset += length
    return ""


def ipv4_answers(packet):
    if len(packet) < 12:
        return []
    _, _, questions, answers, _, _ = struct.unpack("!HHHHHH", packet[:12])
    offset = 12
    try:
        for _ in range(questions):
            offset = skip_name(packet, offset) + 4
        result = []
        for _ in range(answers):
            offset = skip_name(packet, offset)
            record_type, record_class, ttl, length = struct.unpack("!HHIH", packet[offset : offset + 10])
            offset += 10
            rdata = packet[offset : offset + length]
            offset += length
            if record_type == 1 and record_class == 1 and length == 4:
                result.append((socket.inet_ntoa(rdata), ttl))
        return result
    except (ValueError, struct.error):
        return []


def servfail(packet):
    if len(packet) < 12:
        return packet
    ident, flags, questions, _, _, _ = struct.unpack("!HHHHHH", packet[:12])
    flags = (flags | 0x8000 | 0x0002) & ~0x0200
    return struct.pack("!HHHHHH", ident, flags, questions, 0, 0, 0) + packet[12:]


def forward(packet):
    query_id = packet[:2]
    for upstream in UPSTREAMS:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1.5)
            try:
                sock.sendto(packet, upstream)
                response, _ = sock.recvfrom(65535)
                if response[:2] == query_id:
                    return response
            except OSError:
                continue
    return None


def route_is_ethernet(ip):
    try:
        result = subprocess.run(
            ["/sbin/route", "-n", "get", ip],
            capture_output=True,
            text=True,
            timeout=1,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return f"gateway: {ETH_GATEWAY}" in result.stdout and f"interface: {ETH_INTERFACE}" in result.stdout


def bind_route(ip):
    if route_is_ethernet(ip):
        return True, False
    try:
        subprocess.run(["/sbin/route", "-n", "delete", "-host", ip], capture_output=True, timeout=1, check=False)
        result = subprocess.run(
            ["/sbin/route", "-n", "add", "-host", ip, ETH_GATEWAY, "-ifp", ETH_INTERFACE],
            capture_output=True,
            text=True,
            timeout=1,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, False
    return route_is_ethernet(ip), result.returncode == 0


def load_state():
    try:
        with open(STATE_FILE, "r", encoding="ascii") as state_file:
            return json.load(state_file)
    except (OSError, ValueError):
        return {}


def save_state(state):
    directory = os.path.dirname(STATE_FILE)
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="network-split-dns-routes.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as state_file:
            json.dump(state, state_file, sort_keys=True)
        os.replace(temporary, STATE_FILE)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def cleanup_routes(state):
    now = time.time()
    changed = False
    for ip, expiry in list(state.items()):
        if expiry > now:
            continue
        if route_is_ethernet(ip):
            subprocess.run(["/sbin/route", "-n", "delete", "-host", ip], capture_output=True, timeout=1, check=False)
            logging.info("expired route removed ip=%s", ip)
        del state[ip]
        changed = True
    return changed


def handle(packet, state):
    response = forward(packet)
    if response is None:
        logging.warning("upstream DNS unavailable domain=%s", query_name(packet))
        return servfail(packet)

    answers = ipv4_answers(response)
    if not answers:
        return response

    domain = query_name(packet)
    now = time.time()
    for ip, ttl in answers:
        ready, created = bind_route(ip)
        if not ready:
            logging.error("route bind failed domain=%s ip=%s", domain, ip)
            return servfail(packet)
        if created:
            logging.info("route bound domain=%s ip=%s ttl=%s", domain, ip, ttl)
        # Only retire routes this agent created. Static policy routes remain
        # owned by the existing route guard.
        if created or ip in state:
            state[ip] = now + min(MAX_TTL, max(MIN_TTL, ttl)) + EXPIRY_GRACE
    return response


def main():
    setup_logging()
    state = load_state()
    cleanup_routes(state)
    save_state(state)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((LISTEN_HOST, LISTEN_PORT))
        listener.settimeout(30)
        logging.info("started listen=%s:%s", LISTEN_HOST, LISTEN_PORT)
        while True:
            try:
                packet, client = listener.recvfrom(65535)
                response = handle(packet, state)
                if cleanup_routes(state):
                    logging.info("expired DNS route state cleaned")
                save_state(state)
                listener.sendto(response, client)
            except socket.timeout:
                if cleanup_routes(state):
                    save_state(state)
            except Exception as error:
                logging.exception("request handling failed error=%s", error)


if __name__ == "__main__":
    main()
