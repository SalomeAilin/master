#!/usr/bin/env python3
"""Run the fixed proxy binary with bounded, private diagnostic logs."""
import logging
from logging.handlers import RotatingFileHandler
import os
import signal
import subprocess


def main():
    os.umask(0o077)
    handler = RotatingFileHandler("/var/log/network-domain-proxy/service.log", maxBytes=2 * 1024 * 1024, backupCount=3)
    logger = logging.getLogger("proxy")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    child = subprocess.Popen([
        "/usr/local/libexec/network-domain-sing-box", "run", "-c",
        "/usr/local/etc/network-domain-proxy.json",
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    def stop(signum, frame):
        child.terminate()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for line in child.stdout:
            logger.info(line.rstrip())
        return child.wait()
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        handler.close()


if __name__ == "__main__":
    raise SystemExit(main())
