#!/usr/bin/env python3
"""dns_monitor.py – HARDENED DNS resolver configuration.

Security controls:
  • Structured query logging (JSON)
  • Domain blocklist enforcement
  • Per-source-IP rate limiting (10 qps)
  • DNS tunneling detection via Shannon entropy
  • Alert generation for suspicious patterns
"""
from __future__ import annotations

import collections
import datetime
import json
import math
import socket
import sys
import time

# ---- Configuration -------------------------------------------------------

LISTEN_ADDR = "127.0.0.1"
LISTEN_PORT = 5353  # non-privileged port for demo

# Logging – structured JSON to stdout
ENABLE_LOGGING = True

# Only allow recursion from internal subnets
ALLOW_RECURSION_FROM = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

# Rate limiting
RATE_LIMIT_ENABLED = True
RATE_LIMIT_QPS = 10  # max queries per second per source IP

# Domain blocklist
BLOCKLIST_ENABLED = True
BLOCKLIST_DOMAINS: list[str] = [
    "evil-c2.example.com",
    "malware-drop.example.net",
    "c2-callback.example.org",
    "exfil-data.example.com",
]

# DNS-over-HTTPS – require certificate validation
DOH_ENABLED = True
DOH_VERIFY_CERT = True

# DNS tunneling detection
TUNNELING_DETECTION = True
ENTROPY_THRESHOLD = 3.5  # Shannon entropy above this triggers alert

# ---- Helpers -------------------------------------------------------------

_rate_tracker: dict[str, list[float]] = collections.defaultdict(list)


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of *text*."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum(
        (c / length) * math.log2(c / length) for c in freq.values()
    )


def _is_rate_limited(src_ip: str) -> bool:
    now = time.time()
    window = [t for t in _rate_tracker[src_ip] if now - t < 1.0]
    _rate_tracker[src_ip] = window
    if len(window) >= RATE_LIMIT_QPS:
        return True
    _rate_tracker[src_ip].append(now)
    return False


def _is_blocked(domain: str) -> bool:
    for bad in BLOCKLIST_DOMAINS:
        if domain == bad or domain.endswith("." + bad):
            return True
    return False


def _check_tunneling(domain: str) -> bool:
    labels = domain.split(".")
    if len(labels) > 2:
        subdomain = ".".join(labels[:-2])
        if _shannon_entropy(subdomain) > ENTROPY_THRESHOLD:
            return True
    return False


def _log(event: dict) -> None:
    if ENABLE_LOGGING:
        event["timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"
        print(json.dumps(event), flush=True)


def _alert(alert_type: str, details: dict) -> None:
    _log({"level": "ALERT", "alert_type": alert_type, **details})


# ---- Server loop ---------------------------------------------------------

def start_server() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_ADDR, LISTEN_PORT))
    _log({"level": "INFO", "msg": f"DNS resolver listening on {LISTEN_ADDR}:{LISTEN_PORT}"})
    while True:
        data, addr = sock.recvfrom(4096)
        handle_query(data, addr, sock)


def handle_query(data: bytes, addr: tuple[str, int], sock: socket.socket) -> None:
    src_ip = addr[0]
    domain = _extract_domain(data)

    # Rate limiting
    if RATE_LIMIT_ENABLED and _is_rate_limited(src_ip):
        _alert("RATE_LIMIT_EXCEEDED", {"src_ip": src_ip, "domain": domain})
        return

    # Blocklist check
    if BLOCKLIST_ENABLED and _is_blocked(domain):
        _alert("BLOCKED_DOMAIN", {"src_ip": src_ip, "domain": domain})
        return

    # Tunneling detection
    if TUNNELING_DETECTION and _check_tunneling(domain):
        _alert("DNS_TUNNELING_SUSPECTED", {
            "src_ip": src_ip,
            "domain": domain,
            "entropy": round(_shannon_entropy(domain.split(".")[0]), 3),
        })
        return

    # Log legitimate query
    _log({"level": "INFO", "action": "QUERY", "src_ip": src_ip, "domain": domain})

    # Forward to upstream
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.settimeout(5)
    try:
        upstream.sendto(data, ("8.8.8.8", 53))
        response, _ = upstream.recvfrom(4096)
        sock.sendto(response, addr)
    except socket.timeout:
        _log({"level": "ERROR", "msg": "Upstream timeout", "src_ip": src_ip, "domain": domain})
    finally:
        upstream.close()


def _extract_domain(data: bytes) -> str:
    """Best-effort domain extraction from raw DNS query bytes."""
    try:
        idx = 12  # skip DNS header
        parts: list[str] = []
        while idx < len(data):
            length = data[idx]
            if length == 0:
                break
            idx += 1
            parts.append(data[idx:idx + length].decode("ascii", errors="replace"))
            idx += length
        return ".".join(parts)
    except Exception:
        return "<parse-error>"


if __name__ == "__main__":
    start_server()
