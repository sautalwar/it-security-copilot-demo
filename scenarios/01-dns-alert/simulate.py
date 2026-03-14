#!/usr/bin/env python3
"""Scenario 01 – DNS Exfiltration Alert: simulation script.

Creates a deliberately insecure DNS monitor configuration and sample log data
that contains evidence of DNS-tunneling exfiltration.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import os
import random
import string
import textwrap

ROOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "vulnerable-app")


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


# ---------------------------------------------------------------------------
# Vulnerable DNS monitor source
# ---------------------------------------------------------------------------

VULNERABLE_DNS_MONITOR = textwrap.dedent("""\
    #!/usr/bin/env python3
    \"\"\"dns_monitor.py – INSECURE DNS resolver configuration.

    WARNING: This file is intentionally vulnerable for demonstration purposes.
    \"\"\"
    from __future__ import annotations

    import socket
    import struct

    # ---- Configuration -------------------------------------------------------

    LISTEN_ADDR = "0.0.0.0"
    LISTEN_PORT = 53

    # No query logging
    ENABLE_LOGGING = False

    # Allow recursive queries from ANY source (no ACL)
    ALLOW_RECURSION_FROM = ["0.0.0.0/0"]

    # No rate limiting
    RATE_LIMIT_ENABLED = False
    RATE_LIMIT_QPS = 0  # unlimited

    # No domain blocklist
    BLOCKLIST_ENABLED = False
    BLOCKLIST_DOMAINS: list[str] = []

    # Accept DNS-over-HTTPS without certificate validation
    DOH_ENABLED = True
    DOH_VERIFY_CERT = False

    # No DNS tunneling detection
    TUNNELING_DETECTION = False

    # ---- Server loop ---------------------------------------------------------

    def start_server() -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((LISTEN_ADDR, LISTEN_PORT))
        print(f"DNS resolver listening on {LISTEN_ADDR}:{LISTEN_PORT}")
        while True:
            data, addr = sock.recvfrom(4096)
            # Forward query upstream without any inspection
            handle_query(data, addr, sock)


    def handle_query(data: bytes, addr: tuple[str, int], sock: socket.socket) -> None:
        \"\"\"Forward the query to an upstream resolver without filtering.\"\"\"
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.sendto(data, ("8.8.8.8", 53))
        response, _ = upstream.recvfrom(4096)
        sock.sendto(response, addr)
        upstream.close()


    if __name__ == "__main__":
        start_server()
""")


# ---------------------------------------------------------------------------
# Log generation helpers
# ---------------------------------------------------------------------------

NORMAL_DOMAINS: list[str] = [
    "www.google.com",
    "www.microsoft.com",
    "login.microsoftonline.com",
    "github.com",
    "api.github.com",
    "outlook.office365.com",
    "teams.microsoft.com",
    "cdn.jsdelivr.net",
    "pypi.org",
    "registry.npmjs.org",
    "stackoverflow.com",
    "docs.python.org",
]

C2_DOMAIN = "evil-c2.example.com"

RECORD_TYPES: list[str] = ["A", "AAAA", "CNAME", "MX", "TXT"]

SOURCE_IPS: list[str] = [
    "10.0.1.15",
    "10.0.1.22",
    "10.0.1.38",
    "10.0.2.5",
    "10.0.2.17",
]

COMPROMISED_IP = "10.0.1.15"


def _random_b64_label(length: int = 20) -> str:
    """Create a Base64-encoded subdomain label simulating exfiltrated data."""
    raw = "".join(random.choices(string.ascii_letters + string.digits, k=length))
    return base64.b64encode(raw.encode()).decode().rstrip("=").lower()


def _generate_log_lines(count: int = 200) -> list[str]:
    """Return a list of DNS query log lines mixing normal and suspicious traffic."""
    lines: list[str] = []
    base_time = datetime.datetime(2025, 1, 15, 9, 0, 0)

    for i in range(count):
        ts = base_time + datetime.timedelta(seconds=random.randint(0, 3600))
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%SZ")

        if i % 4 == 0:
            # Suspicious: Base64-encoded subdomain to C2
            label = _random_b64_label(random.randint(15, 40))
            domain = f"{label}.{C2_DOMAIN}"
            src_ip = COMPROMISED_IP
            rtype = random.choice(["A", "TXT"])
        elif i % 20 == 1:
            # Suspicious: TXT query with large payload marker
            label = _random_b64_label(60)
            domain = f"{label}.{C2_DOMAIN}"
            src_ip = COMPROMISED_IP
            rtype = "TXT"
        else:
            domain = random.choice(NORMAL_DOMAINS)
            src_ip = random.choice(SOURCE_IPS)
            rtype = random.choice(RECORD_TYPES)

        resp_code = "NOERROR" if random.random() > 0.05 else "NXDOMAIN"
        line = f"{ts_str} query {src_ip} {rtype} {domain} {resp_code}"
        lines.append(line)

    # Add a high-frequency burst (50+ queries in ~60 s)
    burst_base = base_time + datetime.timedelta(minutes=30)
    for j in range(55):
        ts = burst_base + datetime.timedelta(seconds=j)
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
        label = _random_b64_label(25)
        domain = f"{label}.{C2_DOMAIN}"
        line = f"{ts_str} query {COMPROMISED_IP} A {domain} NOERROR"
        lines.append(line)

    lines.sort()
    return lines


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def simulate(output_dir: str) -> None:
    _ensure_dir(output_dir)

    # Write vulnerable dns_monitor.py
    monitor_path = os.path.join(output_dir, "dns_monitor.py")
    with open(monitor_path, "w", encoding="utf-8") as f:
        f.write(VULNERABLE_DNS_MONITOR)
    print(f"[+] Created INSECURE DNS monitor config → {monitor_path}")

    # Write sample log
    log_path = os.path.join(output_dir, "dns_queries.log")
    lines = _generate_log_lines()
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] Created sample DNS query log ({len(lines)} entries) → {log_path}")

    # Summary
    c2_count = sum(1 for l in lines if C2_DOMAIN in l)
    print()
    print("=== Simulation Summary ===")
    print(f"  Vulnerable DNS config : {monitor_path}")
    print(f"  DNS query log         : {log_path}")
    print(f"  Total log entries     : {len(lines)}")
    print(f"  C2 domain queries     : {c2_count}")
    print(f"  Compromised host IP   : {COMPROMISED_IP}")
    print(f"  C2 domain             : {C2_DOMAIN}")
    print()
    print("[!] The DNS resolver has NO logging, NO blocklist, NO rate limiting,")
    print("    and NO tunneling detection.  Run remediate.py to fix.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulate an insecure DNS resolver and exfiltration log data.",
    )
    parser.add_argument(
        "--output-dir",
        default=ROOT_DIR,
        help="Directory to write vulnerable files into (default: vulnerable-app/).",
    )
    args = parser.parse_args()
    simulate(args.output_dir)


if __name__ == "__main__":
    main()
