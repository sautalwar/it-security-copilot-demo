#!/usr/bin/env python3
"""Scenario 01 – DNS Exfiltration Alert: remediation script.

Rewrites the insecure DNS monitor with hardened configuration, analyses the
DNS query log, and generates a security report.
"""
from __future__ import annotations

import argparse
import collections
import datetime
import math
import os
import re
import textwrap

ROOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "vulnerable-app")

C2_DOMAIN = "evil-c2.example.com"

KNOWN_BAD_DOMAINS: list[str] = [
    "evil-c2.example.com",
    "malware-drop.example.net",
    "c2-callback.example.org",
    "exfil-data.example.com",
]


# ---------------------------------------------------------------------------
# Hardened DNS monitor source
# ---------------------------------------------------------------------------

HARDENED_DNS_MONITOR = textwrap.dedent("""\
    #!/usr/bin/env python3
    \"\"\"dns_monitor.py – HARDENED DNS resolver configuration.

    Security controls:
      • Structured query logging (JSON)
      • Domain blocklist enforcement
      • Per-source-IP rate limiting (10 qps)
      • DNS tunneling detection via Shannon entropy
      • Alert generation for suspicious patterns
    \"\"\"
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
        \"\"\"Calculate Shannon entropy of *text*.\"\"\"
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
        \"\"\"Best-effort domain extraction from raw DNS query bytes.\"\"\"
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
""")


# ---------------------------------------------------------------------------
# Log analysis helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _parse_log(log_path: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    if not os.path.isfile(log_path):
        return entries
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 6:
                entries.append({
                    "timestamp": parts[0],
                    "action": parts[1],
                    "src_ip": parts[2],
                    "record_type": parts[3],
                    "domain": parts[4],
                    "response_code": parts[5],
                })
    return entries


def _analyse_logs(entries: list[dict[str, str]]) -> dict:
    """Analyse parsed log entries and return a findings dict."""
    findings: dict = {
        "total_queries": len(entries),
        "unique_source_ips": len({e["src_ip"] for e in entries}),
        "c2_queries": [],
        "high_entropy_domains": [],
        "rate_burst_ips": [],
        "txt_exfil_queries": [],
    }

    # Per-IP per-minute counters for burst detection
    ip_minute_counts: dict[str, dict[str, int]] = collections.defaultdict(
        lambda: collections.defaultdict(int)
    )

    for entry in entries:
        domain = entry["domain"]
        src_ip = entry["src_ip"]
        ts_minute = entry["timestamp"][:16]  # YYYY-MM-DDTHH:MM
        ip_minute_counts[src_ip][ts_minute] += 1

        # C2 domain match
        if C2_DOMAIN in domain:
            findings["c2_queries"].append(entry)

        # High entropy subdomain
        labels = domain.split(".")
        if len(labels) > 2:
            subdomain = ".".join(labels[:-2])
            ent = _shannon_entropy(subdomain)
            if ent > 3.5:
                findings["high_entropy_domains"].append(
                    {"domain": domain, "entropy": round(ent, 3), "src_ip": src_ip}
                )

        # TXT exfil pattern
        if entry["record_type"] == "TXT" and C2_DOMAIN in domain:
            findings["txt_exfil_queries"].append(entry)

    # Burst detection (>30 queries in any 1-minute window from same IP)
    for ip, minutes in ip_minute_counts.items():
        for minute, count in minutes.items():
            if count > 30:
                findings["rate_burst_ips"].append(
                    {"src_ip": ip, "minute": minute, "count": count}
                )

    return findings


def _generate_report(findings: dict) -> str:
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("  DNS EXFILTRATION — SECURITY REPORT")
    lines.append(f"  Generated: {datetime.datetime.utcnow().isoformat()}Z")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Total queries analysed : {findings['total_queries']}")
    lines.append(f"Unique source IPs      : {findings['unique_source_ips']}")
    lines.append("")

    lines.append(f"[!] C2 domain queries        : {len(findings['c2_queries'])}")
    lines.append(f"[!] High-entropy subdomains  : {len(findings['high_entropy_domains'])}")
    lines.append(f"[!] TXT exfil queries        : {len(findings['txt_exfil_queries'])}")
    lines.append(f"[!] Rate-burst detections    : {len(findings['rate_burst_ips'])}")
    lines.append("")

    if findings["rate_burst_ips"]:
        lines.append("--- Rate-burst details ---")
        for b in findings["rate_burst_ips"]:
            lines.append(f"  IP {b['src_ip']}  {b['minute']}  ({b['count']} queries)")
        lines.append("")

    if findings["c2_queries"]:
        lines.append("--- Sample C2 queries (first 10) ---")
        for q in findings["c2_queries"][:10]:
            lines.append(f"  {q['timestamp']}  {q['src_ip']}  {q['record_type']}  {q['domain']}")
        lines.append("")

    lines.append("--- Recommendations ---")
    lines.append("  1. Block evil-c2.example.com at DNS and firewall level.")
    lines.append("  2. Isolate host 10.0.1.15 for forensic investigation.")
    lines.append("  3. Enable DNS query logging on all resolvers.")
    lines.append("  4. Deploy entropy-based tunneling detection.")
    lines.append("  5. Restrict outbound DNS to approved resolvers only.")
    lines.append("")
    lines.append("=" * 70)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def remediate(output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)

    # 1. Overwrite vulnerable dns_monitor.py with hardened version
    monitor_path = os.path.join(output_dir, "dns_monitor.py")
    with open(monitor_path, "w", encoding="utf-8") as f:
        f.write(HARDENED_DNS_MONITOR)
    print(f"[+] Wrote HARDENED DNS monitor → {monitor_path}")

    # 2. Analyse existing log
    log_path = os.path.join(output_dir, "dns_queries.log")
    entries = _parse_log(log_path)
    if entries:
        findings = _analyse_logs(entries)
        report = _generate_report(findings)
        report_path = os.path.join(output_dir, "dns_security_report.txt")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report + "\n")
        print(f"[+] Generated security report → {report_path}")
        print()
        print(report)
    else:
        print("[*] No DNS query log found — run simulate.py first.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Remediate the insecure DNS resolver and analyse logs.",
    )
    parser.add_argument(
        "--output-dir",
        default=ROOT_DIR,
        help="Directory containing vulnerable files (default: vulnerable-app/).",
    )
    args = parser.parse_args()
    remediate(args.output_dir)


if __name__ == "__main__":
    main()
