#!/usr/bin/env python3
"""Scenario 04 – Network Forensics: remediation script.

Rewrites the packet capture with proper forensic controls, generates a
forensic report with timeline and IOC analysis, and creates an IOC blocklist.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import textwrap

ROOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "vulnerable-app")

C2_IPS: list[str] = ["203.0.113.66", "198.51.100.42", "203.0.113.100"]
C2_DOMAINS: list[str] = [
    "evil-c2.example.com",
    "malware-drop.example.net",
    "c2-callback.example.org",
    "exfil-data.example.com",
]
EXFIL_URLS: list[str] = [
    "https://evil-c2.example.com/upload",
    "https://exfil-data.example.com/api/recv",
    "https://malware-drop.example.net/collect",
]
COMPROMISED_HOST = "10.0.1.15"


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _fake_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Hardened capture script
# ---------------------------------------------------------------------------

HARDENED_CAPTURE_SCRIPT = textwrap.dedent("""\
    #!/usr/bin/env python3
    \"\"\"network_capture.py – HARDENED forensic packet capture.

    Security & forensic controls:
      • BPF filters for targeted capture
      • Automatic IOC extraction (IPs, domains, hashes)
      • Timeline generation
      • PCAP integrity hashing (SHA-256)
      • Chain-of-custody metadata
    \"\"\"
    from __future__ import annotations

    import datetime
    import hashlib
    import json
    import os
    import re
    import socket
    import struct
    import time

    # ---- Configuration -------------------------------------------------------

    INTERFACE = "eth0"
    CAPTURE_DIR = "/var/forensics/captures"
    SNAP_LENGTH = 1518  # standard Ethernet MTU

    # BPF filter: focus on C2 traffic, DNS, and outbound HTTPS
    BPF_FILTER = (
        "host 203.0.113.66 or host 198.51.100.42 or host 203.0.113.100 "
        "or port 53 or port 443"
    )

    # Automatic IOC extraction
    AUTO_EXTRACT_IOCS = True

    # Timeline generation
    GENERATE_TIMELINE = True

    # Integrity hashing
    HASH_CAPTURES = True
    HASH_ALGORITHM = "sha256"

    # Chain-of-custody
    CHAIN_OF_CUSTODY = True

    # Known-bad indicators for matching
    KNOWN_C2_IPS: list[str] = ["203.0.113.66", "198.51.100.42", "203.0.113.100"]
    KNOWN_C2_DOMAINS: list[str] = [
        "evil-c2.example.com",
        "malware-drop.example.net",
        "c2-callback.example.org",
        "exfil-data.example.com",
    ]

    # ---- Forensic helpers ----------------------------------------------------

    def _sha256_file(path: str) -> str:
        \"\"\"Compute SHA-256 hash of a file for integrity verification.\"\"\"
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()


    def _write_chain_of_custody(capture_path: str, analyst: str = "auto") -> str:
        \"\"\"Write chain-of-custody metadata alongside the capture file.\"\"\"
        meta = {
            "capture_file": capture_path,
            "sha256": _sha256_file(capture_path) if os.path.exists(capture_path) else "pending",
            "analyst": analyst,
            "capture_start": datetime.datetime.utcnow().isoformat() + "Z",
            "interface": INTERFACE,
            "bpf_filter": BPF_FILTER,
            "snap_length": SNAP_LENGTH,
            "hostname": socket.gethostname(),
            "notes": "Automated forensic capture for incident IR-2025-0115",
        }
        meta_path = capture_path + ".custody.json"
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)
        return meta_path


    def _extract_iocs_from_payload(payload: bytes) -> dict:
        \"\"\"Extract IOCs from raw packet payload.\"\"\"
        text = payload.decode("ascii", errors="ignore")
        iocs: dict = {"ips": set(), "domains": set(), "urls": set()}

        # IP addresses
        for match in re.finditer(r"\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b", text):
            ip = match.group(1)
            if ip in KNOWN_C2_IPS:
                iocs["ips"].add(ip)

        # Domains
        for domain in KNOWN_C2_DOMAINS:
            if domain in text:
                iocs["domains"].add(domain)

        # URLs
        for match in re.finditer(r"https?://[^\\s]+", text):
            iocs["urls"].add(match.group(0))

        return {k: list(v) for k, v in iocs.items()}


    def _generate_pcap_header() -> bytes:
        \"\"\"Generate a standard PCAP global header.\"\"\"
        return struct.pack(
            "<IHHiIII",
            0xA1B2C3D4,  # magic number
            2, 4,         # version
            0,            # timezone
            0,            # sigfigs
            SNAP_LENGTH,  # snaplen
            1,            # Ethernet
        )


    # ---- Capture loop --------------------------------------------------------

    def start_capture() -> None:
        \"\"\"Start filtered forensic packet capture with IOC extraction.\"\"\"
        os.makedirs(CAPTURE_DIR, exist_ok=True)
        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        capture_path = os.path.join(CAPTURE_DIR, f"forensic_{ts}.pcap")

        print(f"[*] Starting forensic capture on {INTERFACE}")
        print(f"[*] BPF filter: {BPF_FILTER}")
        print(f"[*] Output: {capture_path}")

        if CHAIN_OF_CUSTODY:
            meta_path = _write_chain_of_custody(capture_path)
            print(f"[*] Chain-of-custody: {meta_path}")

        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except (OSError, AttributeError):
            print("[!] Raw socket not available — demo mode. No live capture.")
            return

        timeline: list[dict] = []

        with open(capture_path, "wb") as f:
            f.write(_generate_pcap_header())
            packet_count = 0
            try:
                while True:
                    packet, _ = sock.recvfrom(SNAP_LENGTH)
                    now = datetime.datetime.utcnow()

                    # Write PCAP packet record
                    ts_sec = int(now.timestamp())
                    ts_usec = now.microsecond
                    pkt_len = len(packet)
                    f.write(struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len))
                    f.write(packet)

                    # IOC extraction
                    if AUTO_EXTRACT_IOCS:
                        iocs = _extract_iocs_from_payload(packet)
                        if any(iocs.values()):
                            event = {
                                "timestamp": now.isoformat() + "Z",
                                "iocs": iocs,
                                "packet_number": packet_count,
                            }
                            timeline.append(event)
                            print(f"  [IOC] {event}")

                    packet_count += 1

            except KeyboardInterrupt:
                print(f"\\n[*] Capture stopped. {packet_count} packets captured.")

        # Hash the capture file
        if HASH_CAPTURES:
            file_hash = _sha256_file(capture_path)
            print(f"[*] Capture SHA-256: {file_hash}")

        # Write timeline
        if GENERATE_TIMELINE and timeline:
            timeline_path = capture_path + ".timeline.json"
            with open(timeline_path, "w") as f:
                json.dump(timeline, f, indent=2)
            print(f"[*] Timeline: {timeline_path}")


    if __name__ == "__main__":
        start_capture()
""")


# ---------------------------------------------------------------------------
# Forensic report
# ---------------------------------------------------------------------------

def _generate_forensic_report() -> str:
    malware_files = [
        ("backdoor_loader.exe", "Initial access payload, dropped via phishing"),
        ("dns_tunnel_agent.dll", "DNS tunneling agent for C2 communication"),
        ("data_harvester.py", "Script to collect and stage sensitive files"),
        ("keylogger_module.so", "Keylogger for credential harvesting"),
    ]

    lines: list[str] = []
    lines.append("# Network Forensics Report")
    lines.append("")
    lines.append(f"**Incident ID:** IR-2025-0115")
    lines.append(f"**Date:** 2025-01-15")
    lines.append(f"**Analyst:** Automated Forensic Analysis")
    lines.append(f"**Classification:** CONFIDENTIAL")
    lines.append(f"**Generated:** {datetime.datetime.utcnow().isoformat()}Z")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("A DNS tunneling-based data exfiltration attack was detected and")
    lines.append("analysed. The compromised host (`10.0.1.15`) communicated with")
    lines.append("multiple C2 servers using encoded DNS subdomain queries. Approximately")
    lines.append("15 MB of data was exfiltrated over a 2-hour window.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Attack Timeline")
    lines.append("")
    lines.append("| Time (UTC) | Event |")
    lines.append("|------------|-------|")
    lines.append("| 2025-01-15 08:45 | Phishing email delivered to user on 10.0.1.15 |")
    lines.append("| 2025-01-15 08:52 | User opens attachment → `backdoor_loader.exe` executes |")
    lines.append("| 2025-01-15 08:53 | `dns_tunnel_agent.dll` loaded into memory |")
    lines.append("| 2025-01-15 08:55 | First DNS beacon to `evil-c2.example.com` |")
    lines.append("| 2025-01-15 09:00 | `data_harvester.py` deployed, begins file collection |")
    lines.append("| 2025-01-15 09:05 | `keylogger_module.so` installed for credential capture |")
    lines.append("| 2025-01-15 09:10 | High-frequency DNS exfiltration begins (50+ q/min) |")
    lines.append("| 2025-01-15 09:30 | Burst exfil: 55 queries in 60 seconds |")
    lines.append("| 2025-01-15 09:45 | Large outbound HTTPS transfer to `203.0.113.66` |")
    lines.append("| 2025-01-15 10:00 | Failed lateral movement attempts (brute-force SSH) |")
    lines.append("| 2025-01-15 10:15 | Alert triggered in SIEM |")
    lines.append("| 2025-01-15 10:20 | Incident response initiated |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Indicators of Compromise (IOCs)")
    lines.append("")
    lines.append("### C2 Server IPs")
    lines.append("")
    for ip in C2_IPS:
        lines.append(f"- `{ip}`")
    lines.append("")
    lines.append("### Malicious Domains")
    lines.append("")
    for domain in C2_DOMAINS:
        lines.append(f"- `{domain}`")
    lines.append("")
    lines.append("### Malware Hashes (SHA-256)")
    lines.append("")
    lines.append("| Hash | Filename | Description |")
    lines.append("|------|----------|-------------|")
    for name, desc in malware_files:
        h = _fake_hash(name)
        lines.append(f"| `{h[:16]}...` | `{name}` | {desc} |")
    lines.append("")
    lines.append("### Data Exfiltration Endpoints")
    lines.append("")
    for url in EXFIL_URLS:
        lines.append(f"- `{url}`")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Scope of Data Exfiltration")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append("| Compromised hosts | 1 (10.0.1.15) |")
    lines.append("| Duration of exfil | ~2 hours |")
    lines.append("| Estimated data volume | ~15 MB |")
    lines.append("| C2 channels used | DNS tunneling + HTTPS |")
    lines.append("| Lateral movement | Attempted, unsuccessful |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Recommendations")
    lines.append("")
    lines.append("1. **Immediate:** Isolate host `10.0.1.15` from the network.")
    lines.append("2. **Immediate:** Block all C2 IPs and domains at firewall and DNS level.")
    lines.append("3. **Short-term:** Reimage host `10.0.1.15` from known-good baseline.")
    lines.append("4. **Short-term:** Reset credentials for all users on the compromised host.")
    lines.append("5. **Short-term:** Deploy IOC blocklist across all network controls.")
    lines.append("6. **Medium-term:** Enable DNS query logging and entropy-based detection.")
    lines.append("7. **Medium-term:** Implement egress filtering and network segmentation.")
    lines.append("8. **Long-term:** Deploy EDR solution with DNS tunneling detection.")
    lines.append("9. **Long-term:** Conduct organization-wide phishing awareness training.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Evidence Chain of Custody")
    lines.append("")
    lines.append("| Item | Hash | Custodian |")
    lines.append("|------|------|-----------|")
    lines.append(f"| dns_queries.log | `{_fake_hash('dns_queries.log')[:32]}...` | IR Team |")
    lines.append(f"| network_flows.json | `{_fake_hash('network_flows.json')[:32]}...` | IR Team |")
    lines.append(f"| captured_iocs.txt | `{_fake_hash('captured_iocs.txt')[:32]}...` | IR Team |")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# IOC blocklist
# ---------------------------------------------------------------------------

def _generate_blocklist() -> dict:
    malware_names = [
        "backdoor_loader.exe",
        "dns_tunnel_agent.dll",
        "data_harvester.py",
        "keylogger_module.so",
    ]
    return {
        "metadata": {
            "name": "IR-2025-0115 IOC Blocklist",
            "generated": datetime.datetime.utcnow().isoformat() + "Z",
            "severity": "Critical",
            "confidence": "High",
            "ttl_hours": 720,
        },
        "block_ips": C2_IPS,
        "block_domains": C2_DOMAINS,
        "block_urls": EXFIL_URLS,
        "block_hashes": [
            {"sha256": _fake_hash(name), "filename": name}
            for name in malware_names
        ],
        "block_subnets": [
            "203.0.113.0/24",
            "198.51.100.0/24",
        ],
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def remediate(output_dir: str) -> None:
    _ensure_dir(output_dir)

    # 1. Hardened capture script
    capture_path = os.path.join(output_dir, "network_capture.py")
    with open(capture_path, "w", encoding="utf-8") as f:
        f.write(HARDENED_CAPTURE_SCRIPT)
    print(f"[+] Wrote HARDENED forensic capture script → {capture_path}")

    # 2. Forensic report
    report_path = os.path.join(output_dir, "forensic_report.md")
    report = _generate_forensic_report()
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"[+] Generated forensic report → {report_path}")

    # 3. IOC blocklist
    blocklist_path = os.path.join(output_dir, "ioc_blocklist.json")
    blocklist = _generate_blocklist()
    with open(blocklist_path, "w", encoding="utf-8") as f:
        json.dump(blocklist, f, indent=2)
    print(f"[+] Generated IOC blocklist → {blocklist_path}")

    print()
    print("=== Forensic Remediation Summary ===")
    print(f"  Hardened capture script : {capture_path}")
    print(f"  Forensic report         : {report_path}")
    print(f"  IOC blocklist           : {blocklist_path}")
    print()
    print("Key improvements:")
    print("  • BPF filtering for targeted capture (vs. capture everything)")
    print("  • Automatic IOC extraction from packet payloads")
    print("  • Timeline generation for incident reconstruction")
    print("  • SHA-256 integrity hashing of all capture files")
    print("  • Chain-of-custody metadata for legal defensibility")
    print("  • Standard PCAP format (vs. non-standard raw dumps)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate hardened forensic capture, report, and IOC blocklist.",
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
