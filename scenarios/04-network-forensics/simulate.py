#!/usr/bin/env python3
"""Scenario 04 – Network Forensics: simulation script.

Creates a deliberately weak packet capture configuration and sample IOC data
to demonstrate an unprepared forensic posture.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import random
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


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _fake_hash(seed: str) -> str:
    """Generate a deterministic SHA-256 hash for demo purposes."""
    return hashlib.sha256(seed.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Weak packet capture script
# ---------------------------------------------------------------------------

WEAK_CAPTURE_SCRIPT = textwrap.dedent("""\
    #!/usr/bin/env python3
    \"\"\"network_capture.py – WEAK packet capture setup.

    WARNING: This file is intentionally under-configured for demonstration.
    \"\"\"
    from __future__ import annotations

    import socket
    import time

    # ---- Configuration -------------------------------------------------------

    INTERFACE = "eth0"
    CAPTURE_FILE = "/tmp/capture.raw"  # non-standard format

    # No BPF filter — capture EVERYTHING
    BPF_FILTER = ""

    # No IOC extraction
    AUTO_EXTRACT_IOCS = False

    # No timeline generation
    GENERATE_TIMELINE = False

    # No integrity hashing of capture files
    HASH_CAPTURES = False

    # No chain-of-custody metadata
    CHAIN_OF_CUSTODY = False

    # No packet size limit
    SNAP_LENGTH = 0  # 0 = unlimited (wastes disk)

    # ---- Capture loop --------------------------------------------------------

    def start_capture() -> None:
        \"\"\"Start raw packet capture without any filtering or analysis.\"\"\"
        print(f"Starting raw capture on {INTERFACE}...")
        print(f"Output: {CAPTURE_FILE}")
        print("WARNING: No BPF filter applied — capturing ALL traffic.")
        print("WARNING: No integrity hashing — captures cannot be verified.")

        try:
            # Attempt raw socket (requires root)
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except (OSError, AttributeError):
            print("Raw socket not available — demo mode only.")
            return

        with open(CAPTURE_FILE, "wb") as f:
            while True:
                packet, _ = sock.recvfrom(65535)
                # Write raw bytes without structure — non-standard format
                f.write(packet)
                f.write(b"\\n---PACKET_BOUNDARY---\\n")


    if __name__ == "__main__":
        start_capture()
""")


# ---------------------------------------------------------------------------
# Sample IOC file
# ---------------------------------------------------------------------------

def _generate_iocs() -> str:
    lines: list[str] = []
    lines.append("# Captured Indicators of Compromise (IOCs)")
    lines.append("# Source: Network forensic analysis")
    lines.append(f"# Date: 2025-01-15")
    lines.append("")

    lines.append("## C2 Server IPs")
    for ip in C2_IPS:
        lines.append(f"  {ip}")
    lines.append("")

    lines.append("## Malicious Domains")
    for domain in C2_DOMAINS:
        lines.append(f"  {domain}")
    lines.append("")

    lines.append("## Malware File Hashes (SHA-256)")
    malware_names = [
        "backdoor_loader.exe",
        "dns_tunnel_agent.dll",
        "data_harvester.py",
        "keylogger_module.so",
    ]
    for name in malware_names:
        h = _fake_hash(name)
        lines.append(f"  {h}  {name}")
    lines.append("")

    lines.append("## Data Exfiltration Endpoints")
    for url in EXFIL_URLS:
        lines.append(f"  {url}")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def simulate(output_dir: str) -> None:
    _ensure_dir(output_dir)

    # 1. Weak capture script
    capture_path = os.path.join(output_dir, "network_capture.py")
    with open(capture_path, "w", encoding="utf-8") as f:
        f.write(WEAK_CAPTURE_SCRIPT)
    print(f"[+] Created WEAK packet capture script → {capture_path}")

    # 2. Sample IOCs
    ioc_path = os.path.join(output_dir, "captured_iocs.txt")
    ioc_content = _generate_iocs()
    with open(ioc_path, "w", encoding="utf-8") as f:
        f.write(ioc_content)
    print(f"[+] Created sample IOC file → {ioc_path}")

    print()
    print("=== Simulation Summary ===")
    print(f"  Weak capture script   : {capture_path}")
    print(f"  Sample IOCs           : {ioc_path}")
    print()
    print("[!] The capture setup has NO BPF filtering, NO IOC extraction,")
    print("    NO timeline generation, and NO integrity hashing.")
    print("    Run remediate.py to create a proper forensic capture setup.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulate a weak packet capture setup and create sample IOC data.",
    )
    parser.add_argument(
        "--output-dir",
        default=ROOT_DIR,
        help="Directory to write files into (default: vulnerable-app/).",
    )
    args = parser.parse_args()
    simulate(args.output_dir)


if __name__ == "__main__":
    main()
