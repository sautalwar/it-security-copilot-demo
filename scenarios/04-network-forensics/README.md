# Scenario 04 — Network Forensics

## Overview

Deep packet analysis to understand the **full scope of the breach** — what
data was exfiltrated, the attack timeline, and all Indicators of Compromise
(IOCs).

## Investigation Goals

1. Capture and filter network traffic for forensic evidence.
2. Extract IOCs (IP addresses, domains, file hashes, URLs).
3. Build a complete attack timeline.
4. Establish chain-of-custody for captured evidence.
5. Generate actionable blocklists.

## What the Simulation Does (`simulate.py`)

1. Creates `vulnerable-app/network_capture.py` — a **weak** packet capture
   setup:
   - No packet filtering (captures everything, drowns in noise)
   - No automatic IOC extraction
   - Saves in non-standard format
   - No timeline correlation
   - No hash verification of captures
2. Creates `vulnerable-app/captured_iocs.txt` with sample IOCs:
   - C2 server IP addresses
   - Malicious domain names
   - File hashes of dropped malware
   - Data exfiltration endpoint URLs

## What the Remediation Does (`remediate.py`)

1. Rewrites `vulnerable-app/network_capture.py` with proper forensic capture:
   - BPF filters for targeted capture
   - Automatic IOC extraction (IPs, domains, hashes)
   - Timeline generation
   - PCAP integrity hashing (SHA-256)
   - Chain-of-custody metadata
2. Generates `vulnerable-app/forensic_report.md` — full timeline, IOC
   summary, and recommendations.
3. Creates `vulnerable-app/ioc_blocklist.json` for automated blocking.

## Usage

```bash
python scenarios/04-network-forensics/simulate.py
python scenarios/04-network-forensics/remediate.py
```
