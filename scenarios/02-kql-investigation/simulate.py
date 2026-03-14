#!/usr/bin/env python3
"""Scenario 02 – KQL Investigation: simulation script.

Creates a weak Microsoft Sentinel SIEM configuration and sample log files
(DNS events, auth events, network flows) that contain correlated suspicious
activity for investigation.
"""
from __future__ import annotations

import argparse
import json
import os
import random

ROOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "vulnerable-app")

C2_DOMAIN = "evil-c2.example.com"
COMPROMISED_IP = "10.0.1.15"
C2_SERVER_IP = "203.0.113.66"

NORMAL_IPS: list[str] = ["10.0.1.22", "10.0.1.38", "10.0.2.5", "10.0.2.17"]
NORMAL_DOMAINS: list[str] = [
    "www.google.com", "login.microsoftonline.com", "github.com",
    "teams.microsoft.com", "outlook.office365.com",
]


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


# ---------------------------------------------------------------------------
# Weak SIEM config
# ---------------------------------------------------------------------------

WEAK_SIEM_CONFIG: dict = {
    "workspace": {
        "name": "SecurityWorkspace",
        "sku": "PerGB2018",
        "retentionInDays": 30,  # too short
    },
    "dataConnectors": {
        "windowsSecurityEvents": {"enabled": True, "streams": ["SecurityEvent"]},
        "dnsAnalytics": {"enabled": False},  # NOT enabled
        "nsgFlowLogs": {"enabled": False},   # NOT enabled
        "azureADSignInLogs": {"enabled": False},
        "microsoftDefenderForEndpoint": {"enabled": False},
        "threatIntelligence": {"enabled": False},
    },
    "alertRules": [
        {
            "name": "HighVolumeOutbound",
            "severity": "Low",
            "threshold": 10000,  # way too high — misses real attacks
            "windowMinutes": 60,
            "enabled": True,
        },
        {
            "name": "FailedLoginsFromSameIP",
            "severity": "Medium",
            "threshold": 100,  # too high
            "windowMinutes": 60,
            "enabled": True,
        },
    ],
    "automationRules": [],       # no automation
    "playbookConnections": [],   # no playbooks
    "incidentSettings": {
        "autoGroupRelatedAlerts": False,
        "autoInvestigate": False,
    },
}


# ---------------------------------------------------------------------------
# Sample log generators
# ---------------------------------------------------------------------------

def _generate_dns_events(count: int = 120) -> list[dict]:
    events: list[dict] = []
    for i in range(count):
        minute = i % 60
        ts = f"2025-01-15T09:{minute:02d}:00Z"
        if i % 3 == 0:
            domain = f"{'x' * random.randint(10, 40)}.{C2_DOMAIN}"
            src_ip = COMPROMISED_IP
            rtype = random.choice(["A", "TXT"])
        else:
            domain = random.choice(NORMAL_DOMAINS)
            src_ip = random.choice(NORMAL_IPS + [COMPROMISED_IP])
            rtype = "A"
        events.append({
            "TimeGenerated": ts,
            "SourceIP": src_ip,
            "QueryType": rtype,
            "QueryName": domain,
            "ResponseCode": "NOERROR",
            "SubType": "LookupQuery",
        })
    return events


def _generate_auth_events(count: int = 60) -> list[dict]:
    events: list[dict] = []
    for i in range(count):
        minute = 10 + (i % 50)
        ts = f"2025-01-15T09:{minute:02d}:00Z"
        if i % 5 == 0:
            src_ip = COMPROMISED_IP
            result = "Failure"
            user = random.choice(["admin", "svc_backup", "root"])
        else:
            src_ip = random.choice(NORMAL_IPS)
            result = random.choice(["Success", "Success", "Failure"])
            user = random.choice(["alice", "bob", "carol", "dave"])
        events.append({
            "TimeGenerated": ts,
            "SourceIP": src_ip,
            "TargetUserName": user,
            "LogonResult": result,
            "LogonType": random.choice(["Interactive", "Network", "RemoteInteractive"]),
            "WorkstationName": f"WS-{random.randint(1, 20):03d}",
        })
    return events


def _generate_network_flows(count: int = 80) -> list[dict]:
    events: list[dict] = []
    for i in range(count):
        minute = i % 60
        ts = f"2025-01-15T09:{minute:02d}:00Z"
        if i % 6 == 0:
            src_ip = COMPROMISED_IP
            dst_ip = C2_SERVER_IP
            bytes_sent = random.randint(500_000, 5_000_000)
            dst_port = 443
        else:
            src_ip = random.choice(NORMAL_IPS + [COMPROMISED_IP])
            dst_ip = f"52.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            bytes_sent = random.randint(500, 50_000)
            dst_port = random.choice([80, 443, 8080])
        events.append({
            "TimeGenerated": ts,
            "SourceIP": src_ip,
            "DestinationIP": dst_ip,
            "DestinationPort": dst_port,
            "BytesSent": bytes_sent,
            "BytesReceived": random.randint(200, 10_000),
            "Protocol": "TCP",
            "FlowDirection": "Outbound",
        })
    return events


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def simulate(output_dir: str) -> None:
    _ensure_dir(output_dir)
    logs_dir = os.path.join(output_dir, "sample_logs")
    _ensure_dir(logs_dir)

    # Weak SIEM config
    config_path = os.path.join(output_dir, "siem_config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(WEAK_SIEM_CONFIG, f, indent=2)
    print(f"[+] Created WEAK Sentinel config → {config_path}")

    # DNS events
    dns_path = os.path.join(logs_dir, "dns_events.json")
    dns_events = _generate_dns_events()
    with open(dns_path, "w", encoding="utf-8") as f:
        json.dump(dns_events, f, indent=2)
    print(f"[+] Created DNS event logs ({len(dns_events)} entries) → {dns_path}")

    # Auth events
    auth_path = os.path.join(logs_dir, "auth_events.json")
    auth_events = _generate_auth_events()
    with open(auth_path, "w", encoding="utf-8") as f:
        json.dump(auth_events, f, indent=2)
    print(f"[+] Created auth event logs ({len(auth_events)} entries) → {auth_path}")

    # Network flows
    net_path = os.path.join(logs_dir, "network_flows.json")
    net_events = _generate_network_flows()
    with open(net_path, "w", encoding="utf-8") as f:
        json.dump(net_events, f, indent=2)
    print(f"[+] Created network flow logs ({len(net_events)} entries) → {net_path}")

    print()
    print("=== Simulation Summary ===")
    print(f"  SIEM config (WEAK)    : {config_path}")
    print(f"  DNS events            : {dns_path}")
    print(f"  Auth events           : {auth_path}")
    print(f"  Network flows         : {net_path}")
    print()
    print("[!] Sentinel has NO DNS connector, NO NSG flow logs, thresholds")
    print("    are too high, and there are NO automated playbooks.")
    print("    Run remediate.py to generate proper KQL queries & harden config.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulate a weak SIEM configuration and correlated log data.",
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
