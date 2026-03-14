#!/usr/bin/env python3
"""Scenario 10 – Network Compliance: plant non-compliant network inventory."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def _non_compliant_inventory() -> dict:
    """Network inventory that fails CIS / NIST / PCI-DSS checks."""
    return {
        "inventory_version": "1.0",
        "last_scan": datetime.now(timezone.utc).isoformat(),
        "devices": [
            {
                "hostname": "sw-core-01",
                "type": "switch",
                "vendor": "Cisco",
                "model": "Catalyst 9300",
                "ip": "10.0.1.1",
                "issues": [
                    "Default credentials (admin/admin)",
                    "Telnet enabled on VTY lines",
                    "SNMPv2 with community string 'public'",
                    "No syslog forwarding configured",
                    "No NTP synchronization",
                    "HTTP management interface enabled (not HTTPS)",
                ],
                "config_snippet": {
                    "username": "admin",
                    "password": "admin",
                    "enable_password": "cisco",
                    "snmp_community": "public",
                    "vty_transport": "telnet",
                    "ntp_server": None,
                    "logging_host": None,
                    "ip_http_server": True,
                    "ip_https_server": False,
                },
            },
            {
                "hostname": "sw-access-02",
                "type": "switch",
                "vendor": "Cisco",
                "model": "Catalyst 2960",
                "ip": "10.0.1.2",
                "issues": [
                    "Default credentials (admin/password)",
                    "Unused ports not shut down",
                    "No port-security configured",
                    "STP BPDU guard not enabled",
                    "No DHCP snooping",
                ],
                "config_snippet": {
                    "username": "admin",
                    "password": "password",
                    "unused_ports_shutdown": False,
                    "port_security": False,
                    "bpdu_guard": False,
                    "dhcp_snooping": False,
                },
            },
            {
                "hostname": "rtr-edge-01",
                "type": "router",
                "vendor": "Cisco",
                "model": "ISR 4451",
                "ip": "10.0.0.1",
                "issues": [
                    "Telnet enabled (SSH not enforced)",
                    "No ACL on management plane",
                    "IP source routing enabled",
                    "No login banner",
                    "SNMP v2c with 'public' community string",
                    "No syslog forwarding",
                    "CDP enabled on external interfaces",
                ],
                "config_snippet": {
                    "vty_transport": "telnet ssh",
                    "ip_source_route": True,
                    "banner_motd": None,
                    "snmp_version": "2c",
                    "snmp_community": "public",
                    "logging_host": None,
                    "cdp_external": True,
                    "management_acl": None,
                },
            },
            {
                "hostname": "rtr-wan-02",
                "type": "router",
                "vendor": "Cisco",
                "model": "ISR 4331",
                "ip": "10.0.0.2",
                "issues": [
                    "Default credentials (cisco/cisco)",
                    "No NTP authentication",
                    "Finger service enabled",
                    "Small-servers enabled",
                ],
                "config_snippet": {
                    "username": "cisco",
                    "password": "cisco",
                    "ntp_authentication": False,
                    "service_finger": True,
                    "service_tcp_small_servers": True,
                    "service_udp_small_servers": True,
                },
            },
            {
                "hostname": "fw-perimeter-01",
                "type": "firewall",
                "vendor": "Palo Alto",
                "model": "PA-3260",
                "ip": "10.0.0.254",
                "issues": [
                    "12 stale firewall rules (>180 days, zero hits)",
                    "Any/any rule present for legacy app",
                    "No change management documentation",
                    "No rule expiration policy",
                ],
                "stale_rules": [
                    {"id": "rule-101", "description": "Legacy FTP allow", "last_hit": "2023-01-15", "hits_30d": 0},
                    {"id": "rule-102", "description": "Temp dev access", "last_hit": "2023-03-22", "hits_30d": 0},
                    {"id": "rule-103", "description": "Old VPN tunnel", "last_hit": "2023-02-01", "hits_30d": 0},
                    {"id": "rule-104", "description": "Test web server", "last_hit": "2023-04-10", "hits_30d": 0},
                    {"id": "rule-105", "description": "Legacy DB access", "last_hit": "2023-01-05", "hits_30d": 0},
                    {"id": "rule-106", "description": "Contractor VPN", "last_hit": "2023-02-28", "hits_30d": 0},
                    {"id": "rule-107", "description": "Deprecated API", "last_hit": "2023-05-01", "hits_30d": 0},
                    {"id": "rule-108", "description": "Old monitoring", "last_hit": "2023-03-15", "hits_30d": 0},
                    {"id": "rule-109", "description": "Any/any legacy app", "last_hit": "2024-01-01", "hits_30d": 2},
                    {"id": "rule-110", "description": "Unused NAT rule", "last_hit": "2023-06-20", "hits_30d": 0},
                    {"id": "rule-111", "description": "Old SNMP permit", "last_hit": "2023-04-05", "hits_30d": 0},
                    {"id": "rule-112", "description": "Decomm server", "last_hit": "2023-07-12", "hits_30d": 0},
                ],
                "change_management": None,
            },
        ],
    }


def _compliance_status() -> dict:
    """Compliance check results showing widespread failures."""
    return {
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "frameworks": {
            "CIS_Cisco_IOS_Benchmark_v4": {
                "total_controls": 52,
                "passed": 14,
                "failed": 31,
                "not_applicable": 7,
                "key_failures": [
                    {"control": "1.1.1", "title": "Set 'enable secret'", "status": "FAIL"},
                    {"control": "1.1.4", "title": "Set 'service password-encryption'", "status": "FAIL"},
                    {"control": "1.2.1", "title": "Set 'no ip source-route'", "status": "FAIL"},
                    {"control": "1.3.1", "title": "Set 'no cdp run' on external interfaces", "status": "FAIL"},
                    {"control": "2.1.1", "title": "Set 'transport input ssh' for VTY", "status": "FAIL"},
                    {"control": "2.1.4", "title": "Disable telnet on all VTY lines", "status": "FAIL"},
                    {"control": "2.2.1", "title": "Configure NTP authentication", "status": "FAIL"},
                    {"control": "3.1.1", "title": "Set syslog logging", "status": "FAIL"},
                    {"control": "3.2.1", "title": "Configure SNMP v3", "status": "FAIL"},
                ],
            },
            "NIST_800_53_Rev5": {
                "total_controls_mapped": 28,
                "passed": 8,
                "failed": 20,
                "key_failures": [
                    {"control": "AC-2", "title": "Account Management", "status": "FAIL", "detail": "Default credentials in use"},
                    {"control": "AC-17", "title": "Remote Access", "status": "FAIL", "detail": "Telnet enabled"},
                    {"control": "AU-2", "title": "Audit Events", "status": "FAIL", "detail": "No syslog forwarding"},
                    {"control": "AU-8", "title": "Time Stamps", "status": "FAIL", "detail": "No NTP configured"},
                    {"control": "CM-7", "title": "Least Functionality", "status": "FAIL", "detail": "Unnecessary services enabled"},
                    {"control": "IA-5", "title": "Authenticator Management", "status": "FAIL", "detail": "Weak passwords"},
                    {"control": "SC-8", "title": "Transmission Confidentiality", "status": "FAIL", "detail": "Telnet (plaintext)"},
                    {"control": "SI-4", "title": "System Monitoring", "status": "FAIL", "detail": "No centralized logging"},
                ],
            },
            "PCI_DSS_v4": {
                "total_requirements_mapped": 18,
                "passed": 5,
                "failed": 13,
                "key_failures": [
                    {"req": "1.2.1", "title": "Restrict inbound/outbound traffic", "status": "FAIL", "detail": "Any/any rule present"},
                    {"req": "1.2.5", "title": "Review firewall rules every 6 months", "status": "FAIL", "detail": "12 stale rules"},
                    {"req": "2.2.2", "title": "Change vendor defaults", "status": "FAIL", "detail": "Default credentials"},
                    {"req": "2.2.4", "title": "Disable unnecessary services", "status": "FAIL", "detail": "Telnet, finger, small-servers"},
                    {"req": "8.2.1", "title": "Unique IDs for all users", "status": "FAIL", "detail": "Shared admin accounts"},
                    {"req": "8.3.6", "title": "Strong passwords", "status": "FAIL", "detail": "admin/admin, cisco/cisco"},
                    {"req": "10.2.1", "title": "Audit log for all access", "status": "FAIL", "detail": "No syslog"},
                    {"req": "10.6.1", "title": "Time sync (NTP)", "status": "FAIL", "detail": "NTP not configured"},
                ],
            },
        },
    }


def simulate(base_dir: Path) -> None:
    """Plant non-compliant network inventory and compliance results."""
    vuln_dir = base_dir / "vulnerable-app"
    vuln_dir.mkdir(parents=True, exist_ok=True)

    inv_path = vuln_dir / "network_inventory.json"
    inv_path.write_text(json.dumps(_non_compliant_inventory(), indent=2) + "\n", encoding="utf-8")
    print(f"[+] Non-compliant network inventory -> {inv_path}")

    cs_path = vuln_dir / "compliance_status.json"
    cs_path.write_text(json.dumps(_compliance_status(), indent=2) + "\n", encoding="utf-8")
    print(f"[+] Compliance failure status        -> {cs_path}")

    print()
    print("[!] Compliance gaps planted:")
    print("    • Default credentials on switches & routers")
    print("    • Telnet enabled (SSH not enforced)")
    print("    • SNMPv2 with 'public' community string")
    print("    • No syslog, no NTP")
    print("    • 12 stale firewall rules")
    print("    • CIS: 31 failures  |  NIST: 20 failures  |  PCI-DSS: 13 failures")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Scenario 10 — simulate non-compliant network infrastructure",
    )
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent.parent,
        help="Repository root (default: two levels up from this script)",
    )
    args = parser.parse_args(argv)
    simulate(args.base_dir)


if __name__ == "__main__":
    main()
