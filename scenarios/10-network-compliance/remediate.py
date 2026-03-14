#!/usr/bin/env python3
"""Scenario 10 – Network Compliance: remediate and generate compliance reports."""
from __future__ import annotations

import argparse
import json
import textwrap
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Compliant network inventory
# ---------------------------------------------------------------------------

def _compliant_inventory() -> dict:
    """Hardened network inventory passing CIS / NIST / PCI-DSS."""
    return {
        "inventory_version": "2.0",
        "last_scan": datetime.now(timezone.utc).isoformat(),
        "devices": [
            {
                "hostname": "sw-core-01",
                "type": "switch",
                "vendor": "Cisco",
                "model": "Catalyst 9300",
                "ip": "10.0.1.1",
                "compliance_status": "PASS",
                "config_snippet": {
                    "username": "netadmin",
                    "password_hash": "$9$hashed_scrypt_value",
                    "enable_secret": "$9$hashed_enable_secret",
                    "snmp_version": "3",
                    "snmp_user": "snmpmonitor",
                    "snmp_auth": "SHA-256",
                    "snmp_priv": "AES-256",
                    "vty_transport": "ssh",
                    "ssh_version": 2,
                    "ntp_server": "10.0.0.10",
                    "ntp_authentication": True,
                    "logging_host": "10.0.0.20",
                    "logging_level": "informational",
                    "ip_http_server": False,
                    "ip_https_server": True,
                    "banner_motd": "Authorized access only. All activity is monitored.",
                    "service_password_encryption": True,
                    "service_timestamps": True,
                },
            },
            {
                "hostname": "sw-access-02",
                "type": "switch",
                "vendor": "Cisco",
                "model": "Catalyst 2960",
                "ip": "10.0.1.2",
                "compliance_status": "PASS",
                "config_snippet": {
                    "username": "netadmin",
                    "password_hash": "$9$hashed_scrypt_value",
                    "unused_ports_shutdown": True,
                    "port_security": True,
                    "port_security_max_mac": 2,
                    "port_security_violation": "shutdown",
                    "bpdu_guard": True,
                    "dhcp_snooping": True,
                    "dynamic_arp_inspection": True,
                    "ip_source_guard": True,
                    "vty_transport": "ssh",
                },
            },
            {
                "hostname": "rtr-edge-01",
                "type": "router",
                "vendor": "Cisco",
                "model": "ISR 4451",
                "ip": "10.0.0.1",
                "compliance_status": "PASS",
                "config_snippet": {
                    "vty_transport": "ssh",
                    "ssh_version": 2,
                    "ip_source_route": False,
                    "banner_motd": "Authorized access only. All activity is monitored and logged.",
                    "snmp_version": "3",
                    "snmp_auth": "SHA-256",
                    "logging_host": "10.0.0.20",
                    "logging_level": "informational",
                    "cdp_external": False,
                    "management_acl": "ACL_MGMT_ONLY",
                    "management_acl_entries": [
                        "permit 10.0.100.0/24",
                        "deny any log",
                    ],
                    "no_ip_finger": True,
                    "no_service_tcp_small_servers": True,
                    "no_service_udp_small_servers": True,
                    "ntp_server": "10.0.0.10",
                    "ntp_authentication": True,
                },
            },
            {
                "hostname": "rtr-wan-02",
                "type": "router",
                "vendor": "Cisco",
                "model": "ISR 4331",
                "ip": "10.0.0.2",
                "compliance_status": "PASS",
                "config_snippet": {
                    "username": "netadmin",
                    "password_hash": "$9$hashed_scrypt_value",
                    "ntp_authentication": True,
                    "ntp_server": "10.0.0.10",
                    "service_finger": False,
                    "service_tcp_small_servers": False,
                    "service_udp_small_servers": False,
                    "vty_transport": "ssh",
                    "ssh_version": 2,
                    "logging_host": "10.0.0.20",
                },
            },
            {
                "hostname": "fw-perimeter-01",
                "type": "firewall",
                "vendor": "Palo Alto",
                "model": "PA-3260",
                "ip": "10.0.0.254",
                "compliance_status": "PASS",
                "config_snippet": {
                    "stale_rules_removed": 12,
                    "any_any_rule_removed": True,
                    "rule_review_schedule": "quarterly",
                    "change_management": "ServiceNow ITSM integrated",
                    "rule_expiration_policy": "90 days max without review",
                    "active_rules": 37,
                    "last_rule_review": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                },
            },
        ],
    }


# ---------------------------------------------------------------------------
# Hardening scripts
# ---------------------------------------------------------------------------

def _harden_switches_script() -> str:
    return textwrap.dedent('''\
        #!/usr/bin/env python3
        """Generate Cisco IOS switch hardening commands."""
        from __future__ import annotations

        import argparse
        import json
        from pathlib import Path


        def generate_commands(hostname: str) -> list[str]:
            """Return IOS CLI commands to harden a Cisco switch."""
            return [
                f"! === Hardening commands for {hostname} ===",
                "configure terminal",
                "",
                "! --- Credentials ---",
                "no username admin",
                "username netadmin privilege 15 algorithm-type scrypt secret <STRONG_PASSWORD>",
                "enable algorithm-type scrypt secret <STRONG_ENABLE_SECRET>",
                "service password-encryption",
                "",
                "! --- SSH only (disable telnet) ---",
                "ip ssh version 2",
                "ip ssh time-out 60",
                "ip ssh authentication-retries 3",
                "line vty 0 15",
                " transport input ssh",
                " login local",
                " exec-timeout 10 0",
                "exit",
                "",
                "! --- Disable HTTP, enable HTTPS ---",
                "no ip http server",
                "ip http secure-server",
                "",
                "! --- SNMPv3 (remove v2c) ---",
                "no snmp-server community public",
                "snmp-server group SNMPV3GRP v3 priv",
                "snmp-server user snmpmonitor SNMPV3GRP v3 auth sha256 <AUTH_PASS> priv aes 256 <PRIV_PASS>",
                "",
                "! --- Syslog ---",
                "logging host 10.0.0.20",
                "logging trap informational",
                "logging source-interface Loopback0",
                "service timestamps log datetime msec localtime show-timezone",
                "",
                "! --- NTP ---",
                "ntp server 10.0.0.10",
                "ntp authenticate",
                "ntp authentication-key 1 md5 <NTP_KEY>",
                "ntp trusted-key 1",
                "",
                "! --- Port security (access ports) ---",
                "interface range GigabitEthernet1/0/1 - 48",
                " switchport port-security",
                " switchport port-security maximum 2",
                " switchport port-security violation shutdown",
                " spanning-tree bpduguard enable",
                "exit",
                "",
                "! --- Shut down unused ports ---",
                "interface range GigabitEthernet1/0/45 - 48",
                " shutdown",
                " description UNUSED",
                "exit",
                "",
                "! --- DHCP snooping ---",
                "ip dhcp snooping",
                "ip dhcp snooping vlan 1-4094",
                "",
                "! --- Banner ---",
                "banner motd ^",
                "Authorized access only. All activity is monitored.",
                "^",
                "",
                "end",
                "write memory",
            ]


        def main(argv: list[str] | None = None) -> None:
            parser = argparse.ArgumentParser(description="Generate Cisco switch hardening commands")
            parser.add_argument("--hostname", default="sw-core-01", help="Switch hostname")
            parser.add_argument("--output", type=Path, help="Write commands to file")
            args = parser.parse_args(argv)

            cmds = generate_commands(args.hostname)
            text = "\\n".join(cmds) + "\\n"

            if args.output:
                args.output.write_text(text)
                print(f"[+] Commands written to {args.output}")
            else:
                print(text)


        if __name__ == "__main__":
            main()
    ''')


def _harden_routers_script() -> str:
    return textwrap.dedent('''\
        #!/usr/bin/env python3
        """Generate Cisco IOS router hardening commands."""
        from __future__ import annotations

        import argparse
        from pathlib import Path


        def generate_commands(hostname: str) -> list[str]:
            """Return IOS CLI commands to harden a Cisco router."""
            return [
                f"! === Hardening commands for {hostname} ===",
                "configure terminal",
                "",
                "! --- Credentials ---",
                "no username cisco",
                "no username admin",
                "username netadmin privilege 15 algorithm-type scrypt secret <STRONG_PASSWORD>",
                "enable algorithm-type scrypt secret <STRONG_ENABLE_SECRET>",
                "service password-encryption",
                "",
                "! --- SSH only ---",
                "ip ssh version 2",
                "ip ssh time-out 60",
                "ip ssh authentication-retries 3",
                "line vty 0 4",
                " transport input ssh",
                " login local",
                " exec-timeout 10 0",
                " access-class ACL_MGMT_ONLY in",
                "exit",
                "",
                "! --- Management ACL ---",
                "ip access-list standard ACL_MGMT_ONLY",
                " permit 10.0.100.0 0.0.0.255",
                " deny any log",
                "exit",
                "",
                "! --- Disable insecure services ---",
                "no ip source-route",
                "no ip finger",
                "no service tcp-small-servers",
                "no service udp-small-servers",
                "no ip http server",
                "ip http secure-server",
                "",
                "! --- Disable CDP on external interfaces ---",
                "interface GigabitEthernet0/0/0",
                " no cdp enable",
                "exit",
                "",
                "! --- SNMPv3 ---",
                "no snmp-server community public",
                "snmp-server group SNMPV3GRP v3 priv",
                "snmp-server user snmpmonitor SNMPV3GRP v3 auth sha256 <AUTH_PASS> priv aes 256 <PRIV_PASS>",
                "",
                "! --- Syslog ---",
                "logging host 10.0.0.20",
                "logging trap informational",
                "logging source-interface Loopback0",
                "service timestamps log datetime msec localtime show-timezone",
                "",
                "! --- NTP with authentication ---",
                "ntp server 10.0.0.10",
                "ntp authenticate",
                "ntp authentication-key 1 md5 <NTP_KEY>",
                "ntp trusted-key 1",
                "",
                "! --- Banner ---",
                "banner motd ^",
                "Authorized access only. All activity is monitored and logged.",
                "^",
                "",
                "end",
                "write memory",
            ]


        def main(argv: list[str] | None = None) -> None:
            parser = argparse.ArgumentParser(description="Generate Cisco router hardening commands")
            parser.add_argument("--hostname", default="rtr-edge-01", help="Router hostname")
            parser.add_argument("--output", type=Path, help="Write commands to file")
            args = parser.parse_args(argv)

            cmds = generate_commands(args.hostname)
            text = "\\n".join(cmds) + "\\n"

            if args.output:
                args.output.write_text(text)
                print(f"[+] Commands written to {args.output}")
            else:
                print(text)


        if __name__ == "__main__":
            main()
    ''')


# ---------------------------------------------------------------------------
# Compliance report (Markdown)
# ---------------------------------------------------------------------------

def _compliance_report_md() -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return textwrap.dedent(f"""\
        # Network Compliance Report

        **Generated:** {now}

        ---

        ## Executive Summary

        A comprehensive compliance audit was performed against **CIS Cisco IOS
        Benchmark v4**, **NIST 800-53 Rev 5**, and **PCI-DSS v4** for all network
        devices.  Critical findings were identified and remediated.

        ## CIS Cisco IOS Benchmark v4 — Before / After

        | Metric | Before | After |
        |--------|--------|-------|
        | Total controls | 52 | 52 |
        | Passed | 14 (27 %) | 48 (92 %) |
        | Failed | 31 (60 %) | 0 (0 %) |
        | N/A | 7 (13 %) | 4 (8 %) |

        ### Key remediations
        - Replaced default credentials with scrypt-hashed passwords
        - Disabled telnet; enforced SSH v2 on all VTY lines
        - Migrated SNMP from v2c ("public") to v3 with SHA-256 / AES-256
        - Configured syslog forwarding to 10.0.0.20
        - Enabled NTP with authentication
        - Disabled CDP on external interfaces
        - Disabled HTTP management; enabled HTTPS only
        - Enabled port security, BPDU guard, DHCP snooping

        ## NIST 800-53 Rev 5 Control Mapping — Before / After

        | Control | Title | Before | After |
        |---------|-------|--------|-------|
        | AC-2 | Account Management | FAIL | PASS |
        | AC-17 | Remote Access | FAIL | PASS |
        | AU-2 | Audit Events | FAIL | PASS |
        | AU-8 | Time Stamps | FAIL | PASS |
        | CM-7 | Least Functionality | FAIL | PASS |
        | IA-5 | Authenticator Management | FAIL | PASS |
        | SC-8 | Transmission Confidentiality | FAIL | PASS |
        | SI-4 | System Monitoring | FAIL | PASS |

        **Result:** 8 → 28 controls passing (28 / 28 = 100 %)

        ## PCI-DSS v4 Requirement Mapping — Before / After

        | Req | Title | Before | After |
        |-----|-------|--------|-------|
        | 1.2.1 | Restrict traffic | FAIL | PASS |
        | 1.2.5 | Review firewall rules | FAIL | PASS |
        | 2.2.2 | Change vendor defaults | FAIL | PASS |
        | 2.2.4 | Disable unnecessary services | FAIL | PASS |
        | 8.2.1 | Unique IDs | FAIL | PASS |
        | 8.3.6 | Strong passwords | FAIL | PASS |
        | 10.2.1 | Audit logs | FAIL | PASS |
        | 10.6.1 | NTP time sync | FAIL | PASS |

        **Result:** 5 → 18 requirements passing (18 / 18 = 100 %)

        ## Remediation Timeline

        | Phase | Action | Duration |
        |-------|--------|----------|
        | 1 | Credential rotation on all devices | Day 1 |
        | 2 | Disable telnet, enable SSH v2 | Day 1 |
        | 3 | SNMP migration v2c → v3 | Day 2 |
        | 4 | Syslog + NTP configuration | Day 2 |
        | 5 | Firewall rule cleanup (12 stale rules) | Day 3 |
        | 6 | Port security & L2 hardening | Day 3-4 |
        | 7 | Validation scan & documentation | Day 5 |

        ---

        *Report generated by the IT Security Copilot Demo — Scenario 10.*
    """)


# ---------------------------------------------------------------------------
# Dashboard JSON
# ---------------------------------------------------------------------------

def _compliance_dashboard() -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall_status": "COMPLIANT",
        "frameworks": {
            "CIS_Cisco_IOS_v4": {
                "before": {"passed": 14, "failed": 31, "na": 7, "pct": 27},
                "after": {"passed": 48, "failed": 0, "na": 4, "pct": 92},
            },
            "NIST_800_53_Rev5": {
                "before": {"passed": 8, "failed": 20, "pct": 29},
                "after": {"passed": 28, "failed": 0, "pct": 100},
            },
            "PCI_DSS_v4": {
                "before": {"passed": 5, "failed": 13, "pct": 28},
                "after": {"passed": 18, "failed": 0, "pct": 100},
            },
        },
        "devices": {
            "total": 5,
            "compliant": 5,
            "non_compliant": 0,
        },
        "remediations_applied": [
            "Credential rotation",
            "SSH enforcement",
            "SNMPv3 migration",
            "Syslog forwarding",
            "NTP configuration",
            "Stale firewall rules removed",
            "Port security enabled",
            "L2 hardening (BPDU guard, DHCP snooping)",
        ],
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def remediate(base_dir: Path) -> None:
    """Generate compliant inventory, hardening scripts, and reports."""
    vuln_dir = base_dir / "vulnerable-app"
    vuln_dir.mkdir(parents=True, exist_ok=True)

    # Compliant inventory
    p = vuln_dir / "network_inventory_compliant.json"
    p.write_text(json.dumps(_compliant_inventory(), indent=2) + "\n", encoding="utf-8")
    print(f"[+] Compliant network inventory     -> {p}")

    # Hardening scripts
    p = vuln_dir / "harden_switches.py"
    p.write_text(_harden_switches_script(), encoding="utf-8")
    print(f"[+] Switch hardening script         -> {p}")

    p = vuln_dir / "harden_routers.py"
    p.write_text(_harden_routers_script(), encoding="utf-8")
    print(f"[+] Router hardening script         -> {p}")

    # Compliance report
    p = vuln_dir / "compliance_report.md"
    p.write_text(_compliance_report_md(), encoding="utf-8")
    print(f"[+] Compliance report (Markdown)    -> {p}")

    # Dashboard JSON
    p = vuln_dir / "compliance_dashboard.json"
    p.write_text(json.dumps(_compliance_dashboard(), indent=2) + "\n", encoding="utf-8")
    print(f"[+] Compliance dashboard (JSON)     -> {p}")

    print()
    print("[✓] Network compliance remediation complete:")
    print("    • 5 devices hardened")
    print("    • CIS:  27 % → 92 %")
    print("    • NIST: 29 % → 100 %")
    print("    • PCI:  28 % → 100 %")
    print("    • 12 stale firewall rules removed")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Scenario 10 — remediate network compliance gaps",
    )
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent.parent,
        help="Repository root (default: two levels up from this script)",
    )
    args = parser.parse_args(argv)
    remediate(args.base_dir)


if __name__ == "__main__":
    main()
