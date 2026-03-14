#!/usr/bin/env python3
"""Scenario 08 -- Remediate: harden the VPN gateway configuration, analyse
user compliance, and generate a full audit report with platform-specific
remediation commands."""
from __future__ import annotations

import argparse
import datetime
import json
import os
import textwrap

ROOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "vulnerable-app")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _today() -> str:
    return datetime.date.today().isoformat()


def _days_since(date_str: str) -> int:
    """Return the number of days between *date_str* (YYYY-MM-DD) and today."""
    try:
        d = datetime.date.fromisoformat(date_str)
    except (ValueError, TypeError):
        return 9999
    return (datetime.date.today() - d).days


# ---------------------------------------------------------------------------
# Hardened VPN gateway configuration
# ---------------------------------------------------------------------------

HARDENED_VPN_CONFIG: dict = {
    "vpn_gateway": {
        "name": "corp-vpn-gw-01",
        "vendor": "Generic",
        "firmware_version": "6.4.8",
        "management_ip": "10.0.0.1",
        "public_ip": "203.0.113.10",
    },
    "ike": {
        "version": "IKEv2",
        "phase1": {
            "encryption": "AES-256-GCM",
            "hash": "SHA-384",
            "dh_group": 20,
            "dh_group_description": "ECDH 384-bit (NIST P-384)",
            "lifetime_seconds": 28800,
            "authentication_method": "certificate",
        },
        "phase2": {
            "encryption": "AES-256-GCM",
            "hash": "SHA-384",
            "pfs_enabled": True,
            "pfs_group": 20,
            "lifetime_seconds": 3600,
        },
    },
    "tunnel": {
        "mode": "tunnel",
        "encapsulation": "ESP",
        "nat_traversal": True,
        "dead_peer_detection": {
            "enabled": True,
            "interval_seconds": 30,
            "retries": 3,
            "action": "restart",
        },
    },
    "authentication": {
        "type": "certificate",
        "certificate_auth_required": True,
        "certificate_authority": "Contoso-Internal-CA",
        "certificate_revocation_check": True,
        "mfa": {
            "enabled": True,
            "provider": "Azure AD / RADIUS",
            "timeout_seconds": 60,
        },
        "re_authenticate_on_reconnect": True,
    },
    "split_tunneling": {
        "enabled": True,
        "mode": "restricted",
        "allowed_subnets": [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ],
        "dns_split": True,
        "dns_servers": [
            "10.0.0.53",
            "10.0.0.54",
        ],
    },
    "session": {
        "timeout_hours": 8,
        "max_concurrent_sessions_per_user": 2,
        "idle_timeout_minutes": 30,
    },
    "logging": {
        "enabled": True,
        "log_level": "informational",
        "syslog_server": "10.0.0.200",
        "syslog_port": 514,
        "syslog_protocol": "TLS",
        "log_auth_events": True,
        "log_tunnel_events": True,
        "log_policy_violations": True,
    },
    "client_policy": {
        "enforce_posture_check": True,
        "minimum_client_version": "5.0.0",
        "allowed_os": [
            "Windows 10+",
            "macOS 12+",
            "Ubuntu 22.04+",
            "iOS 16+",
            "Android 13+",
        ],
        "deny_jailbroken_devices": True,
    },
}


# ---------------------------------------------------------------------------
# Platform-specific remediation commands
# ---------------------------------------------------------------------------

CISCO_ASA_COMMANDS = textwrap.dedent("""\
    ! -- Cisco ASA - Hardened VPN Configuration ---------------------
    !
    ! Phase 1 - IKEv2 policy
    crypto ikev2 policy 10
     encryption aes-gcm-256
     integrity sha384
     group 20
     prf sha384
     lifetime seconds 28800
    !
    ! Phase 2 - IPsec proposal
    crypto ipsec ikev2 ipsec-proposal AES256-GCM
     protocol esp encryption aes-gcm-256
     protocol esp integrity sha-384
    !
    ! Certificate authentication
    tunnel-group Corp-VPN general-attributes
     authentication certificate
     secondary-authentication-server-group AzureAD
    !
    ! Split tunnel - corporate subnets only
    access-list SPLIT-TUNNEL standard permit 10.0.0.0 255.0.0.0
    access-list SPLIT-TUNNEL standard permit 172.16.0.0 255.240.0.0
    access-list SPLIT-TUNNEL standard permit 192.168.0.0 255.255.0.0
    group-policy Corp-VPN-Policy attributes
     split-tunnel-policy tunnelspecified
     split-tunnel-network-list value SPLIT-TUNNEL
    !
    ! Dead Peer Detection
    tunnel-group Corp-VPN ipsec-attributes
     isakmp keepalive threshold 30 retry 3
    !
    ! Session limits
    group-policy Corp-VPN-Policy attributes
     vpn-session-timeout 480
     vpn-idle-timeout 30
     vpn-simultaneous-logins 2
    !
    ! Logging
    logging enable
    logging host inside 10.0.0.200
    logging trap informational
    logging class auth console informational
    logging class vpn console informational
""")

FORTIGATE_COMMANDS = textwrap.dedent("""\
    # -- FortiGate - Hardened VPN Configuration ---------------------
    #
    # Phase 1 - IKEv2
    config vpn ipsec phase1-interface
        edit "Corp-VPN"
            set ike-version 2
            set proposal aes256gcm-sha384
            set dhgrp 20
            set keylife 28800
            set authmethod signature
            set certificate "Contoso-Internal-CA"
            set dpd on-idle
            set dpd-retryinterval 30
            set dpd-retrycount 3
        next
    end
    #
    # Phase 2 - IPsec
    config vpn ipsec phase2-interface
        edit "Corp-VPN-P2"
            set phase1name "Corp-VPN"
            set proposal aes256gcm-sha384
            set pfs enable
            set dhgrp 20
            set keylifeseconds 3600
        next
    end
    #
    # Split tunnelling - corporate subnets
    config firewall address
        edit "Corp-10"
            set subnet 10.0.0.0 255.0.0.0
        next
        edit "Corp-172"
            set subnet 172.16.0.0 255.240.0.0
        next
        edit "Corp-192"
            set subnet 192.168.0.0 255.255.0.0
        next
    end
    config firewall addrgrp
        edit "Corp-Split-Tunnel"
            set member "Corp-10" "Corp-172" "Corp-192"
        next
    end
    config vpn ipsec phase1-interface
        edit "Corp-VPN"
            set split-tunnel-routing enable
            set split-tunnel-routing-address "Corp-Split-Tunnel"
        next
    end
    #
    # Session & idle timeout
    config vpn ssl settings
        set auth-timeout 480
        set idle-timeout 1800
        set dtls-max-proto-ver dtls1.2
    end
    #
    # MFA via RADIUS / Azure AD
    config user radius
        edit "AzureAD-MFA"
            set server 10.0.0.100
            set secret <RADIUS-SECRET>
            set auth-type auto
        next
    end
    #
    # Logging
    config log syslogd setting
        set status enable
        set server 10.0.0.200
        set port 514
        set enc-algorithm high
    end
""")

AZURE_VPN_COMMANDS = textwrap.dedent("""\
    # -- Azure VPN Gateway - Hardened Configuration -----------------
    #
    # Create / update the VPN gateway with IKEv2 and custom IPsec policy
    az network vnet-gateway update \\
        --resource-group Corp-RG \\
        --name corp-vpn-gw-01 \\
        --vpn-type RouteBased \\
        --sku VpnGw2

    # Custom IPsec/IKE policy (AES-256-GCM, SHA-384, DH Group ECP384)
    az network vpn-connection ipsec-policy add \\
        --resource-group Corp-RG \\
        --connection-name Corp-VPN-Connection \\
        --ike-encryption GCMAES256 \\
        --ike-integrity SHA384 \\
        --dh-group ECP384 \\
        --ipsec-encryption GCMAES256 \\
        --ipsec-integrity GCMAES256 \\
        --pfs-group ECP384 \\
        --sa-lifetime 3600 \\
        --sa-datasize 102400000

    # Enable Azure AD / RADIUS authentication
    az network vnet-gateway update \\
        --resource-group Corp-RG \\
        --name corp-vpn-gw-01 \\
        --aad-tenant "https://login.microsoftonline.com/<TENANT-ID>" \\
        --aad-audience "41b23e61-6c1e-4545-b367-cd054e0ed4b4" \\
        --aad-issuer "https://sts.windows.net/<TENANT-ID>/" \\
        --radius-server 10.0.0.100 \\
        --radius-secret <RADIUS-SECRET>

    # Diagnostic logging to Log Analytics
    az monitor diagnostic-settings create \\
        --resource "/subscriptions/<SUB>/resourceGroups/Corp-RG/providers/Microsoft.Network/virtualNetworkGateways/corp-vpn-gw-01" \\
        --name "vpn-diagnostics" \\
        --workspace "/subscriptions/<SUB>/resourceGroups/Corp-RG/providers/Microsoft.OperationalInsights/workspaces/CorpLogAnalytics" \\
        --logs '[{"category":"GatewayDiagnosticLog","enabled":true},{"category":"TunnelDiagnosticLog","enabled":true},{"category":"IKEDiagnosticLog","enabled":true},{"category":"P2SDiagnosticLog","enabled":true}]'
""")


# ---------------------------------------------------------------------------
# User compliance analysis
# ---------------------------------------------------------------------------

def _analyse_users(users: list[dict]) -> list[dict]:
    """Evaluate each user against compliance criteria and return annotated
    records with a ``compliance`` sub-dict."""
    today = _today()
    results: list[dict] = []

    for user in users:
        cert_expired = user.get("certificate_expiry", "1970-01-01") < today
        mfa_missing = not user.get("mfa_enrolled", False)
        days_inactive = _days_since(user.get("last_login", "1970-01-01"))
        inactive = days_inactive > 90

        issues: list[str] = []
        if cert_expired:
            issues.append("expired_certificate")
        if mfa_missing:
            issues.append("mfa_not_enrolled")
        if inactive:
            issues.append(f"inactive_{days_inactive}_days")

        compliant = len(issues) == 0

        results.append({
            **user,
            "compliance": {
                "compliant": compliant,
                "certificate_expired": cert_expired,
                "mfa_missing": mfa_missing,
                "inactive": inactive,
                "days_since_last_login": days_inactive,
                "issues": issues,
            },
        })

    return results


# ---------------------------------------------------------------------------
# Configuration diff -- compare weak vs hardened settings
# ---------------------------------------------------------------------------

_CONFIG_CHECKS: list[dict] = [
    {
        "check": "IKE Version",
        "weak_path": ("ike", "version"),
        "weak_expected": "IKEv1",
        "hardened_value": "IKEv2",
        "severity": "Critical",
        "recommendation": "Upgrade to IKEv2 for modern crypto negotiation and MOBIKE support.",
    },
    {
        "check": "Phase 1 Encryption",
        "weak_path": ("ike", "phase1", "encryption"),
        "weak_expected": "DES",
        "hardened_value": "AES-256-GCM",
        "severity": "Critical",
        "recommendation": "Replace DES (56-bit) with AES-256-GCM (AEAD cipher).",
    },
    {
        "check": "Phase 1 Hash",
        "weak_path": ("ike", "phase1", "hash"),
        "weak_expected": "MD5",
        "hardened_value": "SHA-384",
        "severity": "High",
        "recommendation": "Replace MD5 with SHA-384; MD5 is vulnerable to collision attacks.",
    },
    {
        "check": "DH Group",
        "weak_path": ("ike", "phase1", "dh_group"),
        "weak_expected": 1,
        "hardened_value": "20 (ECDH 384-bit)",
        "severity": "Critical",
        "recommendation": "Upgrade from DH Group 1 (768-bit) to Group 20 (384-bit ECDH) per NIST SP 800-77.",
    },
    {
        "check": "Authentication Method",
        "weak_path": ("ike", "phase1", "authentication_method"),
        "weak_expected": "pre-shared-key",
        "hardened_value": "certificate",
        "severity": "High",
        "recommendation": "Migrate from PSK to certificate-based authentication.",
    },
    {
        "check": "Perfect Forward Secrecy",
        "weak_path": ("ike", "phase2", "pfs_enabled"),
        "weak_expected": False,
        "hardened_value": "Enabled (Group 20)",
        "severity": "High",
        "recommendation": "Enable PFS so session keys are not compromised if the long-term key leaks.",
    },
    {
        "check": "Dead Peer Detection",
        "weak_path": ("tunnel", "dead_peer_detection", "enabled"),
        "weak_expected": False,
        "hardened_value": "Enabled (30 s / 3 retries)",
        "severity": "Medium",
        "recommendation": "Enable DPD to detect and clean up stale tunnels.",
    },
    {
        "check": "MFA Integration",
        "weak_path": ("authentication", "mfa", "enabled"),
        "weak_expected": False,
        "hardened_value": "Enabled (Azure AD / RADIUS)",
        "severity": "High",
        "recommendation": "Enforce MFA for all VPN users via Azure AD or RADIUS integration.",
    },
    {
        "check": "Split Tunnelling Mode",
        "weak_path": ("split_tunneling", "mode"),
        "weak_expected": "unrestricted",
        "hardened_value": "restricted (RFC 1918 subnets only)",
        "severity": "High",
        "recommendation": "Restrict split tunnel to corporate subnets (10/8, 172.16/12, 192.168/16).",
    },
    {
        "check": "Session Timeout",
        "weak_path": ("session", "timeout_hours"),
        "weak_expected": 24,
        "hardened_value": "8 hours",
        "severity": "Medium",
        "recommendation": "Reduce session timeout from 24 h to 8 h to limit hijack window.",
    },
    {
        "check": "Logging",
        "weak_path": ("logging", "enabled"),
        "weak_expected": False,
        "hardened_value": "Enabled (syslog over TLS)",
        "severity": "High",
        "recommendation": "Enable logging with syslog forwarding for audit and forensic readiness.",
    },
]


def _resolve_path(d: dict, keys: tuple) -> object:
    """Walk a nested dict to retrieve a value."""
    for k in keys:
        d = d.get(k, {}) if isinstance(d, dict) else None  # type: ignore[assignment]
        if d is None:
            return None
    return d


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def _generate_report(
    weak_config: dict,
    user_results: list[dict],
) -> str:
    """Build the full VPN audit report as a Markdown string."""
    lines: list[str] = []
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # -- Header -------------------------------------------------------------
    lines.append("# VPN Configuration Audit Report")
    lines.append("")
    lines.append(f"**Generated:** {now}")
    lines.append("")

    # -- 1. Configuration findings ------------------------------------------
    lines.append("## 1. Configuration Findings")
    lines.append("")
    lines.append("| # | Check | Current Value | Recommended | Severity | Recommendation |")
    lines.append("|---|-------|---------------|-------------|----------|----------------|")
    for idx, chk in enumerate(_CONFIG_CHECKS, 1):
        current = _resolve_path(weak_config, chk["weak_path"])
        lines.append(
            f"| {idx} | {chk['check']} | `{current}` | `{chk['hardened_value']}` "
            f"| {chk['severity']} | {chk['recommendation']} |"
        )
    lines.append("")

    # -- 2. Severity summary ------------------------------------------------
    sev_counts: dict[str, int] = {}
    for chk in _CONFIG_CHECKS:
        sev_counts[chk["severity"]] = sev_counts.get(chk["severity"], 0) + 1
    lines.append("### Severity Summary")
    lines.append("")
    for sev in ("Critical", "High", "Medium", "Low"):
        count = sev_counts.get(sev, 0)
        if count:
            lines.append(f"- **{sev}:** {count}")
    lines.append("")

    # -- 3. User compliance -------------------------------------------------
    lines.append("## 2. User Compliance")
    lines.append("")
    lines.append(
        "| Username | Full Name | Role | Cert Expired | MFA Missing "
        "| Inactive (>90 d) | Days Since Login | Status |"
    )
    lines.append(
        "|----------|-----------|------|:------------:|:-----------:"
        "|:----------------:|-----------------:|--------|"
    )
    compliant_count = 0
    non_compliant_count = 0
    for u in user_results:
        c = u["compliance"]
        if c["compliant"]:
            status = "PASS"
            compliant_count += 1
        else:
            status = "FAIL"
            non_compliant_count += 1
        lines.append(
            f"| {u['username']} | {u['full_name']} | {u['role']} "
            f"| {'Yes' if c['certificate_expired'] else 'No'} "
            f"| {'Yes' if c['mfa_missing'] else 'No'} "
            f"| {'Yes' if c['inactive'] else 'No'} "
            f"| {c['days_since_last_login']} "
            f"| {status} |"
        )
    lines.append("")
    lines.append(
        f"**Compliant:** {compliant_count}  |  "
        f"**Non-compliant:** {non_compliant_count}  |  "
        f"**Total:** {len(user_results)}"
    )
    lines.append("")

    # -- 4. Detailed user issues --------------------------------------------
    lines.append("### Non-Compliant User Details")
    lines.append("")
    for u in user_results:
        c = u["compliance"]
        if c["compliant"]:
            continue
        lines.append(f"#### {u['full_name']} (`{u['username']}`)")
        lines.append("")
        for issue in c["issues"]:
            if issue == "expired_certificate":
                lines.append(
                    f"- **Expired certificate** -- expired on "
                    f"`{u['certificate_expiry']}`.  Renew via internal CA."
                )
            elif issue == "mfa_not_enrolled":
                lines.append(
                    "- **MFA not enrolled** -- enrol user in Azure AD MFA "
                    "or issue a hardware TOTP token."
                )
            elif issue.startswith("inactive_"):
                lines.append(
                    f"- **Inactive account** -- last login `{u['last_login']}` "
                    f"({c['days_since_last_login']} days ago).  Disable or "
                    f"require re-validation."
                )
        lines.append("")

    # -- 5. Remediation commands --------------------------------------------
    lines.append("## 3. Platform-Specific Remediation Commands")
    lines.append("")

    lines.append("### 3.1 Cisco ASA")
    lines.append("")
    lines.append("```text")
    lines.append(CISCO_ASA_COMMANDS.rstrip())
    lines.append("```")
    lines.append("")

    lines.append("### 3.2 FortiGate")
    lines.append("")
    lines.append("```text")
    lines.append(FORTIGATE_COMMANDS.rstrip())
    lines.append("```")
    lines.append("")

    lines.append("### 3.3 Azure VPN Gateway")
    lines.append("")
    lines.append("```bash")
    lines.append(AZURE_VPN_COMMANDS.rstrip())
    lines.append("```")
    lines.append("")

    # -- 6. Recommendations summary -----------------------------------------
    lines.append("## 4. Remediation Checklist")
    lines.append("")
    lines.append("- [ ] Upgrade IKE to version 2")
    lines.append("- [ ] Replace DES with AES-256-GCM")
    lines.append("- [ ] Replace MD5 with SHA-384")
    lines.append("- [ ] Upgrade DH group to Group 20 (ECDH P-384)")
    lines.append("- [ ] Migrate authentication from PSK to certificates")
    lines.append("- [ ] Enable MFA for all VPN users")
    lines.append("- [ ] Restrict split tunnelling to corporate subnets")
    lines.append("- [ ] Reduce session timeout to 8 hours")
    lines.append("- [ ] Enable Dead Peer Detection (30 s / 3 retries)")
    lines.append("- [ ] Enable Perfect Forward Secrecy (Group 20)")
    lines.append("- [ ] Enable logging with syslog over TLS")
    lines.append("- [ ] Enforce endpoint posture checks")
    lines.append("- [ ] Renew expired user certificates")
    lines.append("- [ ] Enrol all users in MFA")
    lines.append("- [ ] Disable or re-validate inactive accounts (>90 days)")
    lines.append("")

    lines.append("---")
    lines.append(f"*Report generated by Scenario 08 -- VPN Audit -- {now}*")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Remediation entry point
# ---------------------------------------------------------------------------

def remediate(output_dir: str) -> None:
    """Harden the VPN config, analyse users, and write the audit report."""
    _ensure_dir(output_dir)

    # -- 1. Write hardened VPN configuration --------------------------------
    hardened_path = os.path.join(output_dir, "vpn_config_hardened.json")
    with open(hardened_path, "w", encoding="utf-8") as fh:
        json.dump(HARDENED_VPN_CONFIG, fh, indent=2)
    print(f"[+] Created hardened VPN config -> {hardened_path}")

    # -- 2. Load & analyse VPN users ----------------------------------------
    users_path = os.path.join(output_dir, "vpn_users.json")
    if not os.path.isfile(users_path):
        print(f"[*] No user roster found at {users_path} -- run simulate.py first.")
        user_results: list[dict] = []
    else:
        with open(users_path, encoding="utf-8") as fh:
            data = json.load(fh)
        users = data.get("vpn_users", [])
        user_results = _analyse_users(users)
        non_compliant = sum(
            1 for u in user_results if not u["compliance"]["compliant"]
        )
        print(
            f"[+] Analysed {len(user_results)} VPN users -- "
            f"{non_compliant} non-compliant"
        )

    # -- 3. Load weak config for comparison ---------------------------------
    weak_config_path = os.path.join(output_dir, "vpn_config.json")
    if os.path.isfile(weak_config_path):
        with open(weak_config_path, encoding="utf-8") as fh:
            weak_config = json.load(fh)
    else:
        print(
            f"[*] No weak config found at {weak_config_path} "
            "-- using built-in defaults."
        )
        from simulate import WEAK_VPN_CONFIG
        weak_config: dict = WEAK_VPN_CONFIG  # type: ignore[no-redef]

    # -- 4. Generate and write audit report ---------------------------------
    report = _generate_report(weak_config, user_results)

    report_path = os.path.join(output_dir, "vpn_audit_report.md")
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(report)
    print(f"[+] Generated audit report     -> {report_path}")

    # -- 5. Print report to stdout ------------------------------------------
    print()
    print(report)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Harden VPN config and generate a full audit report.",
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
