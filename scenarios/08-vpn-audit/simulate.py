#!/usr/bin/env python3
"""Scenario 08 -- Simulate: generate an insecure VPN gateway configuration
and a user roster with mixed compliance issues for audit testing."""
from __future__ import annotations

import argparse
import datetime
import json
import os

ROOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "vulnerable-app")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


# ---------------------------------------------------------------------------
# Weak VPN gateway configuration
# ---------------------------------------------------------------------------

WEAK_VPN_CONFIG: dict = {
    "vpn_gateway": {
        "name": "corp-vpn-gw-01",
        "vendor": "Generic",
        "firmware_version": "4.2.1",
        "management_ip": "10.0.0.1",
        "public_ip": "203.0.113.10",
    },
    "ike": {
        "version": "IKEv1",
        "phase1": {
            "encryption": "DES",
            "hash": "MD5",
            "dh_group": 1,
            "lifetime_seconds": 86400,
            "authentication_method": "pre-shared-key",
            "pre_shared_key": "password123",
        },
        "phase2": {
            "encryption": "DES",
            "hash": "MD5",
            "pfs_enabled": False,
            "pfs_group": None,
            "lifetime_seconds": 28800,
        },
    },
    "tunnel": {
        "mode": "tunnel",
        "encapsulation": "ESP",
        "nat_traversal": True,
        "dead_peer_detection": {
            "enabled": False,
            "interval_seconds": 0,
            "retries": 0,
        },
    },
    "authentication": {
        "type": "pre-shared-key",
        "certificate_auth_required": False,
        "certificate_authority": None,
        "mfa": {
            "enabled": False,
            "provider": None,
        },
        "re_authenticate_on_reconnect": False,
    },
    "split_tunneling": {
        "enabled": True,
        "mode": "unrestricted",
        "allowed_subnets": [],
        "dns_split": False,
    },
    "session": {
        "timeout_hours": 24,
        "max_concurrent_sessions_per_user": 0,
        "idle_timeout_minutes": 0,
    },
    "logging": {
        "enabled": False,
        "log_level": "none",
        "syslog_server": None,
        "log_auth_events": False,
        "log_tunnel_events": False,
    },
    "client_policy": {
        "enforce_posture_check": False,
        "minimum_client_version": None,
        "allowed_os": [],
        "deny_jailbroken_devices": False,
    },
}


# ---------------------------------------------------------------------------
# VPN user roster -- mix of compliant and non-compliant accounts
# ---------------------------------------------------------------------------

def _vpn_users() -> list[dict]:
    """Build user roster with dates relative to today so the mix of
    compliant / non-compliant users stays realistic regardless of when
    the simulation is run."""
    today = datetime.date.today()
    future_1y = (today + datetime.timedelta(days=365)).isoformat()
    future_6m = (today + datetime.timedelta(days=180)).isoformat()
    past_1y = (today - datetime.timedelta(days=365)).isoformat()
    past_6m = (today - datetime.timedelta(days=180)).isoformat()
    past_2y = (today - datetime.timedelta(days=730)).isoformat()
    recent_1d = (today - datetime.timedelta(days=1)).isoformat()
    recent_3d = (today - datetime.timedelta(days=3)).isoformat()
    recent_7d = (today - datetime.timedelta(days=7)).isoformat()
    stale_120d = (today - datetime.timedelta(days=120)).isoformat()
    stale_200d = (today - datetime.timedelta(days=200)).isoformat()
    stale_300d = (today - datetime.timedelta(days=300)).isoformat()

    return [
        {
            "username": "jsmith",
            "full_name": "John Smith",
            "email": "jsmith@contoso.com",
            "role": "engineer",
            "enabled": True,
            "mfa_enrolled": True,
            "certificate_expiry": future_1y,
            "last_login": recent_1d,
            "assigned_ip": "10.8.0.10",
        },
        {
            "username": "ajones",
            "full_name": "Alice Jones",
            "email": "ajones@contoso.com",
            "role": "manager",
            "enabled": True,
            "mfa_enrolled": False,
            "certificate_expiry": past_1y,
            "last_login": recent_3d,
            "assigned_ip": "10.8.0.11",
        },
        {
            "username": "bwilliams",
            "full_name": "Bob Williams",
            "email": "bwilliams@contoso.com",
            "role": "analyst",
            "enabled": True,
            "mfa_enrolled": False,
            "certificate_expiry": past_2y,
            "last_login": stale_200d,
            "assigned_ip": "10.8.0.12",
        },
        {
            "username": "cdavis",
            "full_name": "Carol Davis",
            "email": "cdavis@contoso.com",
            "role": "developer",
            "enabled": True,
            "mfa_enrolled": True,
            "certificate_expiry": future_6m,
            "last_login": recent_1d,
            "assigned_ip": "10.8.0.13",
        },
        {
            "username": "dmiller",
            "full_name": "David Miller",
            "email": "dmiller@contoso.com",
            "role": "contractor",
            "enabled": True,
            "mfa_enrolled": False,
            "certificate_expiry": past_6m,
            "last_login": stale_300d,
            "assigned_ip": "10.8.0.14",
        },
        {
            "username": "egarcia",
            "full_name": "Elena Garcia",
            "email": "egarcia@contoso.com",
            "role": "sysadmin",
            "enabled": True,
            "mfa_enrolled": True,
            "certificate_expiry": future_1y,
            "last_login": recent_3d,
            "assigned_ip": "10.8.0.15",
        },
        {
            "username": "flee",
            "full_name": "Frank Lee",
            "email": "flee@contoso.com",
            "role": "intern",
            "enabled": True,
            "mfa_enrolled": False,
            "certificate_expiry": past_1y,
            "last_login": stale_120d,
            "assigned_ip": "10.8.0.16",
        },
        {
            "username": "gmartin",
            "full_name": "Grace Martin",
            "email": "gmartin@contoso.com",
            "role": "engineer",
            "enabled": True,
            "mfa_enrolled": True,
            "certificate_expiry": future_6m,
            "last_login": recent_7d,
            "assigned_ip": "10.8.0.17",
        },
        {
            "username": "hthompson",
            "full_name": "Henry Thompson",
            "email": "hthompson@contoso.com",
            "role": "analyst",
            "enabled": True,
            "mfa_enrolled": False,
            "certificate_expiry": past_2y,
            "last_login": stale_300d,
            "assigned_ip": "10.8.0.18",
        },
        {
            "username": "iwhite",
            "full_name": "Irene White",
            "email": "iwhite@contoso.com",
            "role": "director",
            "enabled": True,
            "mfa_enrolled": True,
            "certificate_expiry": future_1y,
            "last_login": recent_1d,
            "assigned_ip": "10.8.0.19",
        },
    ]


# ---------------------------------------------------------------------------
# Simulation entry point
# ---------------------------------------------------------------------------

def simulate(output_dir: str) -> None:
    """Write insecure VPN configuration and user roster to *output_dir*."""
    _ensure_dir(output_dir)

    vpn_users = _vpn_users()

    # --- VPN gateway config ------------------------------------------------
    config_path = os.path.join(output_dir, "vpn_config.json")
    with open(config_path, "w", encoding="utf-8") as fh:
        json.dump(WEAK_VPN_CONFIG, fh, indent=2)
    print(f"[+] Created insecure VPN config -> {config_path}")

    # --- VPN user roster ---------------------------------------------------
    users_path = os.path.join(output_dir, "vpn_users.json")
    with open(users_path, "w", encoding="utf-8") as fh:
        json.dump({"vpn_users": vpn_users}, fh, indent=2)
    print(f"[+] Created VPN user roster    -> {users_path}")

    # --- Summary -----------------------------------------------------------
    today = datetime.date.today().isoformat()
    cutoff = (datetime.date.today() - datetime.timedelta(days=90)).isoformat()
    expired = sum(1 for u in vpn_users if u["certificate_expiry"] < today)
    no_mfa = sum(1 for u in vpn_users if not u["mfa_enrolled"])
    inactive = sum(1 for u in vpn_users if u["last_login"] < cutoff)

    print()
    print("[!] Simulation summary:")
    print(f"    Total VPN users             : {len(vpn_users)}")
    print(f"    Expired certificates        : {expired}")
    print(f"    MFA not enrolled            : {no_mfa}")
    print(f"    Inactive >90 days           : {inactive}")
    print(f"    IKE version                 : {WEAK_VPN_CONFIG['ike']['version']}")
    print(f"    Encryption algorithm        : {WEAK_VPN_CONFIG['ike']['phase1']['encryption']}")
    print(f"    Hash algorithm              : {WEAK_VPN_CONFIG['ike']['phase1']['hash']}")
    print(f"    DH Group                    : {WEAK_VPN_CONFIG['ike']['phase1']['dh_group']}")
    print(f"    Pre-shared key              : {WEAK_VPN_CONFIG['ike']['phase1']['pre_shared_key']}")
    print(f"    Split tunnelling            : {WEAK_VPN_CONFIG['split_tunneling']['mode']}")
    print(f"    Certificate auth required   : {WEAK_VPN_CONFIG['authentication']['certificate_auth_required']}")
    print(f"    MFA enabled                 : {WEAK_VPN_CONFIG['authentication']['mfa']['enabled']}")
    print(f"    Perfect Forward Secrecy     : {WEAK_VPN_CONFIG['ike']['phase2']['pfs_enabled']}")
    print(f"    Dead Peer Detection         : {WEAK_VPN_CONFIG['tunnel']['dead_peer_detection']['enabled']}")
    print(f"    Logging enabled             : {WEAK_VPN_CONFIG['logging']['enabled']}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulate an insecure VPN gateway and user roster for audit testing.",
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
