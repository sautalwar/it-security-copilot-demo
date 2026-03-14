#!/usr/bin/env python3
"""Scenario 07 -- WAF & Zero Trust: simulation script.

Creates a minimal WAF policy (everything disabled) and a flat network
segmentation configuration to demonstrate the absence of web-application
and network-layer security controls.
"""
from __future__ import annotations

import argparse
import json
import os

ROOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "infra")


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


# ---------------------------------------------------------------------------
# Insecure WAF policy
# ---------------------------------------------------------------------------

INSECURE_WAF: dict = {
    "policyName": "waf-policy-prod",
    "location": "eastus",
    "sku": "WAF_v2",
    "policySettings": {
        "state": "Disabled",
        "mode": "Detection",
        "requestBodyCheck": False,
        "maxRequestBodySizeInKb": 128,
        "fileUploadLimitInMb": 750,
    },
    "managedRules": {
        "managedRuleSets": [],
        "exclusions": [],
    },
    "customRules": [],
    "botProtection": {
        "enabled": False,
        "ruleSets": [],
    },
    "rateLimiting": {
        "enabled": False,
        "rules": [],
    },
    "geoFiltering": {
        "enabled": False,
        "blockedCountries": [],
        "allowedCountries": [],
    },
    "ipReputationFiltering": {
        "enabled": False,
    },
}

# ---------------------------------------------------------------------------
# Flat network segmentation
# ---------------------------------------------------------------------------

FLAT_NETWORK: dict = {
    "networkName": "vnet-prod",
    "addressSpace": "10.0.0.0/16",
    "subnets": [
        {
            "name": "default",
            "addressPrefix": "10.0.0.0/16",
            "nsg": None,
            "serviceEndpoints": [],
            "privateEndpoints": [],
            "delegation": None,
            "description": "Single flat subnet -- all services deployed here",
        },
    ],
    "networkSecurityGroups": [],
    "privateEndpoints": [],
    "serviceEndpoints": [],
    "microsegmentation": False,
    "ddosProtection": False,
    "bastionHost": False,
    "notes": "No tier separation; all services can communicate with all other services.",
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def simulate(output_dir: str) -> None:
    _ensure_dir(output_dir)

    # 1. WAF rules
    waf_path = os.path.join(output_dir, "waf_rules.json")
    with open(waf_path, "w", encoding="utf-8") as f:
        json.dump(INSECURE_WAF, f, indent=2)
        f.write("\n")
    print(f"[+] Created INSECURE WAF policy -> {waf_path}")

    # 2. Network segmentation
    net_path = os.path.join(output_dir, "network_segmentation.json")
    with open(net_path, "w", encoding="utf-8") as f:
        json.dump(FLAT_NETWORK, f, indent=2)
        f.write("\n")
    print(f"[+] Created FLAT network config -> {net_path}")

    # Summary
    print()
    print("=== Simulation Summary ===")
    print(f"  WAF policy        : {waf_path}")
    print(f"  Network config    : {net_path}")
    print()
    print("  WAF gaps:")
    print("    - WAF state: Disabled")
    print("    - No OWASP Core Rule Set")
    print("    - No bot protection")
    print("    - No rate limiting")
    print("    - No geo-filtering")
    print("    - No custom rules")
    print("    - No IP reputation filtering")
    print()
    print("  Network gaps:")
    print("    - Single flat /16 subnet for all services")
    print("    - No NSGs between tiers")
    print("    - No microsegmentation")
    print("    - No service endpoints or private endpoints")
    print("    - No DDoS protection")
    print("    - No Bastion host")
    print()
    print("[!] Applications are unprotected.  Run remediate.py to fix.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulate minimal WAF and flat network configurations.",
    )
    parser.add_argument(
        "--output-dir",
        default=ROOT_DIR,
        help="Directory to write config files into (default: infra/).",
    )
    args = parser.parse_args()
    simulate(args.output_dir)


if __name__ == "__main__":
    main()
