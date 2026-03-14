#!/usr/bin/env python3
"""Scenario 03 – Firewall Containment: simulation script.

Creates deliberately weak firewall rules (JSON) and an overly permissive
Azure NSG (Bicep) to demonstrate a poorly defended network perimeter.
"""
from __future__ import annotations

import argparse
import json
import os
import textwrap

ROOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
VULN_DIR = os.path.join(ROOT_DIR, "vulnerable-app")
INFRA_DIR = os.path.join(ROOT_DIR, "infra")


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


# ---------------------------------------------------------------------------
# Weak firewall rules
# ---------------------------------------------------------------------------

WEAK_FIREWALL_RULES: dict = {
    "firewallPolicy": {
        "name": "CorpFirewall",
        "defaultAction": "Allow",  # default ALLOW — bad
    },
    "rules": [
        {
            "name": "AllowAllOutbound",
            "priority": 100,
            "direction": "Outbound",
            "action": "Allow",
            "protocol": "*",
            "sourceAddress": "10.0.0.0/8",
            "destinationAddress": "*",
            "destinationPort": "*",
            "description": "Allow all outbound traffic — no restrictions.",
        },
        {
            "name": "AllowDNSOutbound",
            "priority": 200,
            "direction": "Outbound",
            "action": "Allow",
            "protocol": "UDP",
            "sourceAddress": "*",
            "destinationAddress": "*",
            "destinationPort": "53",
            "description": "Allow DNS to anywhere — no resolver restriction.",
        },
        {
            "name": "AllowSSHFromAnywhere",
            "priority": 300,
            "direction": "Inbound",
            "action": "Allow",
            "protocol": "TCP",
            "sourceAddress": "0.0.0.0/0",
            "destinationAddress": "*",
            "destinationPort": "22",
            "description": "SSH open to the world — no source restriction.",
        },
        {
            "name": "AllowRDPFromAnywhere",
            "priority": 310,
            "direction": "Inbound",
            "action": "Allow",
            "protocol": "TCP",
            "sourceAddress": "0.0.0.0/0",
            "destinationAddress": "*",
            "destinationPort": "3389",
            "description": "RDP open to the world — no source restriction.",
        },
        {
            "name": "AllowHTTPSOutbound",
            "priority": 400,
            "direction": "Outbound",
            "action": "Allow",
            "protocol": "TCP",
            "sourceAddress": "*",
            "destinationAddress": "*",
            "destinationPort": "443",
            "description": "HTTPS to anywhere — no destination filtering.",
        },
    ],
    "idsIpsRules": [],  # no IDS/IPS
    "networkSegmentation": [],  # no segmentation
}

# ---------------------------------------------------------------------------
# Weak Azure NSG (Bicep)
# ---------------------------------------------------------------------------

WEAK_NSG_BICEP = textwrap.dedent("""\
    // nsg_rules.bicep — INSECURE Network Security Group
    // WARNING: Intentionally overly permissive for demonstration.

    param location string = resourceGroup().location
    param nsgName string = 'insecure-nsg'

    resource nsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
      name: nsgName
      location: location
      properties: {
        securityRules: [
          {
            name: 'AllowAllInbound'
            properties: {
              priority: 100
              direction: 'Inbound'
              access: 'Allow'
              protocol: '*'
              sourceAddressPrefix: '*'
              sourcePortRange: '*'
              destinationAddressPrefix: '*'
              destinationPortRange: '*'
              description: 'Allow ALL inbound — extremely dangerous.'
            }
          }
          {
            name: 'AllowAllOutbound'
            properties: {
              priority: 100
              direction: 'Outbound'
              access: 'Allow'
              protocol: '*'
              sourceAddressPrefix: '*'
              sourcePortRange: '*'
              destinationAddressPrefix: '*'
              destinationPortRange: '*'
              description: 'Allow ALL outbound — no egress filtering.'
            }
          }
          {
            name: 'AllowSSH'
            properties: {
              priority: 200
              direction: 'Inbound'
              access: 'Allow'
              protocol: 'Tcp'
              sourceAddressPrefix: '0.0.0.0/0'
              sourcePortRange: '*'
              destinationAddressPrefix: '*'
              destinationPortRange: '22'
              description: 'SSH from anywhere.'
            }
          }
        ]
      }
    }
""")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def simulate(vuln_dir: str, infra_dir: str) -> None:
    _ensure_dir(vuln_dir)
    _ensure_dir(infra_dir)

    # Weak firewall rules
    fw_path = os.path.join(vuln_dir, "firewall_rules.json")
    with open(fw_path, "w", encoding="utf-8") as f:
        json.dump(WEAK_FIREWALL_RULES, f, indent=2)
    print(f"[+] Created WEAK firewall rules → {fw_path}")

    # Weak NSG Bicep
    nsg_path = os.path.join(infra_dir, "nsg_rules.bicep")
    with open(nsg_path, "w", encoding="utf-8") as f:
        f.write(WEAK_NSG_BICEP)
    print(f"[+] Created WEAK Azure NSG (Bicep) → {nsg_path}")

    print()
    print("=== Simulation Summary ===")
    print(f"  Firewall rules (WEAK) : {fw_path}")
    print(f"  NSG Bicep (WEAK)      : {nsg_path}")
    print()
    print("[!] The firewall defaults to ALLOW all outbound traffic.")
    print("[!] SSH and RDP are open to 0.0.0.0/0.")
    print("[!] No IDS/IPS rules.  No network segmentation.")
    print("    Run remediate.py to generate hardened configurations.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulate weak firewall rules and an overly permissive Azure NSG.",
    )
    parser.add_argument(
        "--vuln-dir",
        default=VULN_DIR,
        help="Directory for vulnerable-app files (default: vulnerable-app/).",
    )
    parser.add_argument(
        "--infra-dir",
        default=INFRA_DIR,
        help="Directory for infrastructure files (default: infra/).",
    )
    args = parser.parse_args()
    simulate(args.vuln_dir, args.infra_dir)


if __name__ == "__main__":
    main()
