#!/usr/bin/env python3
"""Scenario 03 – Firewall Containment: remediation script.

Generates hardened firewall rules, a hardened Azure NSG Bicep template,
and a Linux iptables containment script.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import textwrap

ROOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
VULN_DIR = os.path.join(ROOT_DIR, "vulnerable-app")
INFRA_DIR = os.path.join(ROOT_DIR, "infra")

C2_IP_RANGES: list[str] = [
    "203.0.113.0/24",
    "198.51.100.0/24",
]
C2_DOMAINS: list[str] = [
    "evil-c2.example.com",
    "malware-drop.example.net",
    "c2-callback.example.org",
]
APPROVED_DNS_RESOLVERS: list[str] = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]
BASTION_SUBNET = "10.0.255.0/24"
COMPROMISED_HOST = "10.0.1.15"


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


# ---------------------------------------------------------------------------
# Hardened firewall rules
# ---------------------------------------------------------------------------

HARDENED_FIREWALL_RULES: dict = {
    "firewallPolicy": {
        "name": "CorpFirewall",
        "defaultAction": "Deny",
    },
    "rules": [
        {
            "name": "AllowDNSToApprovedResolvers",
            "priority": 100,
            "direction": "Outbound",
            "action": "Allow",
            "protocol": "UDP",
            "sourceAddress": "10.0.0.0/8",
            "destinationAddress": ", ".join(APPROVED_DNS_RESOLVERS),
            "destinationPort": "53",
            "description": "DNS only to approved resolvers.",
        },
        {
            "name": "BlockC2IPRanges",
            "priority": 150,
            "direction": "Outbound",
            "action": "Deny",
            "protocol": "*",
            "sourceAddress": "*",
            "destinationAddress": ", ".join(C2_IP_RANGES),
            "destinationPort": "*",
            "description": "Block known C2 IP ranges.",
        },
        {
            "name": "IsolateCompromisedHost",
            "priority": 160,
            "direction": "Outbound",
            "action": "Deny",
            "protocol": "*",
            "sourceAddress": COMPROMISED_HOST,
            "destinationAddress": "*",
            "destinationPort": "*",
            "description": "Isolate compromised host from outbound traffic.",
        },
        {
            "name": "AllowHTTPSToKnownEndpoints",
            "priority": 200,
            "direction": "Outbound",
            "action": "Allow",
            "protocol": "TCP",
            "sourceAddress": "10.0.0.0/8",
            "destinationAddress": "AzureCloud",
            "destinationPort": "443",
            "description": "HTTPS only to Azure and approved endpoints.",
        },
        {
            "name": "AllowHTTPToKnownEndpoints",
            "priority": 210,
            "direction": "Outbound",
            "action": "Allow",
            "protocol": "TCP",
            "sourceAddress": "10.0.0.0/8",
            "destinationAddress": "AzureCloud",
            "destinationPort": "80",
            "description": "HTTP only to Azure and approved endpoints.",
        },
        {
            "name": "AllowSSHFromBastion",
            "priority": 300,
            "direction": "Inbound",
            "action": "Allow",
            "protocol": "TCP",
            "sourceAddress": BASTION_SUBNET,
            "destinationAddress": "10.0.0.0/8",
            "destinationPort": "22",
            "description": "SSH only from bastion subnet.",
        },
        {
            "name": "DenySSHFromAnywhere",
            "priority": 310,
            "direction": "Inbound",
            "action": "Deny",
            "protocol": "TCP",
            "sourceAddress": "*",
            "destinationAddress": "*",
            "destinationPort": "22",
            "description": "Block SSH from all other sources.",
        },
        {
            "name": "DenyRDPFromAnywhere",
            "priority": 320,
            "direction": "Inbound",
            "action": "Deny",
            "protocol": "TCP",
            "sourceAddress": "*",
            "destinationAddress": "*",
            "destinationPort": "3389",
            "description": "Block RDP from all sources (use bastion).",
        },
        {
            "name": "DenyAllOutbound",
            "priority": 4096,
            "direction": "Outbound",
            "action": "Deny",
            "protocol": "*",
            "sourceAddress": "*",
            "destinationAddress": "*",
            "destinationPort": "*",
            "description": "Default deny all outbound.",
        },
    ],
    "idsIpsRules": [
        {
            "name": "DNSTunnelingSignature",
            "signature": "dns_query_length > 50 AND dns_query_entropy > 3.5",
            "action": "Alert+Block",
            "severity": "High",
        },
        {
            "name": "LargeOutboundTransfer",
            "signature": "outbound_bytes > 1000000 AND duration < 60",
            "action": "Alert",
            "severity": "Medium",
        },
    ],
    "networkSegmentation": [
        {
            "name": "IsolateServers",
            "from": "10.0.1.0/24",
            "to": "10.0.2.0/24",
            "action": "Deny",
            "exceptions": ["TCP/443", "TCP/80"],
        },
        {
            "name": "ManagementAccess",
            "from": BASTION_SUBNET,
            "to": "10.0.0.0/8",
            "action": "Allow",
            "protocols": ["TCP/22", "TCP/3389"],
        },
    ],
}

# ---------------------------------------------------------------------------
# Hardened Azure NSG (Bicep)
# ---------------------------------------------------------------------------

HARDENED_NSG_BICEP = textwrap.dedent("""\
    // nsg_rules_hardened.bicep — HARDENED Network Security Group
    // Implements least-privilege network access controls.

    param location string = resourceGroup().location
    param nsgName string = 'hardened-nsg'
    param bastionSubnet string = '10.0.255.0/24'

    var c2BlockRanges = [
      '203.0.113.0/24'
      '198.51.100.0/24'
    ]

    var approvedDnsResolvers = [
      '8.8.8.8'
      '8.8.4.4'
      '1.1.1.1'
      '1.0.0.1'
    ]

    resource nsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
      name: nsgName
      location: location
      properties: {
        securityRules: [
          // --- Inbound rules ---
          {
            name: 'AllowSSHFromBastion'
            properties: {
              priority: 100
              direction: 'Inbound'
              access: 'Allow'
              protocol: 'Tcp'
              sourceAddressPrefix: bastionSubnet
              sourcePortRange: '*'
              destinationAddressPrefix: 'VirtualNetwork'
              destinationPortRange: '22'
              description: 'SSH from bastion subnet only.'
            }
          }
          {
            name: 'DenySSHFromAll'
            properties: {
              priority: 110
              direction: 'Inbound'
              access: 'Deny'
              protocol: 'Tcp'
              sourceAddressPrefix: '*'
              sourcePortRange: '*'
              destinationAddressPrefix: '*'
              destinationPortRange: '22'
              description: 'Block SSH from all other sources.'
            }
          }
          {
            name: 'DenyRDPFromAll'
            properties: {
              priority: 120
              direction: 'Inbound'
              access: 'Deny'
              protocol: 'Tcp'
              sourceAddressPrefix: '*'
              sourcePortRange: '*'
              destinationAddressPrefix: '*'
              destinationPortRange: '3389'
              description: 'Block RDP from all sources.'
            }
          }
          {
            name: 'AllowHTTPSInbound'
            properties: {
              priority: 200
              direction: 'Inbound'
              access: 'Allow'
              protocol: 'Tcp'
              sourceAddressPrefix: 'Internet'
              sourcePortRange: '*'
              destinationAddressPrefix: 'VirtualNetwork'
              destinationPortRange: '443'
              description: 'Allow inbound HTTPS.'
            }
          }
          // --- Outbound rules ---
          {
            name: 'AllowDNSToApproved'
            properties: {
              priority: 100
              direction: 'Outbound'
              access: 'Allow'
              protocol: 'Udp'
              sourceAddressPrefix: 'VirtualNetwork'
              sourcePortRange: '*'
              destinationAddressPrefixes: approvedDnsResolvers
              destinationPortRange: '53'
              description: 'DNS to approved resolvers only.'
            }
          }
          {
            name: 'DenyDNSToAll'
            properties: {
              priority: 110
              direction: 'Outbound'
              access: 'Deny'
              protocol: 'Udp'
              sourceAddressPrefix: '*'
              sourcePortRange: '*'
              destinationAddressPrefix: '*'
              destinationPortRange: '53'
              description: 'Block DNS to unapproved resolvers.'
            }
          }
          {
            name: 'BlockC2Ranges'
            properties: {
              priority: 150
              direction: 'Outbound'
              access: 'Deny'
              protocol: '*'
              sourceAddressPrefix: '*'
              sourcePortRange: '*'
              destinationAddressPrefixes: c2BlockRanges
              destinationPortRange: '*'
              description: 'Block traffic to known C2 IP ranges.'
            }
          }
          {
            name: 'AllowHTTPSOutbound'
            properties: {
              priority: 200
              direction: 'Outbound'
              access: 'Allow'
              protocol: 'Tcp'
              sourceAddressPrefix: 'VirtualNetwork'
              sourcePortRange: '*'
              destinationAddressPrefix: 'AzureCloud'
              destinationPortRange: '443'
              description: 'HTTPS to Azure services.'
            }
          }
          {
            name: 'DenyAllOutbound'
            properties: {
              priority: 4096
              direction: 'Outbound'
              access: 'Deny'
              protocol: '*'
              sourceAddressPrefix: '*'
              sourcePortRange: '*'
              destinationAddressPrefix: '*'
              destinationPortRange: '*'
              description: 'Default deny all outbound.'
            }
          }
        ]
      }
    }
""")

# ---------------------------------------------------------------------------
# iptables containment script
# ---------------------------------------------------------------------------

CONTAINMENT_IPTABLES = textwrap.dedent("""\
    #!/usr/bin/env bash
    # containment_iptables.sh — Emergency host-level containment rules
    # Generated: {timestamp}
    #
    # Deploy on compromised host (10.0.1.15) to immediately restrict traffic
    # while forensic investigation proceeds.

    set -euo pipefail

    echo "[*] Applying emergency containment iptables rules..."

    # Flush existing rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t mangle -F

    # Default policies: DROP everything
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP

    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow established/related connections (for forensic tools)
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow SSH from bastion subnet only (for forensic access)
    iptables -A INPUT -p tcp -s 10.0.255.0/24 --dport 22 -j ACCEPT
    iptables -A OUTPUT -p tcp -d 10.0.255.0/24 --sport 22 -j ACCEPT

    # Allow DNS to approved resolvers only
    iptables -A OUTPUT -p udp -d 8.8.8.8 --dport 53 -j ACCEPT
    iptables -A OUTPUT -p udp -d 8.8.4.4 --dport 53 -j ACCEPT
    iptables -A OUTPUT -p udp -d 1.1.1.1 --dport 53 -j ACCEPT
    iptables -A OUTPUT -p udp -d 1.0.0.1 --dport 53 -j ACCEPT

    # Block known C2 IP ranges explicitly
    iptables -A OUTPUT -d 203.0.113.0/24 -j DROP
    iptables -A OUTPUT -d 198.51.100.0/24 -j DROP

    # Log all dropped packets for forensics
    iptables -A INPUT -j LOG --log-prefix "CONTAINMENT-DROP-IN: " --log-level 4
    iptables -A OUTPUT -j LOG --log-prefix "CONTAINMENT-DROP-OUT: " --log-level 4

    # Final DROP (redundant with policy but explicit)
    iptables -A INPUT -j DROP
    iptables -A OUTPUT -j DROP

    echo "[+] Containment rules applied."
    echo "[+] Only bastion SSH and approved DNS are permitted."
    echo "[+] All dropped packets are being logged to syslog."
""")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def remediate(vuln_dir: str, infra_dir: str) -> None:
    _ensure_dir(vuln_dir)
    _ensure_dir(infra_dir)

    ts = datetime.datetime.utcnow().isoformat() + "Z"

    # 1. Hardened firewall rules
    fw_path = os.path.join(vuln_dir, "firewall_rules_hardened.json")
    with open(fw_path, "w", encoding="utf-8") as f:
        json.dump(HARDENED_FIREWALL_RULES, f, indent=2)
    print(f"[+] Generated hardened firewall rules → {fw_path}")

    # 2. Hardened NSG Bicep
    nsg_path = os.path.join(infra_dir, "nsg_rules_hardened.bicep")
    with open(nsg_path, "w", encoding="utf-8") as f:
        f.write(HARDENED_NSG_BICEP)
    print(f"[+] Generated hardened NSG (Bicep) → {nsg_path}")

    # 3. iptables containment script
    ipt_path = os.path.join(vuln_dir, "containment_iptables.sh")
    with open(ipt_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(CONTAINMENT_IPTABLES.format(timestamp=ts))
    print(f"[+] Generated iptables containment script → {ipt_path}")

    # Summary
    print()
    print("=== Containment Summary ===")
    print(f"  Hardened firewall rules : {fw_path}")
    print(f"  Hardened NSG Bicep      : {nsg_path}")
    print(f"  iptables script         : {ipt_path}")
    print()
    print("Key changes from weak → hardened:")
    print("  • Default outbound: Allow → Deny")
    print("  • DNS: any resolver → approved resolvers only")
    print("  • SSH: 0.0.0.0/0 → bastion subnet only")
    print("  • C2 IPs: no block → explicit deny")
    print("  • IDS/IPS: none → DNS tunneling + exfil signatures")
    print("  • Segmentation: none → subnet isolation with exceptions")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate hardened firewall rules, NSG Bicep, and iptables containment.",
    )
    parser.add_argument(
        "--vuln-dir",
        default=VULN_DIR,
        help="Directory for vulnerable-app files (default: vulnerable-app/).",
    )
    parser.add_argument(
        "--infra-dir",
        default=INFRA_DIR,
        help="Directory for infra files (default: infra/).",
    )
    args = parser.parse_args()
    remediate(args.vuln_dir, args.infra_dir)


if __name__ == "__main__":
    main()
