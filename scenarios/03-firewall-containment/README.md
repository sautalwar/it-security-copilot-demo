# Scenario 03 — Firewall Containment

## Overview

After identifying the DNS exfiltration attack and investigating in the SIEM,
**emergency firewall rules** are deployed to contain the threat:

- Block C2 domains and IP ranges
- Restrict outbound DNS to approved resolvers only
- Isolate the compromised host
- Harden network segmentation

## What the Simulation Does (`simulate.py`)

1. Creates `vulnerable-app/firewall_rules.json` with **weak** rules:
   - Default **allow** outbound on all ports
   - No DNS traffic filtering (port 53 wide open outbound)
   - No egress filtering
   - Overly permissive SSH (0.0.0.0/0 → port 22)
   - No network segmentation rules
   - No IDS/IPS rules
2. Creates `infra/nsg_rules.bicep` with an Azure NSG that has overly
   permissive rules.

## What the Remediation Does (`remediate.py`)

1. Generates `vulnerable-app/firewall_rules_hardened.json`:
   - Default **deny** outbound
   - DNS only to approved resolvers (e.g., 8.8.8.8, 1.1.1.1)
   - Block known C2 IP ranges
   - SSH restricted to bastion subnet
   - Egress filtering (443/80 to known endpoints only)
   - IDS/IPS signatures for DNS tunneling
2. Generates `infra/nsg_rules_hardened.bicep` with proper Azure NSG rules.
3. Creates `vulnerable-app/containment_iptables.sh` — a Linux iptables script
   for emergency host-level containment.

## Usage

```bash
python scenarios/03-firewall-containment/simulate.py
python scenarios/03-firewall-containment/remediate.py
```
