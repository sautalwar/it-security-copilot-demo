# Scenario 10 — Network Compliance

## Overview

Continuous compliance monitoring for network infrastructure against industry
benchmarks — **CIS**, **NIST 800-53**, and **PCI-DSS**.  Without ongoing
monitoring, network devices drift from their hardened baselines: default
credentials survive, insecure protocols stay enabled, and stale firewall rules
accumulate.

## What the simulation plants

| Artifact | Problem |
|---|---|
| `vulnerable-app/network_inventory.json` | Network devices with default creds, telnet, SNMPv2 "public", no NTP |
| `vulnerable-app/compliance_status.json` | Compliance results showing failures across CIS, NIST, PCI-DSS |

## What the remediation creates

| Artifact | Improvement |
|---|---|
| `vulnerable-app/network_inventory_compliant.json` | Hardened network inventory |
| `vulnerable-app/harden_switches.py` | Cisco IOS switch-hardening commands |
| `vulnerable-app/harden_routers.py` | Router-hardening commands |
| `vulnerable-app/compliance_report.md` | Full compliance report with before/after |
| `vulnerable-app/compliance_dashboard.json` | Pass / fail metrics dashboard |

## Usage

```bash
python simulate.py --base-dir ../../
python remediate.py --base-dir ../../
```

## Learning objectives

1. Map network controls to CIS, NIST 800-53, and PCI-DSS requirements.
2. Automate device hardening with scripted configuration changes.
3. Track compliance posture over time with dashboards.
