# Scenario 02 — KQL Investigation

## Overview

After the DNS exfiltration alert (Scenario 01), we use **SIEM queries**
(Kusto Query Language for Microsoft Sentinel) to investigate the incident and
correlate it with other suspicious activity across the environment.

## Investigation Goals

1. Identify all hosts that communicated with the C2 domain.
2. Correlate DNS events with authentication failures and network flows.
3. Detect data exfiltration via large outbound transfers.
4. Build a timeline of the attack.

## What the Simulation Does (`simulate.py`)

1. Creates `vulnerable-app/siem_config.json` — a **weak** Sentinel
   configuration:
   - Only basic Windows event logs enabled
   - No DNS analytics connector
   - No network security group flow logs
   - Alert rule thresholds too high (miss real attacks)
   - No automated investigation playbooks
   - Retention period only 30 days
2. Creates `vulnerable-app/sample_logs/` with correlated sample data:
   - `dns_events.json` — DNS queries with suspicious patterns
   - `auth_events.json` — failed logins from the same IP
   - `network_flows.json` — large outbound data transfers

## What the Remediation Does (`remediate.py`)

1. Generates proper KQL detection queries in
   `vulnerable-app/sentinel_queries/`:
   - `dns_tunneling_detection.kql` — high-entropy subdomain detection
   - `correlated_threat_hunt.kql` — cross-table correlation
   - `data_exfil_detection.kql` — outbound transfer anomalies
2. Updates `vulnerable-app/siem_config.json` with hardened settings.
3. Generates an investigation report.

## Usage

```bash
python scenarios/02-kql-investigation/simulate.py
python scenarios/02-kql-investigation/remediate.py
```
