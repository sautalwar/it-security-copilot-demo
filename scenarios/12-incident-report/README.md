# Scenario 12 — Incident Report

## Overview

Generate a comprehensive **executive incident report** from raw incident
artifacts — timeline, IOCs, affected systems, remediation log, and
communications.  In a real incident the data is messy and scattered; this
scenario shows how to organize it into a structured, board-ready report.

## What the simulation plants

| Artifact | Content |
|---|---|
| `vulnerable-app/incident_data/timeline_raw.json` | Unstructured timeline events from the entire day |
| `vulnerable-app/incident_data/iocs_collected.json` | All IOCs found during investigation |
| `vulnerable-app/incident_data/affected_systems.json` | Systems touched by the attacker |
| `vulnerable-app/incident_data/remediation_log.json` | Actions taken and when |
| `vulnerable-app/incident_data/communication_log.json` | Stakeholder communications |

## What the remediation creates

| Artifact | Content |
|---|---|
| `vulnerable-app/incident_report.md` | Full incident report (exec summary, timeline, MITRE ATT&CK, impact, lessons learned, appendices) |
| `vulnerable-app/executive_summary.md` | 1-page C-suite summary |
| `vulnerable-app/board_presentation.json` | Key metrics for board report |

## Usage

```bash
python simulate.py --base-dir ../../
python remediate.py --base-dir ../../
```

## Learning objectives

1. Structure raw incident data into an executive-ready report.
2. Map attacker activity to the MITRE ATT&CK framework.
3. Produce tiered communications (technical team vs. executives vs. board).
