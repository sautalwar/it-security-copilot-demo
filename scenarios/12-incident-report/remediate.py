#!/usr/bin/env python3
"""Scenario 12 – Incident Report: generate comprehensive incident report from raw data."""
from __future__ import annotations

import argparse
import json
import textwrap
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Full incident report (Markdown)
# ---------------------------------------------------------------------------

def _incident_report_md() -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return textwrap.dedent(f"""\
        # Incident Report — IR-2024-1115-001

        **Classification:** Confidential  
        **Prepared by:** Security Operations Center  
        **Date:** {now}  
        **Status:** Active — Remediation In Progress

        ---

        ## 1. Executive Summary

        On November 15, 2024, the Security Operations Center (SOC) detected an active
        data exfiltration incident originating from a phishing email targeting the
        Finance department.  An employee opened a malicious Word document, which
        executed a PowerShell reverse shell granting the attacker access to the
        corporate network.  The attacker performed credential harvesting, moved
        laterally to the database server, and exfiltrated approximately 500,000
        customer records (2.3 GB) to an external command-and-control server.

        Containment was achieved within 75 minutes of initial detection.  All
        compromised systems have been isolated or reimaged.  A full password reset was
        completed for the affected department, and perimeter defenses have been updated
        to block the attacker's infrastructure.  Legal counsel has been engaged, and a
        customer notification is under review.

        ## 2. Incident Classification

        | Field | Value |
        |-------|-------|
        | **Incident ID** | IR-2024-1115-001 |
        | **Severity** | P1 — Critical |
        | **Category** | Data Breach / Exfiltration |
        | **MITRE ATT&CK Tactics** | Initial Access, Execution, Credential Access, Lateral Movement, Exfiltration |
        | **MITRE ATT&CK Techniques** | T1566.001 (Spearphishing Attachment), T1059.001 (PowerShell), T1003.001 (LSASS Memory), T1021.002 (SMB/Windows Admin Shares), T1041 (Exfiltration Over C2), T1071.004 (DNS) |
        | **Detection Time** | 2024-11-15 09:50 UTC |
        | **Containment Time** | 2024-11-15 11:00 UTC |
        | **Time to Contain** | 75 minutes |

        ## 3. Timeline

        | Time (UTC) | Source | Event |
        |------------|--------|-------|
        | 09:15 | Email Gateway | Phishing email delivered to finance-team@corp.com |
        | 09:22 | Endpoint EDR | User john.doe clicked malicious link |
        | 09:23 | Endpoint EDR | Malicious macro executed in Word document |
        | 09:24 | Endpoint EDR | PowerShell reverse shell to 203.0.113.42 |
        | 09:30 | SIEM | Anomalous LDAP queries from WKSTN-FIN-042 |
        | 09:35 | Active Directory | Credential dumping (LSASS memory access) |
        | 09:40 | Network IDS | Lateral movement via SMB to SRV-DB-01 |
        | 09:42 | Database | Bulk SELECT on customers table (500K rows) |
        | 09:45 | Network IDS | 2.3 GB data transfer to 203.0.113.42 |
        | 09:48 | Firewall | DNS exfiltration to evil.example.com |
        | 09:50 | SOC Analyst | Alert triaged — P1 declared |
        | 09:55 | SOC | Incident commander assigned (CISO) |
        | 10:00 | SOC | WKSTN-FIN-042 isolated |
        | 10:05 | Firewall | C2 IP blocked |
        | 10:10 | IAM | Password reset for john.doe |
        | 10:30 | IAM | VPN access revoked |
        | 11:00 | IT Ops | SRV-DB-01 isolated |
        | 13:00 | DFIR | Forensic images captured |
        | 15:00 | IT Ops | WKSTN-FIN-042 reimaged |
        | 16:00 | IAM | Finance department password reset (47 users) |

        ## 4. Technical Analysis

        ### 4.1 Root Cause

        A spearphishing email containing a malicious Word document
        (`invoice_Q4.docm`) was delivered to the Finance team distribution list.  The
        document contained a VBA macro that, upon execution, downloaded and ran a
        PowerShell reverse shell (`update.ps1`) establishing a connection to the
        attacker's C2 server at `203.0.113.42`.

        ### 4.2 Attack Vector

        - **Initial Access:** Spearphishing attachment (T1566.001)
        - **Execution:** VBA macro → PowerShell (T1059.001)
        - **Persistence:** Registry Run key (T1547.001)

        ### 4.3 Lateral Movement

        From the compromised workstation, the attacker:
        1. Dumped credentials from LSASS memory (T1003.001)
        2. Used harvested domain admin credentials to connect to SRV-DB-01 via SMB
        3. Executed a bulk SQL query extracting 500,000 customer records
        4. Exfiltrated data via HTTPS to C2 and DNS tunneling to evil.example.com

        ### 4.4 Attacker Infrastructure

        | Component | Detail |
        |-----------|--------|
        | C2 Server | 203.0.113.42 |
        | Staging Server | 198.51.100.77 |
        | Exfil Domain | evil.example.com |
        | Payload Domain | cdn-update.example.net |

        ## 5. Impact Assessment

        ### 5.1 Data Exposure

        | Data Type | Records | Classification |
        |-----------|---------|----------------|
        | Customer PII (names, emails, addresses) | 500,000 | Confidential |
        | Financial transaction history | 500,000 | Confidential |
        | Active Directory credentials | ~200 (hashes) | Critical |

        ### 5.2 System Compromise

        | System | Impact | Current Status |
        |--------|--------|----------------|
        | WKSTN-FIN-042 | Full compromise, malware | Reimaged |
        | SRV-DB-01 | Data exfiltration | Isolated |
        | DC-01 | Credential harvesting | Monitored |
        | EXCH-01 | Under investigation | Monitored |

        ### 5.3 Business Impact

        - **Regulatory:** Potential GDPR Art. 33 notification required (72-hour clock started)
        - **Financial:** Estimated breach cost $2.5M–$5M (notification, credit monitoring, legal)
        - **Reputational:** Customer trust impact — proactive disclosure recommended
        - **Operational:** Finance department productivity reduced during remediation

        ## 6. Containment Actions

        | # | Action | Time | Owner |
        |---|--------|------|-------|
        | 1 | Network isolation of WKSTN-FIN-042 | 10:00 | SOC |
        | 2 | Blocked C2 IP at perimeter firewall | 10:05 | Network |
        | 3 | Password reset for initial victim | 10:10 | IAM |
        | 4 | Blocked phishing sender at email gateway | 10:15 | Email Admin |
        | 5 | VPN token revocation | 10:30 | IAM |
        | 6 | Database server isolation | 11:00 | IT Ops |

        ## 7. Remediation Actions

        | # | Action | Status | Cross-ref |
        |---|--------|--------|-----------|
        | 1 | DNS exfiltration detection rules deployed | Complete | Scenario 01 |
        | 2 | KQL investigation queries created | Complete | Scenario 02 |
        | 3 | Firewall containment rules updated | Complete | Scenario 03 |
        | 4 | Network forensics analysis | Complete | Scenario 04 |
        | 5 | Secret exposure scan and rotation | Complete | Scenario 05 |
        | 6 | IaC hardening (Terraform/Bicep) | Complete | Scenario 06 |
        | 7 | WAF and Zero Trust policies | Complete | Scenario 07 |
        | 8 | VPN audit and hardening | Complete | Scenario 08 |
        | 9 | Policy-as-code framework deployed | Complete | Scenario 09 |
        | 10 | Network compliance remediation | Complete | Scenario 10 |
        | 11 | Application vulnerability fixes | Complete | Scenario 11 |
        | 12 | MFA enforcement for all remote access | In Progress | — |
        | 13 | Network segmentation review | In Progress | — |

        ## 8. Lessons Learned

        1. **Email security gaps:** The phishing email bypassed existing email filters.
           Macro-enabled documents should be blocked by default for non-exempt users.

        2. **Missing MFA:** The attacker reused harvested credentials without a second
           factor.  MFA must be enforced for all remote and privileged access.

        3. **Insufficient network segmentation:** Lateral movement from workstation to
           database server was possible because both were on the same VLAN.

        4. **Credential exposure:** LSASS memory was accessible to standard processes.
           Credential Guard and LSA protection should be enabled.

        5. **Detection delay:** 28 minutes elapsed between initial compromise (09:22)
           and SOC triage (09:50).  Automated response playbooks would reduce this.

        6. **Stale firewall rules:** 12 stale rules provided unnecessary attack surface
           (see Scenario 10).

        7. **Lack of policy-as-code:** Infrastructure changes were deployed without
           automated security checks (see Scenario 09).

        ## 9. Recommendations

        | Priority | Recommendation | Owner | Target Date |
        |----------|----------------|-------|-------------|
        | P1 | Enforce MFA on all VPN, RDP, and privileged access | IAM Team | 2024-11-22 |
        | P1 | Block macro-enabled documents at email gateway | Email Admin | 2024-11-18 |
        | P1 | Enable Credential Guard on all workstations | Endpoint Team | 2024-11-29 |
        | P2 | Implement network microsegmentation (finance ↔ servers) | Network Team | 2024-12-13 |
        | P2 | Deploy automated incident response playbooks | SOC | 2024-12-06 |
        | P2 | Quarterly phishing simulation exercises | Security Awareness | 2024-12-20 |
        | P3 | Policy-as-code for all infrastructure deployments | DevOps | 2025-01-10 |
        | P3 | Review and harden all firewall rules quarterly | Network Team | 2025-01-17 |

        ---

        ## Appendix A: Indicators of Compromise (IOCs)

        | Type | Value | Context |
        |------|-------|---------|
        | IPv4 | 203.0.113.42 | C2 server |
        | IPv4 | 198.51.100.77 | Staging server |
        | Domain | evil.example.com | DNS exfiltration |
        | Domain | cdn-update.example.net | Payload delivery |
        | SHA-256 | a1b2c3d4...123456 | Malicious Word doc |
        | SHA-256 | deadbeef...01234567 | PowerShell payload |
        | Email | accounts@spoofed-vendor.com | Phishing sender |
        | File | invoice_Q4.docm | Malicious attachment |
        | File | update.ps1 | Dropped script |
        | Registry | HKCU\\\\...\\\\Run\\\\WindowsUpdate | Persistence |
        | User-Agent | Mozilla/5.0 (...Update Service) | C2 beacon |
        | Mutex | Global\\\\WinUpdateMtx_2024 | Malware mutex |

        ## Appendix B: Affected Systems

        | Hostname | Type | Compromise | Status |
        |----------|------|-----------|--------|
        | WKSTN-FIN-042 | Workstation | Initial access, malware | Reimaged |
        | SRV-DB-01 | Database | Data exfiltration | Isolated |
        | DC-01 | Domain Controller | Credential harvesting | Monitored |
        | EXCH-01 | Email Server | Under investigation | Monitored |

        ## Appendix C: Communication Log

        | Time | From | To | Channel | Summary |
        |------|------|----|---------|---------|
        | 09:55 | SOC Lead | CISO | Phone | P1 declared |
        | 10:15 | CISO | Exec Team | Email | Incident notification |
        | 11:00 | CISO | Exec Team | Teams | Briefing — containment status |
        | 12:00 | General Counsel | CISO | Email | Outside counsel engaged |
        | 14:00 | CISO | Board | Email | Board notification |
        | 16:00 | PR Team | CISO | Email | Draft customer notification |
        | 18:00 | CISO | All Staff | Email | Security awareness reminder |
        | 09:00+1d | CISO | Exec Team | Email | 24-hour status update |

        ---

        *Report generated by IT Security Copilot Demo — Scenario 12.*
    """)


# ---------------------------------------------------------------------------
# Executive summary (1-page)
# ---------------------------------------------------------------------------

def _executive_summary_md() -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return textwrap.dedent(f"""\
        # Executive Summary — Security Incident IR-2024-1115-001

        **Date:** {now}  
        **Classification:** Confidential  
        **Prepared for:** C-Suite / Board of Directors

        ---

        ## What Happened

        On November 15, 2024, a targeted phishing email tricked a Finance employee
        into opening a malicious document.  The attacker gained access to the corporate
        network, harvested credentials, and exfiltrated approximately **500,000 customer
        records** (names, emails, addresses, and transaction history) to an external
        server.

        ## Impact

        - **500,000 customer records** potentially exposed
        - **4 systems** compromised (1 workstation, 1 database server, 2 under investigation)
        - **47 employees** required password resets
        - **Estimated cost:** $2.5M – $5M (notification, credit monitoring, legal, remediation)
        - **Regulatory:** GDPR 72-hour notification clock initiated

        ## Response

        The SOC detected the attack and achieved **full containment within 75 minutes**.
        All compromised systems have been isolated or rebuilt.  Credentials have been
        rotated.  Legal counsel is engaged, and a customer notification draft is under
        review.

        ## Key Actions Underway

        1. **MFA enforcement** for all remote and privileged access (target: Nov 22)
        2. **Email gateway hardening** — block macro-enabled documents (target: Nov 18)
        3. **Network segmentation** review for finance systems (target: Dec 13)
        4. **Credential Guard** deployment on all workstations (target: Nov 29)

        ## Key Takeaway

        This incident exploited three preventable gaps: lack of MFA, insufficient email
        filtering, and flat network architecture.  The remediation plan addresses all
        three with specific owners and deadlines.

        ---

        *Full technical report available: incident_report.md*
    """)


# ---------------------------------------------------------------------------
# Board presentation JSON
# ---------------------------------------------------------------------------

def _board_presentation() -> dict:
    return {
        "incident_id": "IR-2024-1115-001",
        "date": "2024-11-15",
        "severity": "P1 — Critical",
        "metrics": {
            "time_to_detect_minutes": 28,
            "time_to_contain_minutes": 75,
            "systems_compromised": 4,
            "records_exposed": 500000,
            "users_affected": 47,
            "estimated_cost_usd": {"low": 2500000, "high": 5000000},
        },
        "attack_vector": "Spearphishing → Macro → PowerShell → Credential Theft → Data Exfiltration",
        "mitre_attack_tactics": [
            "Initial Access",
            "Execution",
            "Credential Access",
            "Lateral Movement",
            "Exfiltration",
        ],
        "containment_status": "Complete",
        "remediation_status": {
            "completed": 11,
            "in_progress": 2,
            "total": 13,
        },
        "regulatory_status": {
            "gdpr_notification_required": True,
            "gdpr_72hr_deadline": "2024-11-18T09:50:00Z",
            "outside_counsel_engaged": True,
            "customer_notification_draft": "Under legal review",
        },
        "top_recommendations": [
            {"priority": "P1", "action": "Enforce MFA everywhere", "target": "2024-11-22"},
            {"priority": "P1", "action": "Block macro-enabled attachments", "target": "2024-11-18"},
            {"priority": "P1", "action": "Enable Credential Guard", "target": "2024-11-29"},
            {"priority": "P2", "action": "Network microsegmentation", "target": "2024-12-13"},
        ],
        "lessons_learned_count": 7,
        "scenarios_cross_referenced": list(range(1, 12)),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def remediate(base_dir: Path) -> None:
    """Generate comprehensive incident report from raw data."""
    vuln_dir = base_dir / "vulnerable-app"
    vuln_dir.mkdir(parents=True, exist_ok=True)

    # Full incident report
    p = vuln_dir / "incident_report.md"
    p.write_text(_incident_report_md(), encoding="utf-8")
    print(f"[+] Full incident report         -> {p}")

    # Executive summary
    p = vuln_dir / "executive_summary.md"
    p.write_text(_executive_summary_md(), encoding="utf-8")
    print(f"[+] Executive summary (1-page)   -> {p}")

    # Board presentation
    p = vuln_dir / "board_presentation.json"
    p.write_text(json.dumps(_board_presentation(), indent=2) + "\n", encoding="utf-8")
    print(f"[+] Board presentation metrics   -> {p}")

    print()
    print("[✓] Incident report generation complete:")
    print("    • Full technical report with MITRE ATT&CK mapping")
    print("    • Timeline (20 events), impact assessment, lessons learned")
    print("    • Appendices: 12 IOCs, 4 affected systems, 8 communications")
    print("    • Cross-references to scenarios 1–11")
    print("    • Executive summary for C-suite")
    print("    • Board presentation with key metrics")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Scenario 12 — generate comprehensive incident report",
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
