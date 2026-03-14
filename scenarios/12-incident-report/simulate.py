#!/usr/bin/env python3
"""Scenario 12 – Incident Report: plant raw incident artifacts."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


# ---------------------------------------------------------------------------
# Raw timeline events (messy, unsorted, mixed severity)
# ---------------------------------------------------------------------------

def _timeline_raw() -> list[dict]:
    return [
        {"time": "2024-11-15T06:12:00Z", "source": "SIEM", "event": "Normal login activity from VPN gateway", "severity": "info"},
        {"time": "2024-11-15T08:45:00Z", "source": "SIEM", "event": "Scheduled vulnerability scan started", "severity": "info"},
        {"time": "2024-11-15T09:15:00Z", "source": "Email Gateway", "event": "Phishing email delivered to finance-team@corp.com", "severity": "medium"},
        {"time": "2024-11-15T09:22:00Z", "source": "Endpoint EDR", "event": "User john.doe clicked malicious link in email", "severity": "high"},
        {"time": "2024-11-15T09:23:00Z", "source": "Endpoint EDR", "event": "Malicious macro executed in Word document", "severity": "critical"},
        {"time": "2024-11-15T09:24:00Z", "source": "Endpoint EDR", "event": "PowerShell reverse shell established to 203.0.113.42", "severity": "critical"},
        {"time": "2024-11-15T09:30:00Z", "source": "SIEM", "event": "Anomalous LDAP queries from WKSTN-FIN-042", "severity": "high"},
        {"time": "2024-11-15T09:35:00Z", "source": "Active Directory", "event": "Credential dumping detected (LSASS memory access)", "severity": "critical"},
        {"time": "2024-11-15T09:40:00Z", "source": "Network IDS", "event": "Lateral movement via SMB to SRV-DB-01", "severity": "critical"},
        {"time": "2024-11-15T09:42:00Z", "source": "Database", "event": "Bulk SELECT query on customers table (500K rows)", "severity": "critical"},
        {"time": "2024-11-15T09:45:00Z", "source": "Network IDS", "event": "Large data transfer to external IP 203.0.113.42 (2.3 GB)", "severity": "critical"},
        {"time": "2024-11-15T09:48:00Z", "source": "Firewall", "event": "DNS exfiltration pattern detected to evil.example.com", "severity": "critical"},
        {"time": "2024-11-15T09:50:00Z", "source": "SOC Analyst", "event": "Alert triaged — severity escalated to P1", "severity": "high"},
        {"time": "2024-11-15T09:55:00Z", "source": "SOC Analyst", "event": "Incident commander assigned: Jane Smith (CISO)", "severity": "high"},
        {"time": "2024-11-15T10:00:00Z", "source": "SOC Analyst", "event": "Containment initiated — network isolation of WKSTN-FIN-042", "severity": "high"},
        {"time": "2024-11-15T10:05:00Z", "source": "Firewall", "event": "Blocked all traffic to/from 203.0.113.42", "severity": "high"},
        {"time": "2024-11-15T10:10:00Z", "source": "Active Directory", "event": "Forced password reset for john.doe and service accounts", "severity": "high"},
        {"time": "2024-11-15T10:30:00Z", "source": "Network Team", "event": "VPN access revoked for compromised credentials", "severity": "high"},
        {"time": "2024-11-15T11:00:00Z", "source": "IT Ops", "event": "SRV-DB-01 isolated from network", "severity": "high"},
        {"time": "2024-11-15T12:00:00Z", "source": "Legal", "event": "Outside counsel engaged for data breach assessment", "severity": "medium"},
        {"time": "2024-11-15T13:00:00Z", "source": "IT Ops", "event": "Forensic images captured from WKSTN-FIN-042 and SRV-DB-01", "severity": "info"},
        {"time": "2024-11-15T14:00:00Z", "source": "SOC Analyst", "event": "Malware sample extracted and submitted to sandbox", "severity": "info"},
        {"time": "2024-11-15T15:00:00Z", "source": "IT Ops", "event": "WKSTN-FIN-042 reimaged from known-good baseline", "severity": "info"},
        {"time": "2024-11-15T16:00:00Z", "source": "Security Team", "event": "Full AD password reset for all finance department users", "severity": "high"},
        {"time": "2024-11-15T18:00:00Z", "source": "CISO", "event": "Post-incident review meeting scheduled for 2024-11-16", "severity": "info"},
    ]


# ---------------------------------------------------------------------------
# IOCs collected
# ---------------------------------------------------------------------------

def _iocs() -> dict:
    return {
        "collection_date": "2024-11-15T14:00:00Z",
        "indicators": [
            {"type": "ipv4", "value": "203.0.113.42", "context": "C2 server, data exfiltration destination"},
            {"type": "ipv4", "value": "198.51.100.77", "context": "Secondary staging server"},
            {"type": "domain", "value": "evil.example.com", "context": "DNS exfiltration domain"},
            {"type": "domain", "value": "cdn-update.example.net", "context": "Payload delivery domain"},
            {"type": "sha256", "value": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456", "context": "Malicious Word document (invoice_Q4.docm)"},
            {"type": "sha256", "value": "deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567", "context": "PowerShell reverse shell payload"},
            {"type": "email", "value": "accounts@spoofed-vendor.com", "context": "Phishing email sender"},
            {"type": "filename", "value": "invoice_Q4.docm", "context": "Malicious attachment"},
            {"type": "filename", "value": "update.ps1", "context": "Dropped PowerShell script"},
            {"type": "registry_key", "value": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate", "context": "Persistence mechanism"},
            {"type": "user_agent", "value": "Mozilla/5.0 (compatible; MSIE 6.0; Update Service)", "context": "C2 beacon user agent"},
            {"type": "mutex", "value": "Global\\WinUpdateMtx_2024", "context": "Malware mutex for single-instance check"},
        ],
    }


# ---------------------------------------------------------------------------
# Affected systems
# ---------------------------------------------------------------------------

def _affected_systems() -> dict:
    return {
        "assessment_date": "2024-11-15T15:00:00Z",
        "systems": [
            {
                "hostname": "WKSTN-FIN-042",
                "type": "Workstation",
                "os": "Windows 11 Pro",
                "user": "john.doe",
                "department": "Finance",
                "compromise_type": "Initial access — malware execution",
                "data_at_risk": "Local documents, cached credentials, email",
                "status": "Reimaged",
            },
            {
                "hostname": "SRV-DB-01",
                "type": "Database Server",
                "os": "Windows Server 2022",
                "service": "MS SQL Server 2022",
                "compromise_type": "Lateral movement — credential reuse",
                "data_at_risk": "Customer PII (500K records), financial transactions",
                "status": "Isolated, under forensic analysis",
            },
            {
                "hostname": "DC-01",
                "type": "Domain Controller",
                "os": "Windows Server 2022",
                "compromise_type": "Credential harvesting (LSASS dump)",
                "data_at_risk": "Active Directory credentials",
                "status": "Monitored — no evidence of persistent compromise",
            },
            {
                "hostname": "EXCH-01",
                "type": "Email Server",
                "os": "Windows Server 2022",
                "service": "Exchange 2019",
                "compromise_type": "Potential — phishing email originated here",
                "data_at_risk": "Email content for finance team",
                "status": "Under investigation",
            },
        ],
        "total_users_affected": 47,
        "total_records_exposed": 500000,
    }


# ---------------------------------------------------------------------------
# Remediation log
# ---------------------------------------------------------------------------

def _remediation_log() -> list[dict]:
    return [
        {"time": "2024-11-15T10:00:00Z", "action": "Isolated WKSTN-FIN-042 from network", "owner": "SOC Team", "status": "complete"},
        {"time": "2024-11-15T10:05:00Z", "action": "Blocked C2 IP 203.0.113.42 at perimeter firewall", "owner": "Network Team", "status": "complete"},
        {"time": "2024-11-15T10:10:00Z", "action": "Reset password for john.doe", "owner": "IAM Team", "status": "complete"},
        {"time": "2024-11-15T10:15:00Z", "action": "Blocked phishing sender domain at email gateway", "owner": "Email Admin", "status": "complete"},
        {"time": "2024-11-15T10:30:00Z", "action": "Revoked VPN tokens for compromised accounts", "owner": "IAM Team", "status": "complete"},
        {"time": "2024-11-15T11:00:00Z", "action": "Isolated SRV-DB-01 from network", "owner": "IT Ops", "status": "complete"},
        {"time": "2024-11-15T13:00:00Z", "action": "Captured forensic disk images", "owner": "DFIR Team", "status": "complete"},
        {"time": "2024-11-15T14:00:00Z", "action": "Submitted malware to sandbox for analysis", "owner": "Malware Analysis", "status": "complete"},
        {"time": "2024-11-15T15:00:00Z", "action": "Reimaged WKSTN-FIN-042 from known-good baseline", "owner": "IT Ops", "status": "complete"},
        {"time": "2024-11-15T16:00:00Z", "action": "Full password reset for finance department (47 users)", "owner": "IAM Team", "status": "complete"},
        {"time": "2024-11-15T17:00:00Z", "action": "Deployed updated EDR signatures for detected malware", "owner": "Security Eng", "status": "complete"},
        {"time": "2024-11-16T09:00:00Z", "action": "Enabled MFA for all VPN and RDP access", "owner": "IAM Team", "status": "in_progress"},
        {"time": "2024-11-16T10:00:00Z", "action": "Network segmentation review and hardening", "owner": "Network Team", "status": "in_progress"},
    ]


# ---------------------------------------------------------------------------
# Communication log
# ---------------------------------------------------------------------------

def _communication_log() -> list[dict]:
    return [
        {"time": "2024-11-15T09:55:00Z", "from": "SOC Lead", "to": "CISO", "channel": "Phone", "message": "P1 incident declared — active data exfiltration detected from finance workstation."},
        {"time": "2024-11-15T10:15:00Z", "from": "CISO", "to": "Executive Team", "channel": "Email", "message": "Security incident in progress. Containment actions underway. Customer data potentially affected. Briefing at 11:00."},
        {"time": "2024-11-15T11:00:00Z", "from": "CISO", "to": "Executive Team", "channel": "Teams Meeting", "message": "Briefing: Phishing attack led to credential theft and data exfiltration. ~500K customer records potentially exposed. Containment complete. Legal engaged."},
        {"time": "2024-11-15T12:00:00Z", "from": "General Counsel", "to": "CISO", "channel": "Email", "message": "Outside counsel (Morrison & Foerster) engaged. Breach notification assessment begins. 72-hour GDPR clock started."},
        {"time": "2024-11-15T14:00:00Z", "from": "CISO", "to": "Board of Directors", "channel": "Email", "message": "Board notification: Security incident involving potential customer data exposure. Full report to follow within 24 hours."},
        {"time": "2024-11-15T16:00:00Z", "from": "PR Team", "to": "CISO", "channel": "Email", "message": "Draft customer notification prepared. Awaiting legal review before release."},
        {"time": "2024-11-15T18:00:00Z", "from": "CISO", "to": "All Staff", "channel": "Email", "message": "Security awareness reminder: Do not click links in unexpected emails. Report suspicious messages to security@corp.com."},
        {"time": "2024-11-16T09:00:00Z", "from": "CISO", "to": "Executive Team", "channel": "Email", "message": "24-hour update: All compromised systems contained. Forensic analysis ongoing. Customer notification draft under legal review."},
    ]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def simulate(base_dir: Path) -> None:
    """Plant raw incident data artifacts."""
    data_dir = base_dir / "vulnerable-app" / "incident_data"
    data_dir.mkdir(parents=True, exist_ok=True)

    artifacts: list[tuple[str, object]] = [
        ("timeline_raw.json", _timeline_raw()),
        ("iocs_collected.json", _iocs()),
        ("affected_systems.json", _affected_systems()),
        ("remediation_log.json", _remediation_log()),
        ("communication_log.json", _communication_log()),
    ]

    for filename, data in artifacts:
        path = data_dir / filename
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"[+] {filename:<30s} → {path}")

    print()
    print("[!] Raw incident data planted:")
    print("    • 25 timeline events (unsorted, mixed severity)")
    print("    • 12 IOCs (IPs, domains, hashes, filenames)")
    print("    • 4 affected systems (workstation, DB, DC, Exchange)")
    print("    • 13 remediation actions")
    print("    • 8 stakeholder communications")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Scenario 12 — simulate raw incident data",
    )
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent.parent,
        help="Repository root (default: two levels up from this script)",
    )
    args = parser.parse_args(argv)
    simulate(args.base_dir)


if __name__ == "__main__":
    main()
