#!/usr/bin/env python3
"""Scenario 02 – KQL Investigation: remediation script.

Generates KQL detection queries for Microsoft Sentinel, hardens the SIEM
configuration, and produces an investigation report from the sample logs.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import textwrap

ROOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "vulnerable-app")

C2_DOMAIN = "evil-c2.example.com"
COMPROMISED_IP = "10.0.1.15"
C2_SERVER_IP = "203.0.113.66"


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


# ---------------------------------------------------------------------------
# KQL queries
# ---------------------------------------------------------------------------

KQL_DNS_TUNNELING = textwrap.dedent("""\
    // dns_tunneling_detection.kql
    // Detects DNS tunneling via high-entropy subdomain queries.
    // Shannon entropy > 3.5 on subdomain labels is flagged.

    let EntropyThreshold = 3.5;
    let LookbackWindow = 1h;
    DnsEvents
    | where TimeGenerated > ago(LookbackWindow)
    | where SubType == "LookupQuery"
    | extend SubdomainLabels = tostring(split(QueryName, ".")[0])
    | extend LabelLength = strlen(SubdomainLabels)
    | where LabelLength > 12
    // Approximate Shannon entropy via character frequency diversity
    | extend UniqueChars = array_length(
          array_distinct(extract_all("(.)", SubdomainLabels))
      )
    | extend EntropyEstimate = log2(UniqueChars) * (LabelLength / toreal(LabelLength))
    | where EntropyEstimate > EntropyThreshold
    | summarize
          SuspiciousQueryCount = count(),
          Domains = make_set(QueryName, 20),
          FirstSeen = min(TimeGenerated),
          LastSeen = max(TimeGenerated)
      by SourceIP = ClientIP
    | where SuspiciousQueryCount > 5
    | sort by SuspiciousQueryCount desc
""")

KQL_CORRELATED_THREAT_HUNT = textwrap.dedent("""\
    // correlated_threat_hunt.kql
    // Correlates DNS, authentication, and network flow events to find
    // hosts involved in C2 communication AND brute-force / lateral movement.

    let SuspiciousDNSHosts =
        DnsEvents
        | where TimeGenerated > ago(1h)
        | where QueryName contains "evil-c2.example.com"
        | distinct ClientIP;
    let FailedAuthHosts =
        SecurityEvent
        | where TimeGenerated > ago(1h)
        | where EventID == 4625  // failed logon
        | summarize FailedCount = count() by SourceIP = IpAddress
        | where FailedCount > 5
        | distinct SourceIP;
    let HighOutboundHosts =
        AzureNetworkAnalytics_CL
        | where TimeGenerated > ago(1h)
        | where FlowDirection_s == "O"
        | summarize TotalBytesSent = sum(toint(BytesSent_d)) by SourceIP = SrcIP_s
        | where TotalBytesSent > 1000000  // > 1 MB
        | distinct SourceIP;
    // Find IPs present in at least 2 of the 3 indicator sets
    SuspiciousDNSHosts
    | join kind=inner FailedAuthHosts on $left.ClientIP == $right.SourceIP
    | project SuspiciousIP = ClientIP, Indicator = "DNS+Auth"
    | union (
        SuspiciousDNSHosts
        | join kind=inner HighOutboundHosts on $left.ClientIP == $right.SourceIP
        | project SuspiciousIP = ClientIP, Indicator = "DNS+Exfil"
      )
    | summarize Indicators = make_set(Indicator) by SuspiciousIP
    | sort by array_length(Indicators) desc
""")

KQL_DATA_EXFIL = textwrap.dedent("""\
    // data_exfil_detection.kql
    // Detects anomalous outbound data transfers that may indicate exfiltration.

    let BaselineWindow = 7d;
    let DetectionWindow = 1h;
    let ThresholdMultiplier = 3.0;
    // Step 1: Calculate per-host baseline
    let Baseline =
        AzureNetworkAnalytics_CL
        | where TimeGenerated between (ago(BaselineWindow) .. ago(DetectionWindow))
        | where FlowDirection_s == "O"
        | summarize
              AvgBytesSent = avg(toint(BytesSent_d)),
              StdDevBytes = stdev(toint(BytesSent_d))
          by SourceIP = SrcIP_s;
    // Step 2: Current window activity
    let Current =
        AzureNetworkAnalytics_CL
        | where TimeGenerated > ago(DetectionWindow)
        | where FlowDirection_s == "O"
        | summarize
              CurrentBytesSent = sum(toint(BytesSent_d)),
              DestIPs = make_set(DestIP_s, 10),
              FlowCount = count()
          by SourceIP = SrcIP_s;
    // Step 3: Compare and alert
    Current
    | join kind=leftouter Baseline on SourceIP
    | extend Threshold = AvgBytesSent + (StdDevBytes * ThresholdMultiplier)
    | where CurrentBytesSent > Threshold or CurrentBytesSent > 5000000
    | project
          SourceIP,
          CurrentBytesSent,
          BaselineAvg = round(AvgBytesSent, 0),
          Threshold = round(Threshold, 0),
          DestIPs,
          FlowCount
    | sort by CurrentBytesSent desc
""")


# ---------------------------------------------------------------------------
# Hardened SIEM config
# ---------------------------------------------------------------------------

HARDENED_SIEM_CONFIG: dict = {
    "workspace": {
        "name": "SecurityWorkspace",
        "sku": "PerGB2018",
        "retentionInDays": 90,
    },
    "dataConnectors": {
        "windowsSecurityEvents": {"enabled": True, "streams": ["SecurityEvent"]},
        "dnsAnalytics": {"enabled": True, "streams": ["DnsEvents", "DnsInventory"]},
        "nsgFlowLogs": {"enabled": True, "version": 2, "retentionDays": 90},
        "azureADSignInLogs": {"enabled": True, "streams": ["SigninLogs", "AADNonInteractiveUserSignInLogs"]},
        "microsoftDefenderForEndpoint": {"enabled": True},
        "threatIntelligence": {"enabled": True, "feeds": ["MicrosoftTI", "OSINT"]},
    },
    "alertRules": [
        {
            "name": "DNSTunnelingDetection",
            "severity": "High",
            "threshold": 5,
            "windowMinutes": 15,
            "enabled": True,
            "queryFile": "sentinel_queries/dns_tunneling_detection.kql",
        },
        {
            "name": "CorrelatedThreatHunt",
            "severity": "High",
            "threshold": 1,
            "windowMinutes": 60,
            "enabled": True,
            "queryFile": "sentinel_queries/correlated_threat_hunt.kql",
        },
        {
            "name": "DataExfiltrationDetection",
            "severity": "High",
            "threshold": 1,
            "windowMinutes": 60,
            "enabled": True,
            "queryFile": "sentinel_queries/data_exfil_detection.kql",
        },
        {
            "name": "FailedLoginsFromSameIP",
            "severity": "Medium",
            "threshold": 5,
            "windowMinutes": 15,
            "enabled": True,
        },
    ],
    "automationRules": [
        {
            "name": "AutoIsolateCompromisedHost",
            "trigger": "DNSTunnelingDetection",
            "action": "IsolateDevice",
        },
        {
            "name": "AutoBlockC2Domain",
            "trigger": "DNSTunnelingDetection",
            "action": "BlockDomain",
        },
    ],
    "playbookConnections": [
        {
            "name": "IncidentEnrichment",
            "type": "LogicApp",
            "triggers": ["DNSTunnelingDetection", "DataExfiltrationDetection"],
        },
    ],
    "incidentSettings": {
        "autoGroupRelatedAlerts": True,
        "autoInvestigate": True,
    },
}


# ---------------------------------------------------------------------------
# Log analysis & report
# ---------------------------------------------------------------------------

def _load_json(path: str) -> list[dict]:
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _analyse_and_report(output_dir: str) -> str:
    logs_dir = os.path.join(output_dir, "sample_logs")
    dns_events = _load_json(os.path.join(logs_dir, "dns_events.json"))
    auth_events = _load_json(os.path.join(logs_dir, "auth_events.json"))
    net_flows = _load_json(os.path.join(logs_dir, "network_flows.json"))

    c2_dns = [e for e in dns_events if C2_DOMAIN in e.get("QueryName", "")]
    failed_auth = [e for e in auth_events if e.get("LogonResult") == "Failure" and e.get("SourceIP") == COMPROMISED_IP]
    large_outbound = [e for e in net_flows if e.get("SourceIP") == COMPROMISED_IP and e.get("BytesSent", 0) > 100_000]

    total_exfil_bytes = sum(e.get("BytesSent", 0) for e in large_outbound)

    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("  KQL INVESTIGATION — REPORT")
    lines.append(f"  Generated: {datetime.datetime.utcnow().isoformat()}Z")
    lines.append("=" * 70)
    lines.append("")
    lines.append("--- Event Summary ---")
    lines.append(f"  DNS events analysed      : {len(dns_events)}")
    lines.append(f"  Auth events analysed     : {len(auth_events)}")
    lines.append(f"  Network flows analysed   : {len(net_flows)}")
    lines.append("")
    lines.append("--- Findings ---")
    lines.append(f"  [!] C2 DNS queries (evil-c2)      : {len(c2_dns)}")
    lines.append(f"  [!] Failed auths from {COMPROMISED_IP} : {len(failed_auth)}")
    lines.append(f"  [!] Large outbound flows           : {len(large_outbound)}")
    lines.append(f"  [!] Total exfil bytes estimate     : {total_exfil_bytes:,}")
    lines.append("")
    lines.append("--- Correlated Timeline ---")

    # Build simple timeline
    timeline: list[tuple[str, str]] = []
    for e in c2_dns[:5]:
        timeline.append((e["TimeGenerated"], f"DNS → {e['QueryName'][:50]}"))
    for e in failed_auth[:5]:
        timeline.append((e["TimeGenerated"], f"AUTH FAIL → user={e['TargetUserName']}"))
    for e in large_outbound[:5]:
        timeline.append((e["TimeGenerated"], f"EXFIL → {e['BytesSent']:,} bytes → {e['DestinationIP']}"))
    timeline.sort()
    for ts, desc in timeline:
        lines.append(f"  {ts}  {desc}")

    lines.append("")
    lines.append("--- KQL Queries Generated ---")
    lines.append("  1. sentinel_queries/dns_tunneling_detection.kql")
    lines.append("  2. sentinel_queries/correlated_threat_hunt.kql")
    lines.append("  3. sentinel_queries/data_exfil_detection.kql")
    lines.append("")
    lines.append("--- Recommendations ---")
    lines.append("  1. Enable DNS Analytics and NSG Flow Log connectors immediately.")
    lines.append("  2. Reduce alert thresholds to catch low-volume attacks.")
    lines.append("  3. Deploy automated playbooks for host isolation.")
    lines.append("  4. Increase log retention to at least 90 days.")
    lines.append("  5. Investigate compromised host 10.0.1.15.")
    lines.append("")
    lines.append("=" * 70)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def remediate(output_dir: str) -> None:
    _ensure_dir(output_dir)
    queries_dir = os.path.join(output_dir, "sentinel_queries")
    _ensure_dir(queries_dir)

    # 1. Write KQL queries
    kql_files: dict[str, str] = {
        "dns_tunneling_detection.kql": KQL_DNS_TUNNELING,
        "correlated_threat_hunt.kql": KQL_CORRELATED_THREAT_HUNT,
        "data_exfil_detection.kql": KQL_DATA_EXFIL,
    }
    for filename, content in kql_files.items():
        path = os.path.join(queries_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[+] Created KQL query → {path}")

    # 2. Harden SIEM config
    config_path = os.path.join(output_dir, "siem_config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(HARDENED_SIEM_CONFIG, f, indent=2)
    print(f"[+] Updated SIEM config (hardened) → {config_path}")

    # 3. Investigation report
    report = _analyse_and_report(output_dir)
    report_path = os.path.join(output_dir, "investigation_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print(f"[+] Generated investigation report → {report_path}")
    print()
    print(report)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate KQL detection queries, harden SIEM config, and investigate logs.",
    )
    parser.add_argument(
        "--output-dir",
        default=ROOT_DIR,
        help="Directory containing vulnerable files (default: vulnerable-app/).",
    )
    args = parser.parse_args()
    remediate(args.output_dir)


if __name__ == "__main__":
    main()
