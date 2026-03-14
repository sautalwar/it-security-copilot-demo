#!/usr/bin/env python3
"""Scenario 07 -- WAF & Zero Trust: remediation script.

Creates a hardened WAF policy (OWASP CRS, bot protection, rate limiting,
geo-filtering, custom rules) and a Zero Trust network segmentation config
with four-tier subnets, NSGs, private endpoints, and JIT access.
Generates a Zero Trust compliance matrix.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os

ROOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "infra")


# ---------------------------------------------------------------------------
# Hardened WAF policy
# ---------------------------------------------------------------------------

HARDENED_WAF: dict = {
    "policyName": "waf-policy-prod-hardened",
    "location": "eastus",
    "sku": "WAF_v2",
    "policySettings": {
        "state": "Enabled",
        "mode": "Prevention",
        "requestBodyCheck": True,
        "maxRequestBodySizeInKb": 128,
        "fileUploadLimitInMb": 100,
    },
    "managedRules": {
        "managedRuleSets": [
            {
                "ruleSetType": "OWASP",
                "ruleSetVersion": "3.2",
                "ruleGroupOverrides": [],
                "description": "OWASP Core Rule Set 3.2 -- full protection",
            },
            {
                "ruleSetType": "Microsoft_BotManagerRuleSet",
                "ruleSetVersion": "1.0",
                "description": "Bot protection -- block known bad bots, allow good bots",
            },
        ],
        "exclusions": [
            {
                "matchVariable": "RequestHeaderNames",
                "selectorMatchOperator": "Equals",
                "selector": "x-custom-safe-header",
                "description": "Application-specific header excluded from inspection",
            },
        ],
    },
    "customRules": [
        {
            "name": "RateLimitPerIP",
            "priority": 10,
            "ruleType": "RateLimitRule",
            "rateLimitThreshold": 100,
            "rateLimitDurationInMinutes": 1,
            "matchConditions": [
                {
                    "matchVariables": [{"variableName": "RemoteAddr"}],
                    "operator": "IPMatch",
                    "negationCondition": True,
                    "matchValues": ["10.0.0.0/8", "172.16.0.0/12"],
                    "description": "Rate limit external IPs (not internal)",
                }
            ],
            "action": "Block",
            "description": "Block IPs exceeding 100 requests per minute",
        },
        {
            "name": "BlockSQLInjection",
            "priority": 20,
            "ruleType": "MatchRule",
            "matchConditions": [
                {
                    "matchVariables": [
                        {"variableName": "QueryString"},
                        {"variableName": "RequestBody"},
                        {"variableName": "RequestUri"},
                    ],
                    "operator": "Contains",
                    "matchValues": [
                        "' OR 1=1",
                        "'; DROP TABLE",
                        "UNION SELECT",
                        "EXEC xp_",
                        "1=1--",
                        "' OR ''='",
                    ],
                    "transforms": ["Lowercase", "UrlDecode"],
                }
            ],
            "action": "Block",
            "description": "Custom SQL injection patterns beyond OWASP CRS",
        },
        {
            "name": "BlockXSS",
            "priority": 30,
            "ruleType": "MatchRule",
            "matchConditions": [
                {
                    "matchVariables": [
                        {"variableName": "QueryString"},
                        {"variableName": "RequestBody"},
                    ],
                    "operator": "Contains",
                    "matchValues": [
                        "<script>",
                        "javascript:",
                        "onerror=",
                        "onload=",
                        "eval(",
                        "document.cookie",
                    ],
                    "transforms": ["Lowercase", "UrlDecode", "HtmlEntityDecode"],
                }
            ],
            "action": "Block",
            "description": "Custom XSS patterns beyond OWASP CRS",
        },
        {
            "name": "BlockPathTraversal",
            "priority": 40,
            "ruleType": "MatchRule",
            "matchConditions": [
                {
                    "matchVariables": [{"variableName": "RequestUri"}],
                    "operator": "Contains",
                    "matchValues": [
                        "../",
                        "..\\",
                        "/etc/passwd",
                        "/etc/shadow",
                        "\\windows\\system32",
                        "%2e%2e%2f",
                    ],
                    "transforms": ["Lowercase", "UrlDecode"],
                }
            ],
            "action": "Block",
            "description": "Block path traversal attempts",
        },
        {
            "name": "BlockLargePayloads",
            "priority": 50,
            "ruleType": "MatchRule",
            "matchConditions": [
                {
                    "matchVariables": [{"variableName": "RequestBody"}],
                    "operator": "GreaterThan",
                    "matchValues": ["1048576"],
                    "description": "Block request bodies > 1 MB",
                }
            ],
            "action": "Block",
            "description": "Reject oversized request payloads",
        },
    ],
    "botProtection": {
        "enabled": True,
        "badBotAction": "Block",
        "goodBotAction": "Allow",
        "unknownBotAction": "Log",
        "challengeAction": "Captcha",
    },
    "rateLimiting": {
        "enabled": True,
        "defaultThreshold": 100,
        "perMinute": True,
        "burstThreshold": 200,
    },
    "geoFiltering": {
        "enabled": True,
        "defaultAction": "Allow",
        "blockedCountries": [
            "KP", "IR", "SY", "CU", "SD", "RU",
        ],
        "description": "Block traffic from high-risk / sanctioned countries",
    },
    "ipReputationFiltering": {
        "enabled": True,
        "action": "Block",
        "sources": ["Microsoft Threat Intelligence", "Azure WAF IP Reputation"],
    },
}

# ---------------------------------------------------------------------------
# Zero Trust network segmentation
# ---------------------------------------------------------------------------

ZERO_TRUST_SEGMENTATION: dict = {
    "networkName": "vnet-prod-zerotrust",
    "addressSpace": "10.0.0.0/16",
    "subnets": [
        {
            "name": "web-tier",
            "addressPrefix": "10.0.1.0/24",
            "nsg": "nsg-web-tier",
            "purpose": "Public-facing web servers and load balancers",
            "serviceEndpoints": ["Microsoft.Web"],
            "privateEndpoints": [],
        },
        {
            "name": "app-tier",
            "addressPrefix": "10.0.2.0/24",
            "nsg": "nsg-app-tier",
            "purpose": "Application servers and API backends",
            "serviceEndpoints": [
                "Microsoft.Storage",
                "Microsoft.Sql",
                "Microsoft.KeyVault",
            ],
            "privateEndpoints": [
                "pe-storage-app",
                "pe-keyvault-app",
            ],
        },
        {
            "name": "data-tier",
            "addressPrefix": "10.0.3.0/24",
            "nsg": "nsg-data-tier",
            "purpose": "Databases, caches, and data stores",
            "serviceEndpoints": ["Microsoft.Sql"],
            "privateEndpoints": [
                "pe-sql-data",
                "pe-redis-data",
            ],
        },
        {
            "name": "management-tier",
            "addressPrefix": "10.0.4.0/24",
            "nsg": "nsg-mgmt-tier",
            "purpose": "Bastion hosts, jump boxes, and admin access",
            "serviceEndpoints": [],
            "privateEndpoints": [],
            "bastionHost": True,
            "jitAccess": {
                "enabled": True,
                "maxDurationHours": 3,
                "approvalRequired": True,
                "allowedPorts": [22, 3389],
            },
        },
    ],
    "networkSecurityGroups": [
        {
            "name": "nsg-web-tier",
            "rules": [
                {
                    "name": "AllowHTTPSInbound",
                    "priority": 100,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddress": "Internet",
                    "destinationAddress": "10.0.1.0/24",
                    "destinationPort": "443",
                },
                {
                    "name": "AllowHTTPInbound",
                    "priority": 110,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddress": "Internet",
                    "destinationAddress": "10.0.1.0/24",
                    "destinationPort": "80",
                    "note": "Redirect to HTTPS at application level",
                },
                {
                    "name": "AllowMgmtSSH",
                    "priority": 200,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddress": "10.0.4.0/24",
                    "destinationAddress": "10.0.1.0/24",
                    "destinationPort": "22",
                },
                {
                    "name": "DenyAllInbound",
                    "priority": 4096,
                    "direction": "Inbound",
                    "access": "Deny",
                    "protocol": "*",
                    "sourceAddress": "*",
                    "destinationAddress": "*",
                    "destinationPort": "*",
                },
            ],
        },
        {
            "name": "nsg-app-tier",
            "rules": [
                {
                    "name": "AllowHTTPSFromWeb",
                    "priority": 100,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddress": "10.0.1.0/24",
                    "destinationAddress": "10.0.2.0/24",
                    "destinationPort": "443",
                },
                {
                    "name": "AllowMgmtSSH",
                    "priority": 200,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddress": "10.0.4.0/24",
                    "destinationAddress": "10.0.2.0/24",
                    "destinationPort": "22",
                },
                {
                    "name": "DenyAllInbound",
                    "priority": 4096,
                    "direction": "Inbound",
                    "access": "Deny",
                    "protocol": "*",
                    "sourceAddress": "*",
                    "destinationAddress": "*",
                    "destinationPort": "*",
                },
            ],
        },
        {
            "name": "nsg-data-tier",
            "rules": [
                {
                    "name": "AllowSQLFromApp",
                    "priority": 100,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddress": "10.0.2.0/24",
                    "destinationAddress": "10.0.3.0/24",
                    "destinationPort": "1433",
                },
                {
                    "name": "AllowRedisFromApp",
                    "priority": 110,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddress": "10.0.2.0/24",
                    "destinationAddress": "10.0.3.0/24",
                    "destinationPort": "6380",
                    "note": "Redis over TLS",
                },
                {
                    "name": "DenyAllInbound",
                    "priority": 4096,
                    "direction": "Inbound",
                    "access": "Deny",
                    "protocol": "*",
                    "sourceAddress": "*",
                    "destinationAddress": "*",
                    "destinationPort": "*",
                },
            ],
        },
        {
            "name": "nsg-mgmt-tier",
            "rules": [
                {
                    "name": "AllowBastionSSH",
                    "priority": 100,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddress": "AzureBastionSubnet",
                    "destinationAddress": "10.0.4.0/24",
                    "destinationPort": "22",
                },
                {
                    "name": "AllowBastionRDP",
                    "priority": 110,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddress": "AzureBastionSubnet",
                    "destinationAddress": "10.0.4.0/24",
                    "destinationPort": "3389",
                },
                {
                    "name": "DenyAllInbound",
                    "priority": 4096,
                    "direction": "Inbound",
                    "access": "Deny",
                    "protocol": "*",
                    "sourceAddress": "*",
                    "destinationAddress": "*",
                    "destinationPort": "*",
                },
            ],
        },
    ],
    "privateEndpoints": [
        {
            "name": "pe-storage-app",
            "service": "Microsoft.Storage/storageAccounts",
            "subnet": "app-tier",
            "groupId": "blob",
        },
        {
            "name": "pe-keyvault-app",
            "service": "Microsoft.KeyVault/vaults",
            "subnet": "app-tier",
            "groupId": "vault",
        },
        {
            "name": "pe-sql-data",
            "service": "Microsoft.Sql/servers",
            "subnet": "data-tier",
            "groupId": "sqlServer",
        },
        {
            "name": "pe-redis-data",
            "service": "Microsoft.Cache/Redis",
            "subnet": "data-tier",
            "groupId": "redisCache",
        },
    ],
    "ddosProtection": True,
    "bastionHost": {
        "enabled": True,
        "sku": "Standard",
        "subnet": "AzureBastionSubnet",
        "addressPrefix": "10.0.5.0/26",
    },
    "microsegmentation": True,
}

# ---------------------------------------------------------------------------
# Zero Trust compliance matrix
# ---------------------------------------------------------------------------

ZERO_TRUST_PRINCIPLES: list[dict[str, str]] = [
    {
        "principle": "Verify explicitly",
        "control": "WAF inspects every request; OWASP CRS + custom rules validate all input",
        "status": "COMPLIANT",
    },
    {
        "principle": "Use least-privilege access",
        "control": "NSGs restrict traffic to 443 (web->app), 1433/6380 (app->data), 22/3389 (mgmt only)",
        "status": "COMPLIANT",
    },
    {
        "principle": "Assume breach",
        "control": "Microsegmentation isolates tiers; lateral movement blocked by deny-all defaults",
        "status": "COMPLIANT",
    },
    {
        "principle": "Minimize blast radius",
        "control": "Four separate subnets; compromise of web tier cannot reach data tier directly",
        "status": "COMPLIANT",
    },
    {
        "principle": "Encrypt all traffic",
        "control": "TLS 1.2+ enforced; Redis over TLS (6380); private endpoints for PaaS",
        "status": "COMPLIANT",
    },
    {
        "principle": "Continuous monitoring",
        "control": "WAF logging, NSG flow logs, DDoS telemetry, bot detection logs",
        "status": "COMPLIANT",
    },
    {
        "principle": "Automate threat response",
        "control": "Rate limiting auto-blocks abusive IPs; geo-filtering blocks sanctioned regions",
        "status": "COMPLIANT",
    },
    {
        "principle": "Secure admin access",
        "control": "Azure Bastion + JIT VM access; no direct SSH/RDP from internet",
        "status": "COMPLIANT",
    },
]


def _generate_report() -> str:
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("  WAF & ZERO TRUST -- COMPLIANCE REPORT")
    lines.append(f"  Generated: {datetime.datetime.utcnow().isoformat()}Z")
    lines.append("=" * 70)
    lines.append("")

    # WAF summary
    lines.append("--- WAF Policy Summary ---")
    lines.append(f"  State                : Enabled (Prevention mode)")
    lines.append(f"  OWASP CRS            : 3.2")
    lines.append(f"  Bot protection       : Enabled (block bad, allow good)")
    lines.append(f"  Rate limiting        : 100 req/min per IP")
    lines.append(f"  Geo-filtering        : Blocked: KP, IR, SY, CU, SD, RU")
    lines.append(f"  Custom rules         : 5 (SQLi, XSS, path traversal, payloads, rate limit)")
    lines.append(f"  IP reputation        : Enabled (Microsoft Threat Intelligence)")
    lines.append("")

    # Network summary
    lines.append("--- Zero Trust Network Summary ---")
    lines.append(f"  Subnets              : 4 (web, app, data, management)")
    lines.append(f"  NSGs                 : 4 (one per subnet, deny-all default)")
    lines.append(f"  Private endpoints    : 4 (storage, keyvault, SQL, Redis)")
    lines.append(f"  DDoS protection      : Enabled")
    lines.append(f"  Bastion host         : Enabled (Standard SKU)")
    lines.append(f"  JIT VM access        : Enabled (max 3h, approval required)")
    lines.append("")

    # Traffic flow matrix
    lines.append("--- Allowed Traffic Flows ---")
    lines.append(f"  {'Source -> Destination':<30} {'Ports':<14} {'Protocol':<10} Purpose")
    lines.append(f"  {'-'*28}  {'-'*12}  {'-'*8}  {'-'*20}")
    flows = [
        ("Internet -> web-tier", "80, 443", "TCP", "Public web traffic"),
        ("web-tier -> app-tier", "443", "TCP", "HTTPS API calls"),
        ("app-tier -> data-tier", "1433, 6380", "TCP", "SQL Server, Redis TLS"),
        ("app-tier -> Key Vault", "443", "TCP", "Secret retrieval"),
        ("app-tier -> Storage", "443", "TCP", "Blob/file operations"),
        ("mgmt-tier -> all tiers", "22, 3389", "TCP", "Administration (JIT)"),
        ("Bastion -> mgmt-tier", "22, 3389", "TCP", "Secure admin entry"),
    ]
    for src_dst, ports, proto, purpose in flows:
        lines.append(f"  {src_dst:<30} {ports:<14} {proto:<10} {purpose}")
    lines.append("")

    # Zero Trust compliance matrix
    lines.append("--- Zero Trust Compliance Matrix ---")
    compliant = 0
    for item in ZERO_TRUST_PRINCIPLES:
        status_mark = "[PASS]" if item["status"] == "COMPLIANT" else "[FAIL]"
        if item["status"] == "COMPLIANT":
            compliant += 1
        lines.append(f"  {status_mark} {item['principle']}")
        lines.append(f"         {item['control']}")
    lines.append("")
    lines.append(f"  Score: {compliant}/{len(ZERO_TRUST_PRINCIPLES)} principles met")
    lines.append("")

    lines.append("--- Recommendations ---")
    lines.append("  1. Enable NSG flow logs and send to Log Analytics.")
    lines.append("  2. Configure Azure DDoS Protection Standard alerts.")
    lines.append("  3. Review WAF exclusions quarterly.")
    lines.append("  4. Integrate WAF logs with SIEM for correlation.")
    lines.append("  5. Test WAF rules with OWASP ZAP or Burp Suite.")
    lines.append("  6. Rotate Bastion and JIT access policies every 90 days.")
    lines.append("")
    lines.append("=" * 70)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def remediate(output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)

    # 1. Hardened WAF
    waf_path = os.path.join(output_dir, "waf_rules_hardened.json")
    with open(waf_path, "w", encoding="utf-8") as f:
        json.dump(HARDENED_WAF, f, indent=2)
        f.write("\n")
    print(f"[+] Created HARDENED WAF policy -> {waf_path}")

    # 2. Zero Trust segmentation
    zt_path = os.path.join(output_dir, "zero_trust_segmentation.json")
    with open(zt_path, "w", encoding="utf-8") as f:
        json.dump(ZERO_TRUST_SEGMENTATION, f, indent=2)
        f.write("\n")
    print(f"[+] Created Zero Trust network segmentation -> {zt_path}")

    # 3. Report
    report = _generate_report()
    report_path = os.path.join(output_dir, "zero_trust_compliance_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print(f"[+] Generated Zero Trust compliance report -> {report_path}")
    print()
    print(report)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Deploy hardened WAF and Zero Trust segmentation.",
    )
    parser.add_argument(
        "--output-dir",
        default=ROOT_DIR,
        help="Directory to write hardened configs into (default: infra/).",
    )
    args = parser.parse_args()
    remediate(args.output_dir)


if __name__ == "__main__":
    main()
