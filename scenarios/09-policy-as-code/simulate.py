#!/usr/bin/env python3
"""Scenario 09 – Policy-as-Code: plant weak / missing policies."""
from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
from pathlib import Path


def _weak_azure_policy() -> dict:
    """Return an Azure Policy set with only 2 basic, insufficient rules."""
    return {
        "$schema": "https://schema.management.azure.com/schemas/2021-06-01/policySetDefinitions/2021-06-01/policySetDefinition.json",
        "name": "MinimalPolicySet",
        "properties": {
            "displayName": "Minimal Policy Set",
            "description": "WARNING — only enforces tags and location. No encryption, networking, or logging checks.",
            "policyDefinitions": [
                {
                    "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/require-tag-on-rg",
                    "parameters": {},
                    "metadata": {"description": "Require a CostCenter tag on resource groups"},
                },
                {
                    "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/allowed-locations",
                    "parameters": {
                        "listOfAllowedLocations": {
                            "value": ["eastus", "westus2"]
                        }
                    },
                    "metadata": {"description": "Restrict resource deployment to specific regions"},
                },
            ],
            "missingPolicies": [
                "Encryption at rest for storage accounts",
                "Encryption in transit (HTTPS only)",
                "Network isolation / private endpoints",
                "Secret management via Key Vault",
                "Diagnostic / audit logging enabled",
                "SQL Server firewall restrictions",
                "DDoS protection on public IPs",
                "Key Vault soft-delete & purge protection",
                "Managed disk encryption",
                "Container registry admin account disabled",
                "Web app minimum TLS 1.2",
                "Function app HTTPS only",
                "API Management TLS policy",
            ],
        },
    }


def _unchecked_deploy_script() -> str:
    """Return a deployment script with NO policy validation."""
    return textwrap.dedent("""\
        #!/usr/bin/env bash
        # deploy_unchecked.sh — deploys infrastructure WITHOUT any policy check
        set -euo pipefail

        RESOURCE_GROUP="${1:?Usage: deploy_unchecked.sh <resource-group> <template>}"
        TEMPLATE="${2:?Usage: deploy_unchecked.sh <resource-group> <template>}"

        echo "[WARN] No policy validation is being performed!"
        echo "[*] Deploying $TEMPLATE to $RESOURCE_GROUP ..."

        az deployment group create \\
            --resource-group "$RESOURCE_GROUP" \\
            --template-file "$TEMPLATE" \\
            --mode Incremental

        echo "[*] Deployment complete — no policy checks were run."
    """)


def simulate(base_dir: Path) -> None:
    """Create a weak policy setup under *base_dir*/infra/."""
    policies_dir = base_dir / "infra" / "policies"
    policies_dir.mkdir(parents=True, exist_ok=True)

    # Weak Azure Policy definition
    azure_policy_path = policies_dir / "azure_policy.json"
    azure_policy_path.write_text(json.dumps(_weak_azure_policy(), indent=2) + "\n", encoding="utf-8")
    print(f"[+] Created weak Azure Policy set  -> {azure_policy_path}")

    # Deployment script without policy validation
    deploy_path = base_dir / "infra" / "deploy_unchecked.sh"
    deploy_path.write_text(_unchecked_deploy_script(), encoding="utf-8")
    print(f"[+] Created unchecked deploy script -> {deploy_path}")

    # Summary
    print()
    print("[!] Policy gaps planted:")
    print("    • Only 2 Azure policies (tags + location)")
    print("    • No OPA / Rego policies")
    print("    • No Sentinel policies")
    print("    • No pre-commit hooks")
    print("    • No CI policy gate")
    print("    • Missing: encryption, network, secrets, logging policies")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Scenario 09 — simulate weak policy-as-code setup",
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
