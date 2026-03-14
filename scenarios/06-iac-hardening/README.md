# Scenario 06 -- IaC Hardening

## Overview

Infrastructure-as-Code templates contain critical security misconfigurations:
public storage accounts, unprotected databases, missing encryption, and
overly-permissive identity settings.  Both **Azure Bicep** and **Terraform
(AWS)** templates are audited and hardened.

## Misconfigurations

| Resource | Misconfiguration |
|----------|-----------------|
| Storage Account | Public blob access enabled |
| SQL Server | Public endpoint, no firewall rules |
| Virtual Network | No NSG associations |
| Key Vault | Soft delete disabled |
| App Service | HTTP allowed (no HTTPS-only) |
| S3 Bucket (TF) | Public ACL, no encryption |
| EC2 Instance (TF) | Open 0.0.0.0/0 ingress |
| RDS (TF) | Publicly accessible |
| IAM Role (TF) | AdministratorAccess policy attached |

## What the Simulation Does (`simulate.py`)

1. Creates `infra/main.bicep` with insecure Azure resources.
2. Creates `infra/main.tf` with insecure AWS Terraform resources.

## What the Remediation Does (`remediate.py`)

1. Rewrites `main.bicep` with hardened configuration (private access,
   encryption, managed identity, diagnostic settings, etc.).
2. Rewrites `main.tf` with hardened Terraform (private ACLs, encryption,
   least-privilege IAM, restricted security groups).
3. Generates a compliance diff report showing before -> after for each resource.

## Usage

```bash
# Step 1 -- Create insecure IaC templates
python scenarios/06-iac-hardening/simulate.py

# Step 2 -- Harden templates and generate compliance report
python scenarios/06-iac-hardening/remediate.py
```
