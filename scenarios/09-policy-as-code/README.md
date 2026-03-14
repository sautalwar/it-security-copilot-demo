# Scenario 09 — Policy-as-Code

## Overview

Enforce security policies as code so that **every** infrastructure change must
pass automated policy checks before deployment.  Without policy-as-code,
engineers can accidentally (or deliberately) deploy resources that violate
organizational security standards — unencrypted storage, publicly exposed
databases, missing audit logs, etc.

## What the simulation plants

| Artifact | Problem |
|---|---|
| `infra/policies/azure_policy.json` | Only 2 trivial policies (require tags, require location) — no encryption, networking, or logging checks |
| `infra/deploy_unchecked.sh` | Deployment script with **zero** policy validation |
| No OPA / Rego policies | — |
| No Sentinel policies | — |
| No pre-commit hooks or CI gates | — |

## What the remediation creates

| Artifact | Improvement |
|---|---|
| `infra/policies/azure_policy_comprehensive.json` | 15+ Azure Policy definitions covering CIS benchmarks |
| `infra/policies/security_baseline.rego` | OPA Rego rules — encryption, DDoS, diagnostics, Key Vault, SQL |
| `infra/policies/terraform_sentinel.sentinel` | HashiCorp Sentinel policies |
| `infra/deploy_with_policy.sh` | Deployment script that gates on policy evaluation |
| `infra/policies/compliance_report.json` | Before / after compliance coverage report |

## Usage

```bash
# Plant the weak policy setup
python simulate.py --base-dir ../../

# Fix it
python remediate.py --base-dir ../../
```

## Learning objectives

1. Understand why "tag-only" policies are insufficient.
2. See how OPA Rego and Sentinel complement Azure Policy.
3. Learn to gate deployments on policy evaluation results.
