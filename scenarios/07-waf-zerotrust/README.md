# Scenario 07 -- WAF & Zero Trust

## Overview

Web applications are exposed without adequate WAF protection and the network
uses a flat topology where every service can reach every other service.  The
remediation deploys comprehensive WAF rules (OWASP CRS, bot protection, rate
limiting, geo-filtering) and implements Zero Trust network segmentation.

## Security Gaps

| Area | Gap |
|------|-----|
| WAF | No OWASP Core Rule Set |
| WAF | No bot protection |
| WAF | No rate limiting |
| WAF | No geo-filtering |
| Network | Single flat subnet |
| Network | No microsegmentation |
| Network | No service endpoints or private endpoints |
| Network | No tier-based access control |

## What the Simulation Does (`simulate.py`)

1. Creates `infra/waf_rules.json` -- a skeletal WAF policy with everything
   disabled.
2. Creates `infra/network_segmentation.json` -- a flat network with one subnet,
   no NSGs, and no access restrictions.

## What the Remediation Does (`remediate.py`)

1. Creates `infra/waf_rules_hardened.json` with OWASP 3.2 CRS, bot protection,
   rate limiting (100 req/min per IP), geo-filtering, and custom rules for
   SQL injection, XSS, and path traversal.
2. Creates `infra/zero_trust_segmentation.json` with four-tier subnets
   (web, app, data, management), NSGs between tiers, private endpoints, service
   endpoints, and just-in-time VM access.
3. Generates a **Zero Trust compliance matrix**.

## Usage

```bash
# Step 1 -- Create minimal WAF and flat network configs
python scenarios/07-waf-zerotrust/simulate.py

# Step 2 -- Deploy hardened WAF and Zero Trust segmentation
python scenarios/07-waf-zerotrust/remediate.py
```
