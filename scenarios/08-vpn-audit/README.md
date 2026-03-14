# Scenario 08 -- VPN Audit

## Overview

A VPN gateway audit reveals weak cryptographic settings, expired user
certificates, missing MFA, and overly-permissive split tunnelling.  The
remediation hardens the VPN configuration, audits the user roster, and
generates platform-specific remediation commands.

## Findings

| Finding | Severity |
|---------|----------|
| IKEv1 instead of IKEv2 | Critical |
| DES encryption | Critical |
| MD5 hash algorithm | Critical |
| DH Group 1 (768-bit) | Critical |
| Pre-shared key `password123` | Critical |
| Unrestricted split tunnelling | High |
| No certificate-based auth | High |
| No MFA integration | High |
| 24-hour session timeout | Medium |
| Users with expired certificates | High |
| Inactive users still enabled | Medium |

## What the Simulation Does (`simulate.py`)

1. Creates `vulnerable-app/vpn_config.json` with weak VPN cryptographic
   settings, no MFA, and no certificate-based auth.
2. Creates `vulnerable-app/vpn_users.json` with a user roster containing
   expired certificates, missing MFA, and inactive accounts.

## What the Remediation Does (`remediate.py`)

1. Creates `vulnerable-app/vpn_config_hardened.json` with IKEv2, AES-256-GCM,
   SHA-384, ECDH Group 20, certificate auth, MFA, and 8-hour session timeout.
2. Analyses the user roster and flags non-compliant accounts.
3. Generates `vulnerable-app/vpn_audit_report.md` with findings and
   per-platform remediation commands (Cisco ASA, FortiGate, Azure VPN).

## Usage

```bash
# Step 1 -- Create weak VPN config and user roster
python scenarios/08-vpn-audit/simulate.py

# Step 2 -- Harden VPN and generate audit report
python scenarios/08-vpn-audit/remediate.py
```
