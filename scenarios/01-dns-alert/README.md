# Scenario 01 — DNS Exfiltration Alert

## Overview

A DNS tunneling / data-exfiltration attack has been detected on the network.
An attacker is using **randomised subdomain queries** to a command-and-control
(C2) domain (`evil-c2.example.com`) to covertly exfiltrate sensitive data from
the environment.

## Indicators of Compromise

| IOC Type | Value |
|----------|-------|
| C2 Domain | `evil-c2.example.com` |
| Technique | Base64-encoded data in subdomain labels |
| Pattern | High-frequency DNS queries (50+ / min) |
| Record types | A, TXT (TXT used for large-payload exfil) |

## What the Simulation Does (`simulate.py`)

1. Creates `vulnerable-app/dns_monitor.py` — a **deliberately insecure** DNS
   resolver configuration:
   - No query logging enabled
   - Allows recursive queries from any source
   - No rate limiting on DNS queries
   - No blocklist of known-bad domains
   - Accepts DNS-over-HTTPS without validation
2. Creates `vulnerable-app/dns_queries.log` containing mixed traffic:
   - Normal queries (google.com, microsoft.com, …)
   - Suspicious queries with Base64-encoded subdomains to the C2 domain
   - High-frequency bursts (50+ queries in 1 minute)
   - TXT record queries with large payloads (data exfiltration pattern)

## What the Remediation Does (`remediate.py`)

1. Rewrites `vulnerable-app/dns_monitor.py` to add:
   - Structured DNS query logging
   - Domain blocklist checks
   - Rate limiting (max 10 queries/sec per source IP)
   - DNS tunneling detection via Shannon entropy analysis
   - Alert generation for suspicious patterns
2. Analyses `vulnerable-app/dns_queries.log` and generates a security report
   showing detected threats.

## Usage

```bash
# Step 1 — Plant the vulnerable configuration and sample logs
python scenarios/01-dns-alert/simulate.py

# Step 2 — Remediate and generate security report
python scenarios/01-dns-alert/remediate.py
```
