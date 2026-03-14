# Scenario 05 -- Secret Exposure

## Overview

During a security investigation, **hardcoded secrets** are discovered in
application source code, environment files, and container configurations.
Exposed credentials include cloud API keys, database passwords, webhook URLs,
and signing secrets.  The remediation rotates these credentials and moves them
into environment variables (with an Azure Key Vault integration pattern).

## Indicators of Compromise

| IOC Type | Value |
|----------|-------|
| AWS Access Key | `AKIAIOSFODNN7EXAMPLE` (fake but realistic format) |
| Database Password | Plaintext in `config.py` and `.env.production` |
| GitHub PAT | `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |
| Slack Webhook | Full URL with org/channel tokens |
| JWT Signing Key | Static string shared across environments |

## What the Simulation Does (`simulate.py`)

1. Creates `vulnerable-app/config.py` with five hardcoded secrets.
2. Creates `vulnerable-app/.env.production` with database connection strings
   containing embedded passwords.
3. Creates `vulnerable-app/docker-compose.yml` with secrets passed as plain
   environment variables.

## What the Remediation Does (`remediate.py`)

1. Rewrites `config.py` to load every secret from environment variables.
2. Creates `config_secure.py` with an Azure Key Vault integration pattern,
   validation helpers, and secret-rotation utilities.
3. Deletes `.env.production` and adds it to `.gitignore`.
4. Creates `.env.template` with placeholder values for developer onboarding.
5. Rewrites `docker-compose.yml` to use `env_file` and Docker secrets.
6. Generates a **secret-rotation report** with findings and recommendations.

## Usage

```bash
# Step 1 -- Plant hardcoded secrets
python scenarios/05-secret-exposure/simulate.py

# Step 2 -- Remediate and generate rotation report
python scenarios/05-secret-exposure/remediate.py
```
