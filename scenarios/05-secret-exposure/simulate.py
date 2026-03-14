#!/usr/bin/env python3
"""Scenario 05 -- Secret Exposure: simulation script.

Creates application files that contain hardcoded secrets (API keys, database
passwords, tokens, webhook URLs) to demonstrate the risk of credential leakage
in source code and configuration files.
"""
from __future__ import annotations

import argparse
import os
import textwrap

ROOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "vulnerable-app")


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


# ---------------------------------------------------------------------------
# Vulnerable config.py with hardcoded secrets
# ---------------------------------------------------------------------------

VULNERABLE_CONFIG = textwrap.dedent("""\
    #!/usr/bin/env python3
    \"\"\"config.py -- Application configuration.

    WARNING: This file is intentionally vulnerable for demonstration purposes.
    It contains hardcoded secrets that should NEVER appear in source code.
    \"\"\"
    from __future__ import annotations

    # ---- Cloud Provider Credentials -----------------------------------------

    AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
    AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    AWS_REGION = "us-east-1"

    # ---- Database -----------------------------------------------------------

    DB_HOST = "prod-db-01.internal.example.com"
    DB_PORT = 5432
    DB_NAME = "app_production"
    DB_USER = "app_admin"
    DB_PASSWORD = "SuperSecret123!"

    # ---- API Tokens ---------------------------------------------------------

    GITHUB_API_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    SLACK_WEBHOOK_URL = "https://hooks.example.invalid/services/TXXXFAKE0/BXXXFAKE0/FAKE_WEBHOOK_TOKEN_HERE"
    SENDGRID_API_KEY = "SG.xxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

    # ---- Auth / JWT ---------------------------------------------------------

    JWT_SECRET = "my-super-secret-key-12345"
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRY_HOURS = 24

    # ---- Third-party --------------------------------------------------------

    STRIPE_SECRET_KEY = "sk_FAKE_xxxxxxxxxxxxxxxxxxxxxxxx"
    TWILIO_AUTH_TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

    # ---- Helper -------------------------------------------------------------

    def get_db_url() -> str:
        return (
            f"postgresql://{DB_USER}:{DB_PASSWORD}"
            f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
        )
""")

# ---------------------------------------------------------------------------
# Vulnerable .env.production
# ---------------------------------------------------------------------------

VULNERABLE_ENV_PRODUCTION = textwrap.dedent("""\
    # .env.production -- Production environment variables
    # WARNING: Contains real credentials -- do NOT commit to version control!

    DATABASE_URL=postgresql://app_admin:SuperSecret123!@prod-db-01.internal.example.com:5432/app_production
    REDIS_URL=redis://:RedisP@ssw0rd!@prod-redis-01.internal.example.com:6379/0
    MONGODB_URI=mongodb://mongo_admin:M0ng0Secret!@prod-mongo-01.internal.example.com:27017/app?authSource=admin

    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

    GITHUB_API_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    SLACK_WEBHOOK_URL=https://hooks.example.invalid/services/TXXXFAKE0/BXXXFAKE0/FAKE_WEBHOOK_TOKEN_HERE
    SENDGRID_API_KEY=SG.xxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

    JWT_SECRET=my-super-secret-key-12345
    STRIPE_SECRET_KEY=sk_FAKE_xxxxxxxxxxxxxxxxxxxxxxxx
    TWILIO_AUTH_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

    # Encryption key for PII at rest
    ENCRYPTION_KEY=0123456789abcdef0123456789abcdef
""")

# ---------------------------------------------------------------------------
# Vulnerable docker-compose.yml
# ---------------------------------------------------------------------------

VULNERABLE_DOCKER_COMPOSE = textwrap.dedent("""\
    # docker-compose.yml -- Production stack
    # WARNING: Secrets are passed as plain environment variables!
    version: "3.8"

    services:
      web:
        image: myapp/web:latest
        ports:
          - "80:8000"
        environment:
          - DATABASE_URL=postgresql://app_admin:SuperSecret123!@db:5432/app_production
          - REDIS_URL=redis://:RedisP@ssw0rd!@redis:6379/0
          - JWT_SECRET=my-super-secret-key-12345
          - AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
          - AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
          - GITHUB_API_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
          - SLACK_WEBHOOK_URL=https://hooks.example.invalid/services/TXXXFAKE0/BXXXFAKE0/FAKE_WEBHOOK_TOKEN_HERE
          - STRIPE_SECRET_KEY=sk_FAKE_xxxxxxxxxxxxxxxxxxxxxxxx
        depends_on:
          - db
          - redis

      db:
        image: postgres:15
        environment:
          - POSTGRES_USER=app_admin
          - POSTGRES_PASSWORD=SuperSecret123!
          - POSTGRES_DB=app_production
        ports:
          - "5432:5432"
        volumes:
          - pgdata:/var/lib/postgresql/data

      redis:
        image: redis:7
        command: redis-server --requirepass RedisP@ssw0rd!
        ports:
          - "6379:6379"

    volumes:
      pgdata:
""")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def simulate(output_dir: str) -> None:
    _ensure_dir(output_dir)

    # 1. config.py
    config_path = os.path.join(output_dir, "config.py")
    with open(config_path, "w", encoding="utf-8") as f:
        f.write(VULNERABLE_CONFIG)
    print(f"[+] Created INSECURE config with hardcoded secrets -> {config_path}")

    # 2. .env.production
    env_path = os.path.join(output_dir, ".env.production")
    with open(env_path, "w", encoding="utf-8") as f:
        f.write(VULNERABLE_ENV_PRODUCTION)
    print(f"[+] Created .env.production with embedded passwords -> {env_path}")

    # 3. docker-compose.yml
    compose_path = os.path.join(output_dir, "docker-compose.yml")
    with open(compose_path, "w", encoding="utf-8") as f:
        f.write(VULNERABLE_DOCKER_COMPOSE)
    print(f"[+] Created docker-compose.yml with inline secrets -> {compose_path}")

    # Summary
    print()
    print("=== Simulation Summary ===")
    print(f"  config.py          : {config_path}")
    print(f"  .env.production    : {env_path}")
    print(f"  docker-compose.yml : {compose_path}")
    print()
    print("  Hardcoded secrets found:")
    print("    - AWS Access Key / Secret Key")
    print("    - Database password (SuperSecret123!)")
    print("    - GitHub PAT (ghp_...)")
    print("    - Slack Webhook URL")
    print("    - JWT signing secret")
    print("    - Stripe secret key")
    print("    - Redis password")
    print("    - MongoDB credentials")
    print("    - SendGrid API key")
    print("    - Twilio auth token")
    print("    - PII encryption key")
    print()
    print("[!] All secrets are in plaintext.  Run remediate.py to fix.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulate hardcoded secrets in application source code.",
    )
    parser.add_argument(
        "--output-dir",
        default=ROOT_DIR,
        help="Directory to write vulnerable files into (default: vulnerable-app/).",
    )
    args = parser.parse_args()
    simulate(args.output_dir)


if __name__ == "__main__":
    main()
