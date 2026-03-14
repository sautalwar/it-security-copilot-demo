#!/usr/bin/env python3
"""Scenario 05 -- Secret Exposure: remediation script.

Rewrites application files to remove hardcoded secrets, introduces environment-
variable loading with validation, creates an Azure Key Vault integration
pattern, and generates a secret-rotation report.
"""
from __future__ import annotations

import argparse
import datetime
import os
import re
import textwrap

ROOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "vulnerable-app")


# ---------------------------------------------------------------------------
# Hardened config.py  (env-var based)
# ---------------------------------------------------------------------------

HARDENED_CONFIG = textwrap.dedent("""\
    #!/usr/bin/env python3
    \"\"\"config.py -- Application configuration (HARDENED).

    All secrets are loaded from environment variables.
    No credentials are stored in source code.
    \"\"\"
    from __future__ import annotations

    import os
    import sys


    def _require_env(name: str) -> str:
        \"\"\"Return the value of an environment variable or exit with an error.\"\"\"
        value = os.environ.get(name)
        if not value:
            print(f"FATAL: Required environment variable {name} is not set.", file=sys.stderr)
            sys.exit(1)
        return value


    # ---- Cloud Provider Credentials -----------------------------------------

    AWS_ACCESS_KEY_ID = _require_env("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = _require_env("AWS_SECRET_ACCESS_KEY")
    AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

    # ---- Database -----------------------------------------------------------

    DB_HOST = os.environ.get("DB_HOST", "localhost")
    DB_PORT = int(os.environ.get("DB_PORT", "5432"))
    DB_NAME = os.environ.get("DB_NAME", "app_development")
    DB_USER = _require_env("DB_USER")
    DB_PASSWORD = _require_env("DB_PASSWORD")

    # ---- API Tokens ---------------------------------------------------------

    GITHUB_API_TOKEN = _require_env("GITHUB_API_TOKEN")
    SLACK_WEBHOOK_URL = _require_env("SLACK_WEBHOOK_URL")
    SENDGRID_API_KEY = _require_env("SENDGRID_API_KEY")

    # ---- Auth / JWT ---------------------------------------------------------

    JWT_SECRET = _require_env("JWT_SECRET")
    JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
    JWT_EXPIRY_HOURS = int(os.environ.get("JWT_EXPIRY_HOURS", "1"))

    # ---- Third-party --------------------------------------------------------

    STRIPE_SECRET_KEY = _require_env("STRIPE_SECRET_KEY")
    TWILIO_AUTH_TOKEN = _require_env("TWILIO_AUTH_TOKEN")


    # ---- Helper -------------------------------------------------------------

    def get_db_url() -> str:
        return (
            f"postgresql://{DB_USER}:{DB_PASSWORD}"
            f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
        )
""")

# ---------------------------------------------------------------------------
# Secure config with Key Vault integration pattern
# ---------------------------------------------------------------------------

SECURE_CONFIG = textwrap.dedent("""\
    #!/usr/bin/env python3
    \"\"\"config_secure.py -- Azure Key Vault integration pattern.

    Demonstrates how to load secrets from Azure Key Vault with a fallback to
    environment variables for local development.  Uses only the standard
    library for the pattern; in production, use azure-identity and
    azure-keyvault-secrets SDKs.

    Security controls:
      * No hardcoded values
      * Validation of all required secrets at startup
      * Secret rotation helper
      * Audit logging of secret access
    \"\"\"
    from __future__ import annotations

    import json
    import logging
    import os
    import time
    from dataclasses import dataclass, field
    from typing import Optional

    logger = logging.getLogger(__name__)


    # ---- Secret Descriptor ---------------------------------------------------

    @dataclass
    class SecretDescriptor:
        \"\"\"Metadata for a single application secret.\"\"\"
        name: str
        env_var: str
        vault_key: str
        required: bool = True
        rotate_days: int = 90
        last_rotated: Optional[str] = None

    # ---- Required secrets for the application --------------------------------

    REQUIRED_SECRETS: list[SecretDescriptor] = [
        SecretDescriptor("AWS Access Key",       "AWS_ACCESS_KEY_ID",     "aws-access-key-id"),
        SecretDescriptor("AWS Secret Key",       "AWS_SECRET_ACCESS_KEY", "aws-secret-access-key"),
        SecretDescriptor("DB Password",          "DB_PASSWORD",           "db-password"),
        SecretDescriptor("GitHub API Token",     "GITHUB_API_TOKEN",      "github-api-token"),
        SecretDescriptor("Slack Webhook URL",    "SLACK_WEBHOOK_URL",     "slack-webhook-url"),
        SecretDescriptor("SendGrid API Key",     "SENDGRID_API_KEY",      "sendgrid-api-key"),
        SecretDescriptor("JWT Secret",           "JWT_SECRET",            "jwt-secret",           rotate_days=30),
        SecretDescriptor("Stripe Secret Key",    "STRIPE_SECRET_KEY",     "stripe-secret-key"),
        SecretDescriptor("Twilio Auth Token",    "TWILIO_AUTH_TOKEN",     "twilio-auth-token"),
        SecretDescriptor("Encryption Key",       "ENCRYPTION_KEY",        "encryption-key",       rotate_days=180),
    ]


    # ---- Key Vault Client (pattern / mock) -----------------------------------

    class KeyVaultClient:
        \"\"\"Mock Azure Key Vault client demonstrating the integration pattern.

        In production replace with:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
        \"\"\"

        def __init__(self, vault_url: str) -> None:
            self.vault_url = vault_url
            logger.info("KeyVaultClient initialised for %s", vault_url)

        def get_secret(self, name: str) -> Optional[str]:
            \"\"\"Retrieve a secret from Key Vault (mock implementation).\"\"\"
            logger.info("Fetching secret '%s' from Key Vault", name)
            # In production:
            #   credential = DefaultAzureCredential()
            #   client = SecretClient(vault_url=self.vault_url, credential=credential)
            #   return client.get_secret(name).value
            return None  # fall back to env var


    # ---- Secret Loader -------------------------------------------------------

    class SecretLoader:
        \"\"\"Load secrets from Key Vault with env-var fallback.\"\"\"

        def __init__(self, vault_url: Optional[str] = None) -> None:
            self.vault: Optional[KeyVaultClient] = None
            if vault_url:
                self.vault = KeyVaultClient(vault_url)
            self._cache: dict[str, str] = {}

        def get(self, descriptor: SecretDescriptor) -> str:
            \"\"\"Retrieve a secret, checking vault first then env vars.\"\"\"
            if descriptor.name in self._cache:
                return self._cache[descriptor.name]

            value: Optional[str] = None

            # Try Key Vault first
            if self.vault:
                value = self.vault.get_secret(descriptor.vault_key)

            # Fall back to environment variable
            if not value:
                value = os.environ.get(descriptor.env_var)

            if not value and descriptor.required:
                raise RuntimeError(
                    f"Required secret '{descriptor.name}' not found in Key Vault "
                    f"or environment variable {descriptor.env_var}"
                )

            if value:
                self._cache[descriptor.name] = value
            return value or ""

        def validate_all(self) -> list[str]:
            \"\"\"Validate that all required secrets are available.  Returns errors.\"\"\"
            errors: list[str] = []
            for desc in REQUIRED_SECRETS:
                try:
                    self.get(desc)
                except RuntimeError as exc:
                    errors.append(str(exc))
            return errors


    # ---- Secret Rotation Helper ----------------------------------------------

    def check_rotation_status(secrets: list[SecretDescriptor]) -> list[dict]:
        \"\"\"Return a list of secrets that are overdue for rotation.\"\"\"
        results: list[dict] = []
        for desc in secrets:
            results.append({
                "name": desc.name,
                "vault_key": desc.vault_key,
                "rotate_every_days": desc.rotate_days,
                "last_rotated": desc.last_rotated or "unknown",
                "status": "OVERDUE" if not desc.last_rotated else "OK",
            })
        return results


    # ---- Startup validation --------------------------------------------------

    def init_config() -> SecretLoader:
        \"\"\"Initialise configuration and validate all secrets.\"\"\"
        vault_url = os.environ.get("AZURE_KEYVAULT_URL")
        loader = SecretLoader(vault_url=vault_url)
        errors = loader.validate_all()
        if errors:
            for err in errors:
                logger.error(err)
            raise SystemExit("Configuration validation failed -- see errors above.")
        logger.info("All %d secrets validated successfully.", len(REQUIRED_SECRETS))
        return loader
""")

# ---------------------------------------------------------------------------
# .env.template
# ---------------------------------------------------------------------------

ENV_TEMPLATE = textwrap.dedent("""\
    # .env.template -- Copy to .env and fill in real values
    # NEVER commit the .env file to version control!

    # Cloud Provider
    AWS_ACCESS_KEY_ID=
    AWS_SECRET_ACCESS_KEY=
    AWS_REGION=us-east-1

    # Database
    DB_HOST=localhost
    DB_PORT=5432
    DB_NAME=app_development
    DB_USER=
    DB_PASSWORD=

    # API Tokens
    GITHUB_API_TOKEN=
    SLACK_WEBHOOK_URL=
    SENDGRID_API_KEY=

    # Auth / JWT
    JWT_SECRET=
    JWT_ALGORITHM=HS256
    JWT_EXPIRY_HOURS=1

    # Third-party
    STRIPE_SECRET_KEY=
    TWILIO_AUTH_TOKEN=

    # Encryption
    ENCRYPTION_KEY=

    # Azure Key Vault (optional -- enables vault-based secret loading)
    # AZURE_KEYVAULT_URL=https://myapp-kv.vault.azure.net/
""")

# ---------------------------------------------------------------------------
# Hardened docker-compose.yml
# ---------------------------------------------------------------------------

HARDENED_DOCKER_COMPOSE = textwrap.dedent("""\
    # docker-compose.yml -- Production stack (HARDENED)
    #
    # Secrets are loaded from:
    #   1. An env_file (.env) that is NOT committed to version control
    #   2. Docker secrets for highly sensitive values
    version: "3.8"

    services:
      web:
        image: myapp/web:latest
        ports:
          - "443:8000"
        env_file:
          - .env
        secrets:
          - db_password
          - jwt_secret
          - stripe_key
        environment:
          - DB_PASSWORD_FILE=/run/secrets/db_password
          - JWT_SECRET_FILE=/run/secrets/jwt_secret
          - STRIPE_SECRET_KEY_FILE=/run/secrets/stripe_key
        depends_on:
          - db
          - redis

      db:
        image: postgres:15
        env_file:
          - .env
        secrets:
          - db_password
        environment:
          - POSTGRES_USER_FILE=/run/secrets/db_user
          - POSTGRES_PASSWORD_FILE=/run/secrets/db_password
          - POSTGRES_DB=app_production
        volumes:
          - pgdata:/var/lib/postgresql/data

      redis:
        image: redis:7
        command: redis-server --requirepass /run/secrets/redis_password
        secrets:
          - redis_password

    secrets:
      db_password:
        file: ./secrets/db_password.txt
      db_user:
        file: ./secrets/db_user.txt
      jwt_secret:
        file: ./secrets/jwt_secret.txt
      stripe_key:
        file: ./secrets/stripe_key.txt
      redis_password:
        file: ./secrets/redis_password.txt

    volumes:
      pgdata:
""")

# ---------------------------------------------------------------------------
# Gitignore additions
# ---------------------------------------------------------------------------

GITIGNORE_ADDITIONS = textwrap.dedent("""\

    # -- Secret-exposure remediation -----------------------------------------
    .env
    .env.*
    !.env.template
    secrets/
    *.pem
    *.key
    **/credentials*
    **/config.py
""")

# ---------------------------------------------------------------------------
# Secret detection patterns
# ---------------------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
    (r"sk_live_[A-Za-z0-9]{24}", "Stripe Secret Key"),
    (r"SG\.[A-Za-z0-9._-]+", "SendGrid API Key"),
    (r"xox[baprs]-[A-Za-z0-9-]+", "Slack Token"),
    (r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "Slack Webhook"),
    (r"(?i)password\s*=\s*[\"'][^\"']+[\"']", "Hardcoded Password"),
    (r"(?i)secret\s*=\s*[\"'][^\"']+[\"']", "Hardcoded Secret"),
]


def _scan_file_for_secrets(file_path: str) -> list[dict[str, str]]:
    """Scan a file for known secret patterns."""
    findings: list[dict[str, str]] = []
    if not os.path.isfile(file_path):
        return findings
    with open(file_path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            for pattern, label in SECRET_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "file": file_path,
                        "line": str(lineno),
                        "type": label,
                        "snippet": line.strip()[:80],
                    })
    return findings


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def _generate_report(
    findings: list[dict[str, str]],
    files_remediated: list[str],
) -> str:
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("  SECRET EXPOSURE -- ROTATION & REMEDIATION REPORT")
    lines.append(f"  Generated: {datetime.datetime.utcnow().isoformat()}Z")
    lines.append("=" * 70)
    lines.append("")

    # Findings
    lines.append(f"Secrets detected in source code: {len(findings)}")
    lines.append("")
    if findings:
        lines.append("--- Detected Secrets ---")
        lines.append(f"  {'File':<30} {'Line':<6} {'Type':<30} Snippet")
        lines.append(f"  {'-'*28}  {'-'*4}  {'-'*28}  {'-'*30}")
        for f in findings:
            lines.append(
                f"  {os.path.basename(f['file']):<30} {f['line']:<6} "
                f"{f['type']:<30} {f['snippet'][:30]}"
            )
        lines.append("")

    # Remediation actions
    lines.append("--- Remediation Actions Taken ---")
    for path in files_remediated:
        lines.append(f"  [+] {path}")
    lines.append("")

    # Rotation recommendations
    lines.append("--- Secret Rotation Checklist ---")
    rotation_items = [
        ("AWS Access Key / Secret Key", "Rotate in IAM console, update env vars"),
        ("Database Password", "ALTER USER in PostgreSQL, update vault/env"),
        ("GitHub PAT", "Regenerate in GitHub Settings > Developer settings"),
        ("Slack Webhook URL", "Regenerate in Slack App management"),
        ("SendGrid API Key", "Revoke and re-create in SendGrid dashboard"),
        ("JWT Signing Secret", "Generate new random 256-bit key"),
        ("Stripe Secret Key", "Roll key in Stripe Dashboard > API keys"),
        ("Twilio Auth Token", "Rotate in Twilio Console > Account settings"),
        ("Redis Password", "Update CONFIG SET requirepass, restart clients"),
        ("Encryption Key", "Re-encrypt PII with new key, retire old key"),
    ]
    for secret, action in rotation_items:
        lines.append(f"  [ ] {secret}")
        lines.append(f"      Action: {action}")
    lines.append("")

    lines.append("--- Recommendations ---")
    lines.append("  1. Rotate ALL exposed credentials immediately.")
    lines.append("  2. Enable Azure Key Vault (or equivalent) for secret storage.")
    lines.append("  3. Add pre-commit hooks to scan for secrets (e.g., detect-secrets).")
    lines.append("  4. Audit git history for previously committed secrets.")
    lines.append("  5. Enable secret scanning on the GitHub repository.")
    lines.append("  6. Implement least-privilege access for all service accounts.")
    lines.append("")
    lines.append("=" * 70)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def remediate(output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)

    files_remediated: list[str] = []

    # 1. Scan existing files for secrets
    all_findings: list[dict[str, str]] = []
    for fname in ("config.py", ".env.production", "docker-compose.yml"):
        fpath = os.path.join(output_dir, fname)
        all_findings.extend(_scan_file_for_secrets(fpath))

    # 2. Rewrite config.py with env-var loading
    config_path = os.path.join(output_dir, "config.py")
    with open(config_path, "w", encoding="utf-8") as f:
        f.write(HARDENED_CONFIG)
    print(f"[+] Rewrote config.py (secrets -> env vars) -> {config_path}")
    files_remediated.append("config.py (rewritten to use env vars)")

    # 3. Create config_secure.py with Key Vault pattern
    secure_path = os.path.join(output_dir, "config_secure.py")
    with open(secure_path, "w", encoding="utf-8") as f:
        f.write(SECURE_CONFIG)
    print(f"[+] Created secure config with Key Vault pattern -> {secure_path}")
    files_remediated.append("config_secure.py (Azure Key Vault pattern)")

    # 4. Remove .env.production
    env_prod_path = os.path.join(output_dir, ".env.production")
    if os.path.isfile(env_prod_path):
        os.remove(env_prod_path)
        print(f"[+] Removed dangerous credentials file -> {env_prod_path}")
        files_remediated.append(".env.production (DELETED)")
    else:
        print("[*] .env.production not found -- skipping removal.")

    # 5. Update .gitignore
    gitignore_path = os.path.join(output_dir, ".gitignore")
    existing = ""
    if os.path.isfile(gitignore_path):
        with open(gitignore_path, encoding="utf-8") as f:
            existing = f.read()
    if ".env.*" not in existing:
        with open(gitignore_path, "a", encoding="utf-8") as f:
            f.write(GITIGNORE_ADDITIONS)
        print(f"[+] Updated .gitignore with secret-exclusion rules -> {gitignore_path}")
        files_remediated.append(".gitignore (updated with secret exclusions)")

    # 6. Create .env.template
    template_path = os.path.join(output_dir, ".env.template")
    with open(template_path, "w", encoding="utf-8") as f:
        f.write(ENV_TEMPLATE)
    print(f"[+] Created .env.template for developer onboarding -> {template_path}")
    files_remediated.append(".env.template (placeholder values)")

    # 7. Rewrite docker-compose.yml
    compose_path = os.path.join(output_dir, "docker-compose.yml")
    with open(compose_path, "w", encoding="utf-8") as f:
        f.write(HARDENED_DOCKER_COMPOSE)
    print(f"[+] Rewrote docker-compose.yml (env_file + Docker secrets) -> {compose_path}")
    files_remediated.append("docker-compose.yml (env_file + Docker secrets)")

    # 8. Create Docker secret placeholder files
    secrets_dir = os.path.join(output_dir, "secrets")
    os.makedirs(secrets_dir, exist_ok=True)
    for secret_name in ("db_password", "db_user", "jwt_secret", "stripe_key", "redis_password"):
        secret_file = os.path.join(secrets_dir, f"{secret_name}.txt")
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write(f"<REPLACE_WITH_{secret_name.upper()}>\n")
    print(f"[+] Created Docker secret placeholder files -> {secrets_dir}")
    files_remediated.append("secrets/ directory (placeholder files)")

    # 9. Generate report
    report = _generate_report(all_findings, files_remediated)
    report_path = os.path.join(output_dir, "secret_rotation_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print(f"[+] Generated secret-rotation report -> {report_path}")
    print()
    print(report)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Remediate hardcoded secrets and generate rotation report.",
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
