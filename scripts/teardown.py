#!/usr/bin/env python3
"""Master teardown script for the IT Security Copilot Demo.

Resets the demo environment to a clean state, ready for the next run.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

# ── ANSI color helpers ──────────────────────────────────────────────────────

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"


def info(msg: str) -> None:
    print(f"  {BLUE}ℹ{RESET}  {msg}")


def success(msg: str) -> None:
    print(f"  {GREEN}✔{RESET}  {msg}")


def warn(msg: str) -> None:
    print(f"  {YELLOW}⚠{RESET}  {msg}")


def error(msg: str) -> None:
    print(f"  {RED}✖{RESET}  {msg}")


def header(msg: str) -> None:
    print(f"\n{BOLD}{CYAN}{'─' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  {msg}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * 60}{RESET}\n")


def step(num: int, total: int, msg: str) -> None:
    print(f"\n  {BOLD}[{num}/{total}]{RESET} {msg}")


# ── Helpers ─────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent


def run(
    cmd: list[str],
    *,
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess command."""
    return subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        check=check,
        capture_output=capture,
        text=True,
    )


def load_env() -> dict[str, str]:
    """Read the .env file and return key-value pairs."""
    env_path = REPO_ROOT / ".env"
    env_vars: dict[str, str] = {}

    if not env_path.exists():
        warn(".env file not found — using defaults")
        return {
            "GITHUB_OWNER": "sautalwar",
            "GITHUB_REPO": "it-security-copilot-demo",
            "DEMO_BASELINE_TAG": "demo-baseline",
        }

    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            env_vars[key.strip()] = value.strip()

    return env_vars


def confirm_action(prompt: str) -> bool:
    """Ask user for confirmation."""
    try:
        answer = input(f"  {YELLOW}?{RESET}  {prompt} [y/N] ").strip().lower()
        return answer in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


# ── Soft Reset Steps ────────────────────────────────────────────────────────


def read_env_config(env: dict[str, str]) -> None:
    """Step 1: Read .env configuration."""
    step(1, 5, "Reading .env configuration")
    owner = env.get("GITHUB_OWNER", "sautalwar")
    repo = env.get("GITHUB_REPO", "it-security-copilot-demo")
    success(f"Repository: {owner}/{repo}")


def reset_to_baseline(env: dict[str, str]) -> None:
    """Step 2: Reset git to the baseline commit."""
    step(2, 5, "Resetting git to baseline commit")

    tag = env.get("DEMO_BASELINE_TAG", "demo-baseline")

    # Check if the tag exists
    result = run(["git", "tag", "-l", tag], capture=True)
    if not result.stdout.strip():
        error(f"Baseline tag '{tag}' not found. Run setup.py first.")
        sys.exit(1)

    run(["git", "checkout", "main"], check=False)
    run(["git", "reset", "--hard", tag])
    success(f"Reset to tag '{tag}'")


def force_push_cleanup(env: dict[str, str]) -> None:
    """Step 3: Force-push to clean up all demo branches."""
    step(3, 5, "Cleaning up remote branches")

    # Delete demo-created branches (prefixed with demo/)
    result = run(
        ["git", "branch", "-r", "--list", "origin/demo/*"],
        capture=True,
        check=False,
    )
    branches = [
        b.strip().replace("origin/", "")
        for b in result.stdout.strip().splitlines()
        if b.strip()
    ]

    if branches:
        for branch in branches:
            run(["git", "push", "origin", "--delete", branch], check=False)
        success(f"Deleted {len(branches)} demo branch(es)")
    else:
        info("No demo branches to clean up")

    # Force-push main to match baseline
    result = run(["git", "branch", "--show-current"], capture=True)
    current_branch = result.stdout.strip() or "main"
    run(["git", "push", "--force", "origin", current_branch], check=False)
    run(["git", "push", "--tags", "-f"], check=False)
    success(f"Force-pushed '{current_branch}' to origin")


def delete_demo_issues(env: dict[str, str]) -> None:
    """Step 4: Delete any demo-created issues."""
    step(4, 5, "Cleaning up demo issues")

    owner = env.get("GITHUB_OWNER", "sautalwar")
    repo = env.get("GITHUB_REPO", "it-security-copilot-demo")

    # List issues with the 'demo' label
    result = run(
        ["gh", "issue", "list",
         "--repo", f"{owner}/{repo}",
         "--label", "demo",
         "--state", "all",
         "--json", "number",
         "--jq", ".[].number"],
        capture=True,
        check=False,
    )

    if result.returncode != 0 or not result.stdout.strip():
        info("No demo issues found")
        return

    issue_numbers = result.stdout.strip().splitlines()
    for num in issue_numbers:
        num = num.strip()
        if num:
            run(
                ["gh", "issue", "close", num,
                 "--repo", f"{owner}/{repo}"],
                check=False,
            )
    success(f"Closed {len(issue_numbers)} demo issue(s)")


def clean_temp_files() -> None:
    """Step 5: Clean up temporary files."""
    step(5, 5, "Cleaning up temporary files")

    cleaned = 0

    # Remove demo-output directory
    demo_output = REPO_ROOT / "demo-output"
    if demo_output.exists():
        import shutil
        shutil.rmtree(demo_output)
        cleaned += 1

    # Remove __pycache__ directories
    for cache_dir in REPO_ROOT.rglob("__pycache__"):
        import shutil
        shutil.rmtree(cache_dir, ignore_errors=True)
        cleaned += 1

    # Remove .pyc files
    for pyc_file in REPO_ROOT.rglob("*.pyc"):
        pyc_file.unlink(missing_ok=True)
        cleaned += 1

    if cleaned > 0:
        success(f"Cleaned {cleaned} temp file(s)/directory(ies)")
    else:
        info("No temporary files to clean")


# ── Hard Reset ──────────────────────────────────────────────────────────────


def hard_reset(env: dict[str, str]) -> None:
    """Delete and recreate the repository (destructive!)."""
    owner = env.get("GITHUB_OWNER", "sautalwar")
    repo = env.get("GITHUB_REPO", "it-security-copilot-demo")
    full_name = f"{owner}/{repo}"

    header(f"⚠️  HARD RESET — This will DELETE {full_name}")

    if not confirm_action(f"Are you sure you want to DELETE {full_name}?"):
        info("Aborted.")
        return

    step(1, 3, f"Deleting repository {full_name}")
    result = run(
        ["gh", "repo", "delete", full_name, "--yes"],
        capture=True,
        check=False,
    )
    if result.returncode == 0:
        success(f"Deleted {full_name}")
    else:
        error(f"Failed to delete: {result.stderr.strip()}")
        sys.exit(1)

    step(2, 3, f"Recreating repository {full_name}")
    result = run(
        ["gh", "repo", "create", full_name,
         "--public",
         "--description", "IT Security Copilot Demo — interactive security scenarios",
         "--confirm"],
        capture=True,
        check=False,
    )
    if result.returncode == 0:
        success(f"Recreated {full_name}")
    else:
        error(f"Failed to recreate: {result.stderr.strip()}")
        sys.exit(1)

    step(3, 3, "Re-running setup")
    run([sys.executable, str(REPO_ROOT / "scripts" / "setup.py")])
    success("Hard reset complete")


# ── Main ────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Teardown / reset the IT Security Copilot Demo environment.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scripts/teardown.py          # Soft reset to baseline\n"
            "  python scripts/teardown.py --hard    # Delete and recreate repo\n"
        ),
    )
    parser.add_argument(
        "--hard",
        action="store_true",
        help="Delete and recreate the repository (destructive!)",
    )
    args = parser.parse_args()

    env = load_env()

    if args.hard:
        hard_reset(env)
        return

    header("🧹  IT Security Copilot Demo — Teardown")

    read_env_config(env)
    reset_to_baseline(env)
    force_push_cleanup(env)
    delete_demo_issues(env)
    clean_temp_files()

    print()
    print(f"  {GREEN}{BOLD}✔  Demo environment reset — ready for next run{RESET}")
    print()
    info(f"Run {BOLD}python scripts/setup.py{RESET} to reinitialize, or")
    info(f"    {BOLD}python scripts/demo_runner.py{RESET} to start the demo.\n")


if __name__ == "__main__":
    main()
