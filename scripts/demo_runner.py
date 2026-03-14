#!/usr/bin/env python3
"""Interactive CLI demo runner for the IT Security Copilot Demo.

Presents a menu of 12 security scenarios and orchestrates the full
simulate → detect → remediate → verify cycle for each.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
import webbrowser
from dataclasses import dataclass
from pathlib import Path

# ── ANSI color helpers ──────────────────────────────────────────────────────

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BG_GREEN = "\033[42m"
BG_RED = "\033[41m"
BG_BLUE = "\033[44m"


def info(msg: str) -> None:
    print(f"  {BLUE}ℹ{RESET}  {msg}")


def success(msg: str) -> None:
    print(f"  {GREEN}✔{RESET}  {msg}")


def warn(msg: str) -> None:
    print(f"  {YELLOW}⚠{RESET}  {msg}")


def error(msg: str) -> None:
    print(f"  {RED}✖{RESET}  {msg}")


def header(msg: str) -> None:
    print(f"\n{BOLD}{CYAN}{'═' * 64}{RESET}")
    print(f"{BOLD}{CYAN}  {msg}{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 64}{RESET}\n")


def section(msg: str) -> None:
    print(f"\n  {BOLD}{MAGENTA}── {msg} ──{RESET}\n")


def progress_bar(current: int, total: int, width: int = 30) -> str:
    """Render a text-based progress bar."""
    filled = int(width * current / total)
    bar = f"{'█' * filled}{'░' * (width - filled)}"
    pct = int(100 * current / total)
    return f"  [{bar}] {pct}% ({current}/{total})"


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
    """Read the .env file."""
    env_path = REPO_ROOT / ".env"
    env_vars: dict[str, str] = {}
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                env_vars[key.strip()] = value.strip()
    return env_vars


def wait_for_enter(prompt: str = "Press Enter to continue...") -> None:
    """Pause and wait for the user to press Enter."""
    try:
        input(f"\n  {YELLOW}⏸{RESET}  {prompt}")
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)


def clear_screen() -> None:
    """Clear the terminal screen."""
    os.system("cls" if platform.system() == "Windows" else "clear")


# ── Scenario Definitions ───────────────────────────────────────────────────


@dataclass
class Scenario:
    """Represents a single security demo scenario."""

    number: int
    slug: str
    title: str
    description: str
    icon: str

    @property
    def dir_name(self) -> str:
        return f"{self.number:02d}-{self.slug}"

    @property
    def scenario_dir(self) -> Path:
        return REPO_ROOT / "scenarios" / self.dir_name

    @property
    def simulate_script(self) -> Path:
        return self.scenario_dir / "simulate.py"

    @property
    def remediate_script(self) -> Path:
        return self.scenario_dir / "remediate.py"


SCENARIOS: list[Scenario] = [
    Scenario(1, "dns-exfiltration", "DNS Exfiltration Detection",
             "Detect and block data exfiltration through encoded DNS queries", "🔍"),
    Scenario(2, "firewall-misconfig", "Firewall Misconfiguration",
             "Identify overly permissive firewall rules and tighten to least-privilege", "🧱"),
    Scenario(3, "secrets-in-code", "Secrets in Source Code",
             "Find hardcoded API keys and tokens; rotate and migrate to secrets manager", "🔑"),
    Scenario(4, "iam-over-privilege", "IAM Over-Privilege",
             "Detect wildcard IAM policies and reduce to minimum permissions", "👤"),
    Scenario(5, "tls-ssl-weakness", "TLS/SSL Weakness",
             "Find deprecated TLS configs and weak ciphers; enforce TLS 1.2+", "🔒"),
    Scenario(6, "container-escape", "Container Escape Risk",
             "Detect privileged containers and missing security contexts", "📦"),
    Scenario(7, "log-injection", "Log Injection",
             "Find unsanitized log inputs vulnerable to log forging", "📝"),
    Scenario(8, "ssrf-vulnerability", "SSRF Vulnerability",
             "Detect Server-Side Request Forgery; add URL validation", "🌐"),
    Scenario(9, "dependency-confusion", "Dependency Confusion",
             "Identify packages vulnerable to dependency confusion attacks", "📦"),
    Scenario(10, "cicd-pipeline-poisoning", "CI/CD Pipeline Poisoning",
              "Find insecure GitHub Actions workflows; harden pipelines", "⚙️"),
    Scenario(11, "network-segmentation", "Network Segmentation",
              "Detect flat network topologies; implement microsegmentation", "🕸️"),
    Scenario(12, "incident-response", "Incident Response Automation",
              "Build automated incident response playbooks", "🚨"),
]


# ── Menu ────────────────────────────────────────────────────────────────────


def print_menu() -> None:
    """Display the scenario selection menu."""
    header("🛡️  IT Security Copilot Demo — Scenario Menu")

    print(f"  {DIM}Select a scenario to run, or 'all' for a full sequential demo.{RESET}\n")

    for s in SCENARIOS:
        status_indicator = "○"
        scenario_path = s.scenario_dir
        if scenario_path.exists():
            status_indicator = f"{GREEN}●{RESET}"
        else:
            status_indicator = f"{DIM}○{RESET}"

        print(f"   {status_indicator}  {BOLD}{s.number:2d}{RESET}  {s.icon}  {s.title}")
        print(f"       {DIM}{s.description}{RESET}")

    print(f"\n   {BOLD} A{RESET}  🎯  Run ALL scenarios sequentially")
    print(f"   {BOLD} Q{RESET}  🚪  Quit\n")


def get_selection() -> list[Scenario] | None:
    """Get the user's scenario selection."""
    try:
        choice = input(f"  {CYAN}▶{RESET}  Enter scenario number (1-12), 'A' for all, or 'Q' to quit: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return None

    if choice in ("q", "quit", "exit"):
        return None

    if choice in ("a", "all"):
        return list(SCENARIOS)

    try:
        num = int(choice)
        if 1 <= num <= 12:
            return [SCENARIOS[num - 1]]
        else:
            error("Please enter a number between 1 and 12.")
            return get_selection()
    except ValueError:
        error("Invalid input. Enter a number, 'A', or 'Q'.")
        return get_selection()


# ── Scenario Execution ─────────────────────────────────────────────────────


@dataclass
class ScenarioResult:
    """Result of running a single scenario."""

    scenario: Scenario
    success: bool
    duration_seconds: float
    error_message: str = ""


def run_scenario(scenario: Scenario, index: int, total: int, env: dict[str, str]) -> ScenarioResult:
    """Execute a single scenario through the full demo cycle."""
    owner = env.get("GITHUB_OWNER", "sautalwar")
    repo = env.get("GITHUB_REPO", "it-security-copilot-demo")
    start_time = time.time()

    section(f"Scenario {scenario.number}/{len(SCENARIOS)}: {scenario.icon} {scenario.title}")
    print(f"  {DIM}{scenario.description}{RESET}")
    print(f"\n{progress_bar(index, total)}\n")

    # ── Step A: Simulate ────────────────────────────────────────────────
    print(f"  {BOLD}Step 1/6{RESET}  {YELLOW}▶ Simulating vulnerability...{RESET}")

    if scenario.simulate_script.exists():
        result = run(
            [sys.executable, str(scenario.simulate_script)],
            check=False,
            capture=True,
        )
        if result.returncode != 0:
            error(f"Simulate script failed: {result.stderr.strip()}")
            return ScenarioResult(scenario, False, time.time() - start_time,
                                  f"Simulate failed: {result.stderr.strip()}")
        success("Vulnerability planted")
    else:
        warn(f"No simulate script found at {scenario.simulate_script}")
        info("Skipping simulation — you can manually introduce the vulnerability")

    # ── Step B: Commit & push vulnerable code ───────────────────────────
    print(f"  {BOLD}Step 2/6{RESET}  {YELLOW}▶ Committing vulnerable code...{RESET}")

    branch_name = f"demo/{scenario.slug}"
    run(["git", "checkout", "-b", branch_name], check=False)
    run(["git", "add", "-A"])

    status_result = run(["git", "status", "--porcelain"], capture=True)
    if status_result.stdout.strip():
        run(["git", "commit", "-m", f"vuln: introduce {scenario.title.lower()} scenario"])
        success(f"Committed on branch '{branch_name}'")
    else:
        info("No changes to commit")

    run(["git", "push", "-u", "origin", branch_name, "--force"], check=False)
    success("Pushed to GitHub")

    # ── Step C: Pause for Copilot demo ──────────────────────────────────
    print(f"\n  {BOLD}Step 3/6{RESET}  {BG_BLUE}{WHITE} COPILOT DEMO TIME {RESET}")
    print(f"\n  {CYAN}Now open VS Code and use GitHub Copilot to:{RESET}")
    print(f"    1. Review the vulnerable code")
    print(f"    2. Ask Copilot to identify the security issue")
    print(f"    3. Let Copilot suggest the remediation")
    wait_for_enter("Press Enter when ready to apply the fix...")

    # ── Step D: Remediate ───────────────────────────────────────────────
    print(f"  {BOLD}Step 4/6{RESET}  {YELLOW}▶ Applying remediation...{RESET}")

    if scenario.remediate_script.exists():
        result = run(
            [sys.executable, str(scenario.remediate_script)],
            check=False,
            capture=True,
        )
        if result.returncode != 0:
            error(f"Remediate script failed: {result.stderr.strip()}")
            return ScenarioResult(scenario, False, time.time() - start_time,
                                  f"Remediate failed: {result.stderr.strip()}")
        success("Remediation applied")
    else:
        warn(f"No remediate script found at {scenario.remediate_script}")
        info("Skipping auto-remediation — apply the fix manually in VS Code")

    # ── Step E: Commit & push fix ───────────────────────────────────────
    print(f"  {BOLD}Step 5/6{RESET}  {YELLOW}▶ Committing fix...{RESET}")

    run(["git", "add", "-A"])
    status_result = run(["git", "status", "--porcelain"], capture=True)
    if status_result.stdout.strip():
        run(["git", "commit", "-m", f"fix: remediate {scenario.title.lower()}"])
        success("Fix committed")
    else:
        info("No changes to commit")

    run(["git", "push", "origin", branch_name, "--force"], check=False)
    success("Fix pushed to GitHub")

    # ── Step F: Trigger & watch workflow ────────────────────────────────
    print(f"  {BOLD}Step 6/6{RESET}  {YELLOW}▶ Triggering security scan workflow...{RESET}")

    workflow_url = f"https://github.com/{owner}/{repo}/actions"

    # Try to trigger a workflow dispatch
    trigger_result = run(
        ["gh", "workflow", "run", "security-scan.yml",
         "--repo", f"{owner}/{repo}",
         "--ref", branch_name],
        capture=True,
        check=False,
    )

    if trigger_result.returncode == 0:
        success("Workflow triggered")
        info(f"Actions URL: {workflow_url}")

        # Open in browser
        try:
            webbrowser.open(workflow_url)
        except Exception:
            pass

        # Poll for completion
        print(f"\n  {DIM}Waiting for workflow to complete...{RESET}")
        watch_result = run(
            ["gh", "run", "watch",
             "--repo", f"{owner}/{repo}",
             "--exit-status"],
            capture=True,
            check=False,
        )

        if watch_result.returncode == 0:
            success("Workflow passed ✓")
        else:
            warn("Workflow completed with issues — check the Actions tab")
    else:
        warn("Could not trigger workflow (may not exist yet)")
        info(f"Check manually: {workflow_url}")

    # Return to main branch
    run(["git", "checkout", "main"], check=False)

    elapsed = time.time() - start_time
    success(f"Scenario complete in {elapsed:.1f}s")

    return ScenarioResult(scenario, True, elapsed)


# ── Summary Dashboard ───────────────────────────────────────────────────────


def print_summary(results: list[ScenarioResult]) -> None:
    """Print a summary dashboard of all scenario results."""
    header("📊  Demo Summary Dashboard")

    total = len(results)
    passed = sum(1 for r in results if r.success)
    failed = total - passed
    total_time = sum(r.duration_seconds for r in results)

    # Stats bar
    print(f"  {BOLD}Total:{RESET} {total}  |  "
          f"{GREEN}Passed:{RESET} {passed}  |  "
          f"{RED}Failed:{RESET} {failed}  |  "
          f"{BLUE}Time:{RESET} {total_time:.1f}s\n")

    # Results table
    print(f"  {'#':>3}  {'Status':8}  {'Scenario':<35}  {'Time':>8}")
    print(f"  {'─' * 3}  {'─' * 8}  {'─' * 35}  {'─' * 8}")

    for r in results:
        status = f"{BG_GREEN}{WHITE} PASS {RESET}" if r.success else f"{BG_RED}{WHITE} FAIL {RESET}"
        time_str = f"{r.duration_seconds:.1f}s"
        print(f"  {r.scenario.number:3d}  {status}  {r.scenario.icon} {r.scenario.title:<32}  {time_str:>8}")

        if not r.success and r.error_message:
            print(f"       {RED}{r.error_message}{RESET}")

    print()

    if failed == 0:
        print(f"  {GREEN}{BOLD}🎉 All scenarios completed successfully!{RESET}")
    else:
        print(f"  {YELLOW}{BOLD}⚠  {failed} scenario(s) had issues — review above for details.{RESET}")

    print()


# ── Main ────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Interactive demo runner for the IT Security Copilot Demo.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scripts/demo_runner.py              # Interactive menu\n"
            "  python scripts/demo_runner.py --scenario 3  # Run scenario 3 directly\n"
            "  python scripts/demo_runner.py --all          # Run all scenarios\n"
        ),
    )
    parser.add_argument(
        "--scenario", "-s",
        type=int,
        choices=range(1, 13),
        metavar="N",
        help="Run a specific scenario (1-12) without the menu",
    )
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="Run all scenarios sequentially without the menu",
    )
    args = parser.parse_args()

    env = load_env()

    # Direct invocation modes
    if args.all:
        selected = list(SCENARIOS)
    elif args.scenario:
        selected = [SCENARIOS[args.scenario - 1]]
    else:
        # Interactive menu
        clear_screen()
        print_menu()
        selected = get_selection()

    if not selected:
        info("Goodbye! 👋")
        return

    # Run selected scenarios
    header(f"🚀  Running {len(selected)} scenario(s)")
    results: list[ScenarioResult] = []

    for i, scenario in enumerate(selected, start=1):
        try:
            result = run_scenario(scenario, i, len(selected), env)
            results.append(result)
        except KeyboardInterrupt:
            print(f"\n\n  {YELLOW}Demo interrupted by user.{RESET}")
            results.append(ScenarioResult(scenario, False, 0.0, "Interrupted by user"))
            break
        except Exception as exc:
            error(f"Unexpected error: {exc}")
            results.append(ScenarioResult(scenario, False, 0.0, str(exc)))

    # Summary
    if results:
        print_summary(results)

    info(f"Run {BOLD}python scripts/teardown.py{RESET} to reset the environment.\n")


if __name__ == "__main__":
    main()
