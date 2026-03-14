#!/usr/bin/env python3
"""
scripts/16_docker_audit.py

Runs a security audit across the Docker Linux hosts.
Checks: open ports, running services, user accounts, SSH config.

Uses subprocess + docker exec rather than SSH — this is appropriate
for security auditing of your own containers (you have root access
to the Docker socket). For hosts you don't own, use SSH instead.
"""

import json
import subprocess
from datetime import datetime
from pathlib import Path

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

CONTAINERS = ["web-01", "db-01"]

# Audit commands to run inside each container.
# These gather the security-relevant state of the host.
# 'ss -tlnp' shows TCP listening ports with the process that owns them.
# 'getent passwd' shows all user accounts from all sources (including LDAP).
AUDIT_COMMANDS = {
    "open_ports": "ss -tlnp",
    "running_services": "systemctl list-units --type=service --state=running 2>/dev/null || service --status-all 2>&1 | grep '+' || echo 'systemd not available'",
    "user_accounts": "getent passwd | grep -v nologin | grep -v false | grep -v sync",
    "ssh_password_auth": "grep -i 'PasswordAuthentication' /etc/ssh/sshd_config || echo 'not set'",
    "ssh_root_login": "grep -i 'PermitRootLogin' /etc/ssh/sshd_config || echo 'not set'",
    "kernel_version": "uname -r",
    "last_logins": "last -n 5 2>/dev/null || echo 'no login records'",
    "cron_jobs": "crontab -l 2>/dev/null || echo 'no crontab'",
    "world_writable": "find / -xdev -perm -0002 -type f 2>/dev/null | head -10",
}

# Security checks: what value is considered a violation and why.
# 'bad_value' is a case-insensitive substring match against the command output.
SECURITY_CHECKS = {
    "ssh_password_auth": {
        "bad_value": "yes",
        "message": "Password authentication is ENABLED — should be key-only",
        "severity": "HIGH",
    },
    "ssh_root_login": {
        "bad_value": "yes",
        "message": "Root SSH login is ENABLED — should be disabled",
        "severity": "MEDIUM",
    },
}


def run_in_container(container, command):
    """Run a command inside a container and return stdout.

    subprocess.run() with a list (not shell=True) is the secure pattern.
    Each element is a literal argument — no shell interpretation.
    'bash -c command' is needed to support shell piping within the command.
    """
    result = subprocess.run(
        ["docker", "exec", container, "bash", "-c", command],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip() if result.returncode == 0 else f"ERROR: {result.stderr.strip()}"


def audit_container(container):
    """Run all audit commands against a container and flag issues.

    Two-pass structure:
    1. Run all commands and collect output (observation phase)
    2. Check each output against SECURITY_CHECKS rules (analysis phase)

    Separating observation from analysis makes it easy to add new checks
    without changing the execution loop.
    """
    print(f"  Auditing {container}...")
    audit_data = {"container": container, "timestamp": datetime.now().isoformat()}
    findings = []

    for check_name, command in AUDIT_COMMANDS.items():
        output = run_in_container(container, command)
        audit_data[check_name] = output

        # Check for security violations
        if check_name in SECURITY_CHECKS:
            rule = SECURITY_CHECKS[check_name]
            if rule["bad_value"].lower() in output.lower():
                findings.append({
                    "check": check_name,
                    "severity": rule["severity"],
                    "message": rule["message"],
                    "evidence": output[:100],
                })

    audit_data["security_findings"] = findings
    audit_data["finding_count"] = len(findings)
    return audit_data


def main():
    print("=== Meridian Lab — Docker Host Security Audit ===\n")

    all_results = []
    for container in CONTAINERS:
        try:
            result = audit_container(container)
            count = result["finding_count"]
            print(f"  {container}: {count} finding(s)")
            for f in result["security_findings"]:
                print(f"    [{f['severity']}] {f['message']}")
            all_results.append(result)
        except subprocess.TimeoutExpired:
            print(f"  {container}: TIMEOUT")
        except Exception as exc:
            print(f"  {container}: ERROR — {exc}")

    path = REPORT_DIR / f"docker_audit_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
    with open(path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nReport: {path}")


if __name__ == "__main__":
    main()
