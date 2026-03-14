#!/usr/bin/env python3
"""
scripts/14_drift_detect.py

Detects configuration drift between the live device state
and the golden config baseline stored in Git.

Workflow:
  1. Pull running-config from device via Netmiko
  2. Normalize both configs (remove noise lines)
  3. Diff using difflib
  4. Classify drift lines as security-relevant or cosmetic
  5. Report and optionally alert
"""

import difflib
import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path

import yaml
from dotenv import load_dotenv
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

# --- MockCiscoSSH fix ---
# The mock Cisco SSH server (sim/mock_cisco.py) cannot satisfy Netmiko's
# terminal width handshake (it sends "terminal width 511" and expects to
# see that string echoed back in the response).
#
# Fix: subclass CiscoIosSSH and override set_terminal_width() to return ""
# immediately, bypassing the echo-check.
#
# Defined inline to avoid sys.path issues: running scripts/14_drift_detect.py
# adds scripts/ to sys.path, not the project root. Cross-directory imports fail.
# In GNS3 or real hardware: replace MockCiscoSSH with ConnectHandler.
from netmiko.cisco.cisco_ios import CiscoIosSSH

class MockCiscoSSH(CiscoIosSSH):
    """Drop-in replacement for ConnectHandler with mock Cisco SSH servers.

    Skips the terminal width handshake that the Python mock server
    cannot satisfy. In a real network lab or GNS3, use ConnectHandler.
    """
    def set_terminal_width(self, *args, **kwargs):
        return ""   # Bypass "terminal width 511" echo-check
    def set_terminal_length(self, *args, **kwargs):
        return ""   # Bypass "terminal length 0" echo-check

load_dotenv()

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
BASELINE_DIR = Path("baseline")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / f"drift_{datetime.now().strftime('%Y%m%d')}.log"),
        logging.StreamHandler(),
    ]
)
log = logging.getLogger(__name__)

CISCO_DEVICES = [
    {"hostname": "edge-router-01", "host": "127.0.0.1", "port": 2222},
    {"hostname": "fw-01",          "host": "127.0.0.1", "port": 2223},
    {"hostname": "core-sw-01",     "host": "127.0.0.1", "port": 2224},
]

# Lines that change naturally and should NOT trigger drift alerts.
# These are "noise" — they change without any human intent and carry
# no security relevance. Filtering them prevents false positives.
NOISE_PATTERNS = [
    r"^!$",                         # blank comment lines
    r"Building configuration",
    r"ntp clock-period",            # auto-updated by NTP daemon
    r"Last configuration change",   # timestamp — always different
    r"NVRAM config last updated",
    r"^\s*$",                       # blank lines
    r"^! Backup of",
    r"^! Timestamp:",
]

# Lines whose drift is a security violation (high priority).
# Any diff line (+/-) matching these patterns is promoted to
# "security drift" and surfaced prominently in the report.
SECURITY_SENSITIVE_PATTERNS = [
    r"transport input",           # Telnet vs SSH — critical
    r"ip ssh version",            # SSH version enforcement
    r"service password-encryption",
    r"ip access-list",            # ACL additions/removals
    r"access-class",              # ACL applied to VTY lines
    r"enable secret",             # Privilege escalation password
    r"login local",               # Authentication mode
    r"logging",                   # Audit trail config
    r"no shutdown",               # Interface state
    r"shutdown",
]


def load_golden_config(hostname):
    """Load the golden config for a device from the baseline directory.

    Returns a list of lines (with newlines) for use with difflib.
    Returns empty list if no golden config exists (logged as warning).
    """
    path = BASELINE_DIR / f"{hostname}-golden.cfg"
    if not path.exists():
        log.warning("No golden config found for %s at %s", hostname, path)
        return []
    with open(path) as f:
        return f.readlines()


def get_running_config(device_cfg):
    """Fetch the running config from a live device via Netmiko.

    Uses MockCiscoSSH instead of ConnectHandler to bypass the terminal
    width handshake that the mock SSH server cannot satisfy.

    In GNS3 or real hardware:
        with ConnectHandler(**conn_params) as conn:
    """
    conn_params = {
        "device_type": "cisco_ios",
        "host": device_cfg["host"],
        "port": device_cfg["port"],
        "username": os.getenv("DEVICE_USERNAME"),
        "password": os.getenv("DEVICE_PASSWORD"),
    }
    # MockCiscoSSH skips terminal width check for mock servers
    with MockCiscoSSH(**conn_params) as conn:
        config = conn.send_command("show running-config")
    return config.splitlines(keepends=True)


def normalize_config(config_lines):
    """
    Strip noise from config lines before comparison.

    Each line is tested against all NOISE_PATTERNS using re.search().
    If any pattern matches, the line is excluded from the result.
    What remains is only security-relevant configuration content.
    """
    cleaned = []
    for line in config_lines:
        if any(re.search(pattern, line) for pattern in NOISE_PATTERNS):
            continue
        cleaned.append(line)
    return cleaned


def classify_drift(diff_lines):
    """
    Separate diff lines into security-relevant and cosmetic changes.

    diff_lines is the output of difflib.unified_diff() —
    lines starting with '+' were added (present in live, not in golden).
    Lines starting with '-' were removed (present in golden, not in live).
    Lines starting with '+++' or '---' are the file headers — skip them.

    Security-sensitive lines are returned separately so the report can
    prioritise them above cosmetic changes.
    """
    security_drift = []
    cosmetic_drift = []

    for line in diff_lines:
        if not line.startswith(("+", "-")):
            continue
        if line.startswith(("+++", "---")):
            continue
        content = line[1:].strip()
        is_security = any(
            re.search(pattern, content, re.IGNORECASE)
            for pattern in SECURITY_SENSITIVE_PATTERNS
        )
        if is_security:
            security_drift.append(line.rstrip())
        else:
            cosmetic_drift.append(line.rstrip())

    return security_drift, cosmetic_drift


def check_policy_violations(running_config_str, policy):
    """
    Check running config against the security policy YAML rules.

    Two types of violations:
    - FORBIDDEN: a line that must never appear is present
    - MISSING_REQUIRED: a line that must be present is absent

    Uses simple substring matching (in operator) — fast and sufficient
    for single-line policy assertions. For multi-line patterns, use
    difflib comparison instead.
    """
    violations = []
    missing = []

    for forbidden in policy.get("forbidden_config_lines", []):
        if forbidden in running_config_str:
            violations.append({
                "type": "FORBIDDEN",
                "line": forbidden,
                "severity": "HIGH",
            })

    for required in policy.get("required_config_lines", []):
        if required not in running_config_str:
            missing.append({
                "type": "MISSING_REQUIRED",
                "line": required,
                "severity": "HIGH",
            })

    return violations, missing


def analyse_device(device_cfg, policy):
    """Run the full drift analysis for one device.

    The result dict is structured for JSON export — every field is
    serialisable. This allows the compliance report generator (Lab 6)
    to consume these results without additional transformation.
    """
    hostname = device_cfg["hostname"]
    result = {
        "hostname": hostname,
        "timestamp": datetime.now().isoformat(),
        "status": "unknown",
        "drift_detected": False,
        "security_drift": [],
        "cosmetic_drift": [],
        "policy_violations": [],
        "missing_requirements": [],
        "error": None,
    }

    log.info("Checking: %s", hostname)

    try:
        running_lines = get_running_config(device_cfg)
        running_str = "".join(running_lines)
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as exc:
        result["status"] = "connection_failed"
        result["error"] = str(exc)
        log.error("[%s] Connection failed: %s", hostname, exc)
        return result

    golden_lines = load_golden_config(hostname)
    if not golden_lines:
        result["status"] = "no_baseline"
        return result

    # Normalize both configs to remove noise before diffing
    norm_running = normalize_config(running_lines)
    norm_golden = normalize_config(golden_lines)

    # Compute the unified diff.
    # fromfile/tofile are labels in the diff header — helpful for reading output.
    diff = list(difflib.unified_diff(
        norm_golden,
        norm_running,
        fromfile=f"{hostname}-golden",
        tofile=f"{hostname}-live",
        lineterm="",
    ))

    security_drift, cosmetic_drift = classify_drift(diff)
    violations, missing = check_policy_violations(running_str, policy)

    result["drift_detected"] = bool(security_drift or violations or missing)
    result["security_drift"] = security_drift
    result["cosmetic_drift"] = cosmetic_drift
    result["policy_violations"] = violations
    result["missing_requirements"] = missing
    result["status"] = "DRIFT_DETECTED" if result["drift_detected"] else "COMPLIANT"

    if result["drift_detected"]:
        log.warning("[%s] DRIFT DETECTED — %d security changes, %d policy violations",
                    hostname, len(security_drift), len(violations))
        for line in security_drift:
            log.warning("  DRIFT: %s", line)
        for v in violations:
            log.warning("  VIOLATION: %s — %s", v["type"], v["line"])
    else:
        log.info("[%s] COMPLIANT — no drift detected.", hostname)

    return result


def main():
    log.info("=== Meridian Compliance Engine — Drift Detection ===")
    log.info("Timestamp: %s", datetime.now().isoformat())

    # Load policy from the Git-controlled baseline
    policy_path = Path("baseline/security_policy.yaml")
    with open(policy_path) as f:
        policy = yaml.safe_load(f)

    all_results = []
    for device_cfg in CISCO_DEVICES:
        result = analyse_device(device_cfg, policy)
        all_results.append(result)

    # Summary
    compliant = [r for r in all_results if r["status"] == "COMPLIANT"]
    drifted = [r for r in all_results if r["status"] == "DRIFT_DETECTED"]
    failed = [r for r in all_results if r["status"] not in ("COMPLIANT", "DRIFT_DETECTED")]

    log.info("\n=== SUMMARY ===")
    log.info("Compliant: %d/%d", len(compliant), len(all_results))
    log.info("Drift detected: %d/%d", len(drifted), len(all_results))
    log.info("Connection failures: %d", len(failed))

    # Save detailed report for Lab 6's compliance report generator
    report_path = REPORT_DIR / f"drift_report_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
    with open(report_path, "w") as f:
        json.dump(all_results, f, indent=2)
    log.info("Report: %s", report_path)


if __name__ == "__main__":
    main()
