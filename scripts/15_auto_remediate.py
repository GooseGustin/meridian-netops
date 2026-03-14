#!/usr/bin/env python3
"""
scripts/15_auto_remediate.py

Auto-remediation for detected config drift.

Safe remediation principles:
  1. Only push the diff, not the whole config (minimal blast radius)
  2. Verify the state after remediation (idempotency check)
  3. Log every change for the audit trail
  4. Never auto-remediate interface shutdowns or ACL removals
     without the explicit policy flag set (protected commands)
"""

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
# get_running_config_str() and push_remediation() both connect to mock Cisco
# SSH servers (ports 2222-2224). Netmiko's cisco_ios driver sends
# "terminal width 511" during setup and expects to see it echoed back.
# The mock server's response timing doesn't satisfy this check.
#
# Fix: override set_terminal_width() in a subclass to return "" immediately.
# Defined inline to avoid import path issues (scripts/ is on sys.path, not root).
# In GNS3 or real hardware: replace MockCiscoSSH with ConnectHandler.
from netmiko.cisco.cisco_ios import CiscoIosSSH

class MockCiscoSSH(CiscoIosSSH):
    """Bypass terminal width handshake for mock Cisco SSH servers.

    Use only when connecting to the Python mock server (sim/mock_cisco.py).
    Remove and use ConnectHandler directly when using real devices or GNS3.
    """
    def set_terminal_width(self, *args, **kwargs):
        return ""   # Bypass "terminal width 511" echo-check
    def set_terminal_length(self, *args, **kwargs):
        return ""   # Bypass "terminal length 0" echo-check

load_dotenv()

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / f"remediation_{datetime.now().strftime('%Y%m%d')}.log"),
        logging.StreamHandler(),
    ]
)
log = logging.getLogger(__name__)

CISCO_DEVICES = [
    {"hostname": "edge-router-01", "host": "127.0.0.1", "port": 2222},
    {"hostname": "fw-01",          "host": "127.0.0.1", "port": 2223},
    {"hostname": "core-sw-01",     "host": "127.0.0.1", "port": 2224},
]

# Commands that are NEVER auto-applied — require human approval.
# These patterns match commands that could cause immediate service disruption
# or irreversible changes (interface down, route removal, ACL deletion).
PROTECTED_PATTERNS = [
    r"^no interface",
    r"^no ip route",
    r"^shutdown",
    r"^no shutdown",
    r"^no ip access-list",
]


def build_remediation_commands(policy, running_config_str):
    """
    Build the minimum set of commands to bring the device into compliance.

    Implements the minimal blast radius principle:
    - For missing required lines: add them
    - For forbidden lines: negate them with 'no'
    - For protected patterns: log them but DON'T add to safe_commands

    The result is a list of Cisco IOS config-mode commands, safe to pass
    directly to send_config_set().
    """
    commands = []

    # Add missing required lines
    for required in policy.get("required_config_lines", []):
        if required not in running_config_str:
            log.info("  MISSING (will add): %s", required)
            commands.append(required)

    # Remove forbidden lines.
    # Cisco IOS negation: prefix with 'no' to remove a config line.
    # Edge case: if the forbidden line already starts with 'no', don't double-negate.
    # Example: forbidden 'no service password-encryption' → push 'service password-encryption'
    for forbidden in policy.get("forbidden_config_lines", []):
        if forbidden in running_config_str:
            log.warning("  FORBIDDEN (will remove): %s", forbidden)
            if not forbidden.startswith("no "):
                commands.append(f"no {forbidden}")
            else:
                # Remove the 'no' to re-enable the feature
                commands.append(forbidden[3:])

    # Filter out commands that require manual approval.
    # Protected commands are logged but not executed automatically.
    safe_commands = []
    protected = []
    for cmd in commands:
        is_protected = any(re.search(p, cmd, re.IGNORECASE) for p in PROTECTED_PATTERNS)
        if is_protected:
            protected.append(cmd)
        else:
            safe_commands.append(cmd)

    if protected:
        log.warning("  These commands require manual approval (not auto-applied):")
        for cmd in protected:
            log.warning("    -> %s", cmd)

    return safe_commands


def get_running_config_str(device_cfg):
    """Fetch running config as a string.

    Uses MockCiscoSSH instead of ConnectHandler to bypass the terminal
    width handshake that the mock SSH server cannot satisfy.
    """
    conn_params = {
        "device_type": "cisco_ios",
        "host": device_cfg["host"],
        "port": device_cfg["port"],
        "username": os.getenv("DEVICE_USERNAME"),
        "password": os.getenv("DEVICE_PASSWORD"),
    }
    # MockCiscoSSH skips terminal width check for mock servers.
    # In GNS3 or real hardware, replace with:
    #   with ConnectHandler(**conn_params) as conn:
    with MockCiscoSSH(**conn_params) as conn:
        return conn.send_command("show running-config")


def push_remediation(device_cfg, commands):
    """Push remediation commands and verify the result.

    Uses MockCiscoSSH for the same reason as get_running_config_str().

    The post-push re-fetch (show running-config) is the verification step:
    we confirm the commands were accepted AND produced the expected config
    state. IOS sometimes accepts a command without applying it (syntax edge
    cases, mode mismatch) — the verification catches these silently-failed pushes.
    """
    hostname = device_cfg["hostname"]
    conn_params = {
        "device_type": "cisco_ios",
        "host": device_cfg["host"],
        "port": device_cfg["port"],
        "username": os.getenv("DEVICE_USERNAME"),
        "password": os.getenv("DEVICE_PASSWORD"),
    }

    log.info("[%s] Pushing %d remediation command(s)...", hostname, len(commands))
    try:
        with MockCiscoSSH(**conn_params) as conn:
            output = conn.send_config_set(commands)
            log.info("[%s] Push output:\n%s", hostname, output[:300])

            # Re-fetch config for post-remediation verification
            post_config = conn.send_command("show running-config")
            return post_config

    except (NetmikoTimeoutException, NetmikoAuthenticationException) as exc:
        log.error("[%s] Remediation failed: %s", hostname, exc)
        return None


def remediate_device(device_cfg, policy):
    """Full remediation cycle for one device.

    Pattern: fetch → plan → execute → verify
    This cycle is idempotent: if run when device is already compliant,
    build_remediation_commands() returns [] and the function returns early.
    """
    hostname = device_cfg["hostname"]
    log.info("=== Remediating: %s ===", hostname)

    try:
        running = get_running_config_str(device_cfg)
    except Exception as exc:
        log.error("[%s] Cannot reach device: %s", hostname, exc)
        return

    # Build remediation plan (only the delta — not the full config)
    commands = build_remediation_commands(policy, running)

    if not commands:
        log.info("[%s] No remediation needed — device is compliant.", hostname)
        return

    log.info("[%s] Remediation plan: %d commands", hostname, len(commands))
    for cmd in commands:
        log.info("  -> %s", cmd)

    # Execute
    post_config = push_remediation(device_cfg, commands)

    if post_config:
        # Verify each required line is now present in the post-remediation config
        verified = True
        for required in policy.get("required_config_lines", []):
            if required not in post_config:
                log.error("[%s] VERIFICATION FAILED: '%s' still missing after remediation",
                          hostname, required)
                verified = False

        if verified:
            log.info("[%s] Remediation verified — device is now compliant.", hostname)
        else:
            log.critical("[%s] Remediation incomplete — manual review required.", hostname)


def main():
    log.info("=== Meridian Compliance Engine — Auto-Remediation ===")

    policy_path = Path("baseline/security_policy.yaml")
    with open(policy_path) as f:
        policy = yaml.safe_load(f)

    for device_cfg in CISCO_DEVICES:
        remediate_device(device_cfg, policy)

    log.info("=== Remediation pass complete ===")


if __name__ == "__main__":
    main()
