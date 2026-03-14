#!/usr/bin/env python3
"""
scripts/17_acl_generator.py

Generates Cisco IOS ACL configuration from YAML policy + Jinja2 template,
then deploys to the mock device with pre/post verification.

Policy-as-code workflow:
  1. YAML defines the intent (vendor-neutral rules)
  2. Jinja2 translates intent to IOS syntax
  3. Script deploys and verifies
"""

import os
from datetime import datetime
from pathlib import Path

import yaml
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException

load_dotenv()

TEMPLATE_DIR = "templates"
DATA_FILE = "data/acl_policy.yaml"
OUTPUT_DIR = Path("reports")
OUTPUT_DIR.mkdir(exist_ok=True)


def load_policy(path):
    with open(path) as f:
        return yaml.safe_load(f)


def render_acl(acl_data):
    """Render a single ACL dict to Cisco IOS commands using Jinja2.

    Environment(trim_blocks=True): removes the newline after {% %} blocks,
    producing clean IOS config output without extra blank lines.
    FileSystemLoader: looks for templates relative to TEMPLATE_DIR.
    """
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), trim_blocks=True)
    template = env.get_template("cisco_acl.j2")
    return template.render(acl=acl_data, timestamp=datetime.now().isoformat())


def deploy_acl(hostname, port, acl_config_text):
    """Deploy a rendered ACL to a device.

    Parses the rendered text into a command list for send_config_set().
    Comments (!) and blank lines are skipped — they're valid in a config
    file but would cause errors if sent as individual commands to IOS.

    The render is saved to a file before deployment (see main()) so you
    can review exactly what was pushed and compare it to what's on the device.
    """
    conn_params = {
        "device_type": "cisco_ios",
        "host": "127.0.0.1",
        "port": port,
        "username": os.getenv("DEVICE_USERNAME"),
        "password": os.getenv("DEVICE_PASSWORD"),
    }

    # Convert rendered text to list of commands for send_config_set
    commands = []
    current_section = None
    for line in acl_config_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("!"):
            continue
        if stripped.startswith("ip access-list"):
            current_section = stripped
            commands.append(stripped)
        elif current_section and stripped:
            commands.append(f" {stripped}")

    print(f"  Deploying to {hostname} ({len(commands)} commands)...")
    try:
        with ConnectHandler(**conn_params) as conn:
            output = conn.send_config_set(commands)
            # Verify: check that the ACL now appears in show access-lists
            verify = conn.send_command("show access-lists")
            return True, output, verify
    except NetmikoTimeoutException as exc:
        return False, str(exc), ""


def validate_acl_against_policy(show_output, policy_acl):
    """
    Verify that each required rule from the policy appears in the
    device's 'show access-lists' output.

    Uses a simple fragment match — not exact line matching.
    Returns a list of issues found (empty list = all rules present).
    """
    issues = []
    for rule in policy_acl["rules"]:
        # Build a search fragment for this rule (action + protocol)
        frag = f"{rule['action']} {rule['protocol']}"
        if frag not in show_output.lower():
            issues.append(f"Rule seq {rule['seq']} ({frag}) not found in device output")
    return issues


def main():
    print("=== Meridian Lab — ACL Generator & Deployer ===\n")

    policy = load_policy(DATA_FILE)

    # Target devices for this lab
    TARGET_DEVICES = [
        {"hostname": "edge-router-01", "port": 2222},
        {"hostname": "fw-01", "port": 2223},
    ]

    for acl in policy["access_lists"]:
        print(f"ACL: {acl['name']}")

        # Render the template
        rendered = render_acl(acl)
        print("  Rendered config:")
        print("  " + "\n  ".join(rendered.strip().splitlines()))

        # Save rendered config to file BEFORE deploying.
        # This is the "review before deploy" safety step.
        # In production, commit this file to Git and review the diff.
        output_path = OUTPUT_DIR / f"acl_{acl['name']}_{datetime.now().strftime('%Y%m%d')}.txt"
        with open(output_path, "w") as f:
            f.write(rendered)
        print(f"  Saved to: {output_path}")

        # Deploy to relevant devices
        for device in TARGET_DEVICES:
            success, output, verify = deploy_acl(
                device["hostname"], device["port"], rendered
            )
            if success:
                issues = validate_acl_against_policy(verify, acl)
                if issues:
                    print(f"  [{device['hostname']}] WARNING: Validation issues:")
                    for issue in issues:
                        print(f"    -> {issue}")
                else:
                    print(f"  [{device['hostname']}] Deployed and verified.")
            else:
                print(f"  [{device['hostname']}] FAILED: {output}")

        print()


if __name__ == "__main__":
    main()
