#!/usr/bin/env python3
"""
scripts/05_template_deploy.py

Renders interface configs from a Jinja2 template + YAML data,
then pushes them to the appropriate mock device.
"""

import os
from pathlib import Path

import yaml
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

load_dotenv()

TEMPLATE_DIR = "templates"
DATA_FILE = "data/interface_data.yaml"


def load_data(path):
    with open(path) as f:
        return yaml.safe_load(f)


def render_config(template_name, context):
    """Render a Jinja2 template with the given context dict."""
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template(template_name)
    return template.render(**context)


def push_config(hostname, port, config_lines):
    """Push rendered config lines to a device using Netmiko send_config_set."""
    conn_params = {
        "device_type": "cisco_ios",
        "host": "127.0.0.1",
        "port": port,
        "username": os.getenv("DEVICE_USERNAME"),
        "password": os.getenv("DEVICE_PASSWORD"),
    }

    try:
        with ConnectHandler(**conn_params) as conn:
            print(f"  Pushing config to {hostname}...")
            output = conn.send_config_set(config_lines)
            # Verify the interface is now described correctly
            verify = conn.send_command(
                f"show ip interface brief"
            )
            print(f"  Config output:\n{output}")
            print(f"  Verification:\n{verify}")
            return True

    except (NetmikoAuthenticationException, NetmikoTimeoutException) as exc:
        print(f"  ERROR on {hostname}: {exc}")
        return False


def main():
    print("=== Meridian Lab — Template Deploy ===\n")

    data = load_data(DATA_FILE)

    for intf_cfg in data["interfaces"]:
        device = intf_cfg["device"]
        port = intf_cfg["port"]
        print(f"Processing: {device} — {intf_cfg['interface_name']}")

        # Render the Jinja2 template with this interface's data
        rendered = render_config("interface_config.j2", intf_cfg)

        print("  Rendered config:")
        for line in rendered.splitlines():
            print(f"    {line}")

        # Convert rendered text to a list of commands for send_config_set
        config_lines = [
            line for line in rendered.splitlines()
            if line.strip() and not line.strip().startswith("{")
        ]

        push_config(device, port, config_lines)
        print()


if __name__ == "__main__":
    main()
