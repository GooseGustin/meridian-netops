#!/usr/bin/env python3
"""
scripts/04_config_backup.py

Pulls running configs from all Cisco devices and commits to Git.
Run this daily (via cron) to maintain a config history.
"""

import os
import subprocess
from datetime import datetime
from pathlib import Path

import yaml
from dotenv import load_dotenv
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from netmiko.cisco.cisco_ios import CiscoIosSSH

class MockCiscoSSH(CiscoIosSSH):
    def set_terminal_width(self, *args, **kwargs):
        """Skip terminal width setup — mock server doesn't support it."""
        return ""

load_dotenv()

INVENTORY_FILE = "inventory.yaml"
BACKUP_DIR = Path("backups")
BACKUP_DIR.mkdir(exist_ok=True)


def load_cisco_devices(inventory_path):
    """Load only Cisco devices from inventory."""
    with open(inventory_path) as f:
        data = yaml.safe_load(f)
    return [d for d in data["devices"] if d["device_type"] == "cisco_ios"]


def backup_device(device_cfg):
    """Pull running-config from one device and save to disk."""
    hostname = device_cfg["hostname"]

    conn_params = {
        "device_type": "cisco_ios",
        "host": device_cfg["host"],
        "port": device_cfg["port"],
        "username": os.getenv("DEVICE_USERNAME"),
        "password": os.getenv("DEVICE_PASSWORD"),
    }

    try:
        # with ConnectHandler(**conn_params) as conn:
        ConnClass = MockCiscoSSH if conn_params['device_type'] == "cisco_ios" else ConnectHandler
        with ConnClass(**conn_params) as conn:
            print(f"  Backing up {hostname}...")
            config = conn.send_command("show running-config")

            # Save with hostname in filename (no timestamp — Git tracks history)
            backup_path = BACKUP_DIR / f"{hostname}.cfg"
            with open(backup_path, "w") as f:
                f.write(f"! Backup of {hostname}\n")
                f.write(f"! Timestamp: {datetime.now().isoformat()}\n")
                f.write("!\n")
                f.write(config)

            print(f"  Saved: {backup_path} ({len(config)} bytes)")
            return str(backup_path), None

    except NetmikoAuthenticationException:
        return None, f"Auth failed on {hostname}"
    except NetmikoTimeoutException:
        return None, f"Timeout on {hostname}"
    except Exception as exc:
        return None, f"Error on {hostname}: {exc}"


def git_commit_backups(paths, message):
    """Stage backup files and commit to Git."""
    for path in paths:
        subprocess.run(["git", "add", path], check=True)

    result = subprocess.run(
        ["git", "diff", "--cached", "--quiet"],
        capture_output=True
    )

    if result.returncode == 0:
        print("\n  No config changes detected — nothing to commit.")
        return

    subprocess.run(
        ["git", "commit", "-m", message],
        check=True
    )
    print(f"\n  Committed: {message}")


def main():
    print("=== Meridian Lab — Config Backup ===")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"Timestamp: {timestamp}\n")

    devices = load_cisco_devices(INVENTORY_FILE)
    print(f"Found {len(devices)} Cisco device(s) to back up.\n")

    backed_up = []
    errors = []

    for device_cfg in devices:
        path, err = backup_device(device_cfg)
        if path:
            backed_up.append(path)
        if err:
            errors.append(err)

    print(f"\n  Backed up: {len(backed_up)}/{len(devices)} devices")
    for err in errors:
        print(f"  ERROR: {err}")

    if backed_up:
        commit_msg = f"backup: automated config snapshot {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        git_commit_backups(backed_up, commit_msg)

    print("\nDone.")


if __name__ == "__main__":
    main()
