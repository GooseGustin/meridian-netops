#!/usr/bin/env python3
"""
scripts/03_inventory_gather.py

Reads inventory.yaml, connects to every device, collects facts,
and writes a JSON report to reports/inventory_report.json.
"""

import json
import os
import re
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
    def set_terminal_length(self, *args, **kwargs):
        return ""   # Similarly skip terminal length handshake

load_dotenv()

INVENTORY_FILE = "inventory.yaml"
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)


def load_inventory(path):
    with open(path) as f:
        data = yaml.safe_load(f)
    return data["devices"]


def get_cisco_facts(conn, hostname):
    """Gather structured facts from a Cisco IOS device."""
    facts = {}

    # Parse version for OS version string
    ver_output = conn.send_command("show version")
    version_match = re.search(r"Version (\S+),", ver_output)
    facts["os_version"] = version_match.group(1) if version_match else "unknown"

    uptime_match = re.search(r"uptime is (.+)", ver_output)
    facts["uptime"] = uptime_match.group(1).strip() if uptime_match else "unknown"

    # CPU usage
    cpu_output = conn.send_command("show processes cpu | include CPU")
    cpu_match = re.search(r"five seconds: (\d+)%", cpu_output)
    facts["cpu_5sec"] = int(cpu_match.group(1)) if cpu_match else -1

    # Interface summary
    intf_output = conn.send_command("show ip interface brief")
    interfaces = []
    for line in intf_output.splitlines():
        if re.match(r"^\s*(GigabitEthernet|FastEthernet|Loopback)", line):
            parts = line.split()
            if len(parts) >= 6:
                interfaces.append({
                    "interface": parts[0],
                    "ip": parts[1],
                    "status": parts[4],
                    "protocol": parts[5],
                })
    facts["interfaces"] = interfaces

    return facts


def get_linux_facts(conn, hostname):
    """Gather structured facts from a Linux host."""
    facts = {}

    uname = conn.send_command("uname -a")
    facts["kernel"] = uname.strip()

    uptime = conn.send_command("uptime -p")
    facts["uptime"] = uptime.strip()

    # Disk usage on root
    df = conn.send_command("df -h /")
    lines = df.strip().splitlines()
    if len(lines) >= 2:
        parts = lines[1].split()
        if len(parts) >= 5:
            facts["disk_used"] = parts[2]
            facts["disk_avail"] = parts[3]
            facts["disk_use_pct"] = parts[4]

    # Memory
    free = conn.send_command("free -m")
    for line in free.splitlines():
        if line.startswith("Mem:"):
            parts = line.split()
            facts["mem_total_mb"] = parts[1]
            facts["mem_used_mb"] = parts[2]
            break

    return facts


def gather_device_facts(device_cfg):
    """Connect to a device and gather facts. Returns a result dict."""
    hostname = device_cfg["hostname"]
    device_type = device_cfg["device_type"]

    # Build Netmiko connection dict from inventory entry
    # Credentials come from environment, not the inventory file
    conn_params = {
        "device_type": device_type,
        "host": device_cfg["host"],
        "port": device_cfg["port"],
        "username": (
            os.getenv("DEVICE_USERNAME")
            if device_type == "cisco_ios"
            else os.getenv("DOCKER_USERNAME")
        ),
        "password": (
            os.getenv("DEVICE_PASSWORD")
            if device_type == "cisco_ios"
            else os.getenv("DOCKER_PASSWORD")
        ),
        "fast_cli": False,  # Disable fast_cli for better compatibility
        "global_delay_factor": 2,  # Increase delay for slower devices
    }

    result = {
        "hostname": hostname,
        "role": device_cfg.get("role"),
        "site": device_cfg.get("site"),
        "device_type": device_type,
        "timestamp": datetime.now().isoformat(),
        "status": "unknown",
        "facts": {},
        "error": None,
    }

    try:
        print(f"  Connecting to {hostname} ({device_cfg['host']}:{device_cfg['port']})...")
        # with ConnectHandler(**conn_params) as conn:
        ConnClass = MockCiscoSSH if device_type == "cisco_ios" else ConnectHandler
        with ConnClass(**conn_params) as conn:
            if device_type == "cisco_ios":
                result["facts"] = get_cisco_facts(conn, hostname)
            elif device_type == "linux":
                result["facts"] = get_linux_facts(conn, hostname)
            result["status"] = "success"
            print(f"  OK — {hostname}")

    except NetmikoAuthenticationException:
        result["status"] = "auth_failed"
        result["error"] = "Authentication failed"
        print(f"  FAIL — {hostname}: auth failed")
    except NetmikoTimeoutException:
        result["status"] = "timeout"
        result["error"] = "Connection timed out"
        print(f"  FAIL — {hostname}: timeout")
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        print(f"  FAIL — {hostname}: {exc}")

    return result


def main():
    print("=== Meridian Lab — Inventory Gather ===")
    print(f"Timestamp: {datetime.now().isoformat()}\n")

    devices = load_inventory(INVENTORY_FILE)
    print(f"Loaded {len(devices)} devices from inventory.\n")

    all_results = []
    for device_cfg in devices:
        result = gather_device_facts(device_cfg)
        all_results.append(result)

    # Write JSON report
    report_path = REPORT_DIR / "inventory_report.json"
    with open(report_path, "w") as f:
        json.dump(all_results, f, indent=2)

    # Print summary
    print(f"\n=== Results ===")
    success = [r for r in all_results if r["status"] == "success"]
    failed = [r for r in all_results if r["status"] != "success"]
    print(f"  Successful: {len(success)}/{len(all_results)}")
    for r in failed:
        print(f"  FAILED: {r['hostname']} — {r['error']}")

    print(f"\nReport written to: {report_path}")


if __name__ == "__main__":
    main()
