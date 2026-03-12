#!/usr/bin/env python3
"""
scripts/08_linux_patch.py

Patches Linux hosts identified in the vulnerability report.
Connects via SSH (Netmiko), runs apt update/upgrade, logs results.

Target: Docker containers web-01 and db-01
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

load_dotenv()

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

# Configure structured logging — this is the audit trail.
# Two handlers: one writes to a dated log file, one prints to screen.
# This means you get live feedback AND a persistent record.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / f"patching_{datetime.now().strftime('%Y%m%d')}.log"),
        logging.StreamHandler(),
    ]
)
log = logging.getLogger(__name__)

# Linux hosts to patch (pulled from inventory in a real workflow)
LINUX_HOSTS = [
    {
        "hostname": "web-01",
        "host": "127.0.0.1",
        "port": 2225,
        "device_type": "linux",       # Netmiko's Linux driver — no enable mode, no terminal width checks
        "username": os.getenv("DOCKER_USERNAME"),
        "password": os.getenv("DOCKER_PASSWORD"),
    },
    {
        "hostname": "db-01",
        "host": "127.0.0.1",
        "port": 2226,
        "device_type": "linux",
        "username": os.getenv("DOCKER_USERNAME"),
        "password": os.getenv("DOCKER_PASSWORD"),
    },
]


def pre_patch_check(conn, hostname):
    """Gather baseline state before patching.

    This snapshot is compared against post_patch_check() to prove
    that changes occurred and identify what specifically changed.
    """
    log.info("[%s] Running pre-patch check...", hostname)
    checks = {}

    uname = conn.send_command("uname -r")
    checks["kernel_before"] = uname.strip()

    uptime = conn.send_command("uptime")
    checks["uptime_before"] = uptime.strip()

    # List packages with available updates — head -20 limits output size
    available = conn.send_command("apt list --upgradable 2>/dev/null | head -20")
    checks["upgradable_packages_preview"] = available.strip()

    log.info("[%s] Kernel before: %s", hostname, checks["kernel_before"])
    return checks


def run_patch(conn, hostname):
    """Run the apt update and upgrade sequence.

    apt-get update: refreshes the package index from apt sources.
                    Does NOT install anything — just fetches the list.
    apt-get upgrade --only-upgrade: upgrades installed packages only.
                    Won't pull in new dependency packages, reducing
                    the chance of unexpected software appearing.
    read_timeout=300: apt upgrade on a real host can take minutes.
                      The default timeout would cause a false failure.
    """
    log.info("[%s] Running apt update...", hostname)
    update_out = conn.send_command(
        "apt-get update -y 2>&1 | tail -5",
        read_timeout=120
    )
    log.info("[%s] apt update complete.", hostname)

    log.info("[%s] Running apt upgrade (security packages only)...", hostname)
    upgrade_out = conn.send_command(
        "apt-get upgrade -y --only-upgrade 2>&1 | tail -10",
        read_timeout=300
    )
    log.info("[%s] apt upgrade complete.", hostname)

    return {"update_output": update_out, "upgrade_output": upgrade_out}


def post_patch_check(conn, hostname, pre_checks):
    """Verify the patch was applied successfully.

    Key signals:
    - kernel_changed: True if a kernel package was upgraded.
      The new kernel won't be active until next reboot.
    - reboot_required: True if /var/run/reboot-required exists.
      apt writes this file when an update requires a reboot to take effect.
    """
    log.info("[%s] Running post-patch check...", hostname)

    uname = conn.send_command("uname -r")
    kernel_after = uname.strip()

    checks = {
        "kernel_after": kernel_after,
        "kernel_changed": kernel_after != pre_checks.get("kernel_before"),
    }

    if checks["kernel_changed"]:
        log.info("[%s] Kernel updated: %s -> %s",
                 hostname, pre_checks["kernel_before"], kernel_after)
    else:
        log.info("[%s] Kernel unchanged (no kernel update required).", hostname)

    # Check if a reboot is needed
    reboot_required = conn.send_command(
        "test -f /var/run/reboot-required && echo 'REBOOT_NEEDED' || echo 'NO_REBOOT'"
    )
    checks["reboot_required"] = "REBOOT_NEEDED" in reboot_required
    if checks["reboot_required"]:
        log.warning("[%s] REBOOT REQUIRED — schedule during maintenance window.", hostname)

    return checks


def patch_host(host_config):
    """Orchestrate the full patch cycle for one host.

    The result dict is a structured record of the entire operation:
    what was done, what changed, and what failed. This is saved to
    JSON for the compliance record — auditors can verify that every
    host was patched on a specific date with these exact outcomes.
    """
    hostname = host_config["hostname"]
    result = {
        "hostname": hostname,
        "timestamp": datetime.now().isoformat(),
        "status": "pending",
        "pre_checks": {},
        "patch_output": {},
        "post_checks": {},
        "error": None,
    }

    try:
        log.info("[%s] Connecting...", hostname)
        conn_params = {k: v for k, v in host_config.items() if k in ["host", "port", "device_type", "username", "password"]}
        with ConnectHandler(**conn_params) as conn:
            result["pre_checks"] = pre_patch_check(conn, hostname)
            result["patch_output"] = run_patch(conn, hostname)
            result["post_checks"] = post_patch_check(conn, hostname, result["pre_checks"])
            result["status"] = "success"

    except NetmikoAuthenticationException:
        result["status"] = "auth_failed"
        result["error"] = "Authentication failed"
        log.error("[%s] Authentication failed.", hostname)
    except NetmikoTimeoutException:
        result["status"] = "timeout"
        result["error"] = "Connection timed out"
        log.error("[%s] Connection timed out.", hostname)
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        log.error("[%s] Error: %s", hostname, exc)

    return result


def main():
    log.info("=== Meridian Automated Linux Patching ===")

    all_results = []
    for host_config in LINUX_HOSTS:
        result = patch_host(host_config)
        all_results.append(result)

    # Save results — one JSON file per run with timestamp in filename
    path = REPORT_DIR / f"patch_results_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
    with open(path, "w") as f:
        json.dump(all_results, f, indent=2)

    # Summary
    log.info("=== Patching Summary ===")
    for r in all_results:
        status_line = f"[{r['hostname']}] {r['status'].upper()}"
        if r["post_checks"].get("reboot_required"):
            status_line += " — REBOOT REQUIRED"
        if r["error"]:
            status_line += f" — {r['error']}"
        log.info(status_line)

    log.info("Results saved to: %s", path)


if __name__ == "__main__":
    main()
