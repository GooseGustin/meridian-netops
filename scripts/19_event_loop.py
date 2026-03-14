#!/usr/bin/env python3
"""
scripts/19_event_loop.py

The Meridian closed-loop compliance engine.

Endpoints:
  POST /event/config-change  — triggered when a device config changes
  POST /event/policy-update  — triggered when the policy file changes in Git
  GET  /status               — current compliance state of all devices

Test with:
  curl -X POST http://localhost:5001/event/config-change \
    -H "Content-Type: application/json" \
    -d '{"hostname": "fw-01", "changed_by": "netops", "description": "Manual ACL update"}'
"""

import logging
import os
import re
from datetime import datetime
from pathlib import Path

import yaml
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

# --- MockCiscoSSH fix ---
# get_running_config() and remediate() both connect to mock Cisco devices
# (ports 2222-2224). Netmiko's cisco_ios driver sends "terminal width 511"
# and expects it echoed back — the mock server doesn't satisfy this check.
#
# Fix: override set_terminal_width() to return "" immediately.
# Defined inline (not in a separate module) to avoid sys.path issues:
# running scripts/19_event_loop.py adds scripts/ not project root to sys.path.
#
# In GNS3 or real hardware: replace MockCiscoSSH with ConnectHandler.
from netmiko.cisco.cisco_ios import CiscoIosSSH

class MockCiscoSSH(CiscoIosSSH):
    """Bypass terminal width handshake for mock Cisco SSH servers.

    Use only with the Python mock SSH server (sim/mock_cisco.py).
    In GNS3 or real hardware, remove this class and use ConnectHandler.
    """
    def set_terminal_width(self, *args, **kwargs):
        return ""   # Bypass "terminal width 511" echo-check
    def set_terminal_length(self, *args, **kwargs):
        return ""   # Bypass "terminal length 0" echo-check

load_dotenv()

app = Flask(__name__)

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "event_loop.log"),
        logging.StreamHandler(),
    ]
)
log = logging.getLogger(__name__)

DEVICE_MAP = {
    "edge-router-01": {"host": "127.0.0.1", "port": 2222},
    "fw-01":          {"host": "127.0.0.1", "port": 2223},
    "core-sw-01":     {"host": "127.0.0.1", "port": 2224},
}

# In-memory compliance state.
# In production: use Redis or a database for persistence across restarts
# and to support multiple event_loop instances behind a load balancer.
COMPLIANCE_STATE = {
    hostname: {"status": "unknown", "last_checked": None}
    for hostname in DEVICE_MAP
}


def load_policy():
    """Load the security policy from the Git-controlled baseline file.

    Called fresh on every event so that policy updates (via /event/policy-update)
    are picked up without restarting the server.
    """
    with open("baseline/security_policy.yaml") as f:
        return yaml.safe_load(f)


def get_running_config(hostname):
    """Fetch running config from a device.

    Uses MockCiscoSSH instead of ConnectHandler to bypass terminal
    width handshake for the mock SSH server.

    In GNS3 or real hardware:
        with ConnectHandler(**conn_params) as conn:
    """
    cfg = DEVICE_MAP[hostname]
    conn_params = {
        "device_type": "cisco_ios",
        "host": cfg["host"],
        "port": cfg["port"],
        "username": os.getenv("DEVICE_USERNAME"),
        "password": os.getenv("DEVICE_PASSWORD"),
    }
    with MockCiscoSSH(**conn_params) as conn:
        return conn.send_command("show running-config")


def check_compliance(hostname, policy):
    """Quick policy check — returns (is_compliant, violations, missing).

    Returns (None, [], []) if the device is unreachable.
    is_compliant=True means no forbidden lines and all required lines present.
    """
    try:
        running = get_running_config(hostname)
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as exc:
        log.error("[%s] Cannot reach device: %s", hostname, exc)
        return None, [], []

    violations = [
        line for line in policy.get("forbidden_config_lines", [])
        if line in running
    ]
    missing = [
        line for line in policy.get("required_config_lines", [])
        if line not in running
    ]
    return not (violations or missing), violations, missing


def remediate(hostname, policy):
    """Push minimal remediation commands to bring device into compliance.

    Uses MockCiscoSSH for the same reason as get_running_config().

    Returns (success, detail_message) — the caller logs and updates
    COMPLIANCE_STATE based on the result.
    """
    cfg = DEVICE_MAP[hostname]
    try:
        running = get_running_config(hostname)
    except Exception as exc:
        return False, str(exc)

    commands = []
    for forbidden in policy.get("forbidden_config_lines", []):
        if forbidden in running and not forbidden.startswith("no "):
            commands.append(f"no {forbidden}")
    for required in policy.get("required_config_lines", []):
        if required not in running:
            commands.append(required)

    if not commands:
        return True, "already_compliant"

    conn_params = {
        "device_type": "cisco_ios",
        "host": cfg["host"],
        "port": cfg["port"],
        "username": os.getenv("DEVICE_USERNAME"),
        "password": os.getenv("DEVICE_PASSWORD"),
    }
    try:
        # MockCiscoSSH bypasses terminal width check for mock server.
        with MockCiscoSSH(**conn_params) as conn:
            conn.send_config_set(commands)
        return True, f"applied {len(commands)} command(s)"
    except Exception as exc:
        return False, str(exc)


@app.route("/status", methods=["GET"])
def status():
    """Return the current compliance state of all devices.

    This endpoint is what a monitoring dashboard (Grafana, Prometheus)
    would poll to display the compliance status in real time.
    """
    return jsonify({
        "timestamp": datetime.now().isoformat(),
        "compliance_state": COMPLIANCE_STATE,
    }), 200


@app.route("/event/config-change", methods=["POST"])
def config_change_event():
    """
    Triggered when a network change event is received.
    Immediately checks compliance and remediates if needed.

    Expected JSON: {"hostname": "fw-01", "changed_by": "netops", "description": "..."}

    Returns:
    - 200 + "compliant" if device passes policy after change
    - 200 + "remediated" if device was non-compliant and was fixed
    - 200 + "drift_detected" if non-compliant and auto-remediation is disabled
    - 503 if device is unreachable
    """
    data = request.get_json(silent=True) or {}
    hostname = data.get("hostname")
    changed_by = data.get("changed_by", "unknown")
    description = data.get("description", "")

    if not hostname or hostname not in DEVICE_MAP:
        return jsonify({"error": f"Unknown hostname: {hostname}"}), 400

    log.info("Config change event: hostname=%s, by=%s, desc=%s",
             hostname, changed_by, description)

    policy = load_policy()
    is_compliant, violations, missing = check_compliance(hostname, policy)

    COMPLIANCE_STATE[hostname]["last_checked"] = datetime.now().isoformat()

    if is_compliant is None:
        COMPLIANCE_STATE[hostname]["status"] = "unreachable"
        return jsonify({"hostname": hostname, "result": "unreachable"}), 503

    if is_compliant:
        COMPLIANCE_STATE[hostname]["status"] = "compliant"
        log.info("[%s] Compliant after config change.", hostname)
        return jsonify({"hostname": hostname, "result": "compliant"}), 200

    # Drift detected — attempt auto-remediation if policy allows it
    COMPLIANCE_STATE[hostname]["status"] = "drift_detected"
    log.warning("[%s] Non-compliant — violations: %s, missing: %s",
                hostname, violations, missing)

    policy_cfg = load_policy()
    if policy_cfg.get("remediation", {}).get("auto_remediate_forbidden"):
        success, detail = remediate(hostname, policy)
        if success:
            COMPLIANCE_STATE[hostname]["status"] = "remediated"
            log.info("[%s] Auto-remediated: %s", hostname, detail)
        else:
            log.critical("[%s] Remediation FAILED: %s — manual intervention needed",
                         hostname, detail)

    return jsonify({
        "hostname": hostname,
        "result": COMPLIANCE_STATE[hostname]["status"],
        "violations": violations,
        "missing": missing,
    }), 200


@app.route("/event/policy-update", methods=["POST"])
def policy_update_event():
    """
    Triggered when the security_policy.yaml is updated in Git.
    Re-checks ALL devices against the new policy.

    In production: a Git post-receive hook fires this webhook whenever
    security_policy.yaml is pushed to main. Every device is checked
    within seconds of the policy update being approved.
    """
    log.info("Policy update event received — re-checking all devices.")
    policy = load_policy()
    results = {}

    for hostname in DEVICE_MAP:
        is_compliant, violations, missing = check_compliance(hostname, policy)
        COMPLIANCE_STATE[hostname]["last_checked"] = datetime.now().isoformat()
        COMPLIANCE_STATE[hostname]["status"] = (
            "compliant" if is_compliant else
            "unreachable" if is_compliant is None else
            "drift_detected"
        )
        results[hostname] = COMPLIANCE_STATE[hostname]["status"]
        log.info("[%s] -> %s", hostname, results[hostname])

    return jsonify({"results": results}), 200


if __name__ == "__main__":
    log.info("Starting Meridian Closed-Loop Compliance Engine on port 5001...")
    app.run(host="0.0.0.0", port=5001, debug=False)
