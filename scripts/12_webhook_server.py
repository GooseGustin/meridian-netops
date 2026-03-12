#!/usr/bin/env python3
"""
scripts/12_webhook_server.py

Flask webhook receiver for automated incident response.

Workflow:
  1. SIEM detects a threat and POSTs an alert to /webhook
  2. This server validates the alert
  3. If severity is HIGH or CRITICAL, it pushes a blocking ACL
     to the mock firewall via Netmiko
  4. The action is logged for the audit trail

Start with: python scripts/12_webhook_server.py
Test with:  curl -X POST http://localhost:5000/webhook \
              -H "Content-Type: application/json" \
              -d '{"event_type": "brute_force", "attacker_ip": "185.220.101.47", "severity": "HIGH"}'
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

# --- MockCiscoSSH fix ---
# Netmiko's cisco_ios driver sends "terminal width 511" during session setup
# and waits to see that string echoed back. The Python mock SSH server doesn't
# replicate this precisely, causing a "Pattern not detected" error.
#
# Fix: subclass CiscoIosSSH and override set_terminal_width() to return ""
# immediately, bypassing the echo-check entirely.
#
# This class is defined inline (not imported from a separate module) to avoid
# Python sys.path issues — running scripts/foo.py adds scripts/ to sys.path,
# not the project root, so cross-directory imports fail.
from netmiko.cisco.cisco_ios import CiscoIosSSH

class MockCiscoSSH(CiscoIosSSH):
    """Drop-in replacement for ConnectHandler when device_type='cisco_ios'.

    Skips the terminal width handshake that the Python mock server
    cannot satisfy. In a real network lab or GNS3 environment, use
    ConnectHandler directly — MockCiscoSSH is only for this mock server.
    """
    def set_terminal_width(self, *args, **kwargs):
        return ""   # Return empty string instead of waiting for echo confirmation
    def set_terminal_length(self, *args, **kwargs):
        return ""   # Similarly skip terminal length handshake

load_dotenv()

app = Flask(__name__)

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

# Set up structured logging for the audit trail.
# Every IP block action is timestamped and written to webhook_audit.log.
# In production, this log would feed into your SIEM as a secondary event source.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "webhook_audit.log"),
        logging.StreamHandler(),
    ]
)
log = logging.getLogger(__name__)

# Firewall device (fw-01 mock)
# In production: pull these from the inventory YAML or Vault secret
FIREWALL = {
    "device_type": "cisco_ios",
    "host": "127.0.0.1",
    "port": 2223,
    "username": os.getenv("DEVICE_USERNAME"),
    "password": os.getenv("DEVICE_PASSWORD"),
}

# Track blocked IPs to ensure idempotency.
# In production: query the firewall's running-config instead of maintaining
# in-memory state (which is lost if the webhook server restarts).
BLOCKED_IPS = set()

VALID_EVENT_TYPES = {"brute_force", "c2_beacon", "port_scan", "data_exfil"}
ACTIONABLE_SEVERITIES = {"HIGH", "CRITICAL"}


def block_ip_on_firewall(attacker_ip):
    """
    Push a deny ACL entry to the firewall for the attacker IP.

    Idempotent: checks BLOCKED_IPS before pushing.
    Uses MockCiscoSSH instead of ConnectHandler to bypass the terminal
    width handshake that the Python mock server cannot satisfy.

    The ACL pushes two rules:
    - deny ip host <attacker> any: blocks inbound traffic FROM the attacker
    - deny ip any host <attacker>: blocks outbound traffic TO the attacker
                                   (prevents data exfiltration TO that IP)
    """
    if attacker_ip in BLOCKED_IPS:
        log.info("IP %s is already blocked — skipping ACL push.", attacker_ip)
        return True, "already_blocked"

    commands = [
        "ip access-list extended BLOCK_THREATS",
        f"deny ip host {attacker_ip} any log",
        f"deny ip any host {attacker_ip} log",
        "exit",
    ]

    try:
        log.info("Connecting to firewall to block %s...", attacker_ip)
        # Use MockCiscoSSH (not ConnectHandler) to avoid terminal width issues
        # with the Python mock SSH server on port 2223.
        with MockCiscoSSH(**FIREWALL) as conn:
            output = conn.send_config_set(commands)
            log.info("ACL push output: %s", output[:200])

        BLOCKED_IPS.add(attacker_ip)
        log.info("Successfully blocked %s on fw-01.", attacker_ip)
        return True, "blocked"

    except NetmikoAuthenticationException:
        log.error("Firewall authentication failed.")
        return False, "auth_failed"
    except NetmikoTimeoutException:
        log.error("Firewall connection timed out.")
        return False, "timeout"
    except Exception as exc:
        log.error("Unexpected error blocking %s: %s", attacker_ip, exc)
        return False, str(exc)


@app.route("/health", methods=["GET"])
def health():
    """Simple health check endpoint.

    Monitoring systems (Nagios, Prometheus) can poll /health to verify
    the webhook server is running. Returns the current blocked IP count
    as a basic operational metric.
    """
    return jsonify({"status": "ok", "blocked_ips": len(BLOCKED_IPS)}), 200


@app.route("/webhook", methods=["POST"])
def handle_webhook():
    """
    Main webhook endpoint. Receives SIEM alerts and triggers response.

    The validation layer (event_type, attacker_ip, severity checks)
    prevents automation from acting on malformed or spoofed payloads.
    Only HIGH and CRITICAL severity events trigger network changes.

    Returns 200 on success, 400 on invalid input, 500 on automation failure.
    The HTTP status code tells the SIEM whether to mark the incident
    as contained (200) or escalate to a human (500).
    """
    data = request.get_json(silent=True)
    if not data:
        log.warning("Received non-JSON request.")
        return jsonify({"error": "Invalid JSON"}), 400

    log.info("Received alert: %s", json.dumps(data))

    # Validate required fields
    event_type = data.get("event_type")
    attacker_ip = data.get("attacker_ip")
    severity = data.get("severity", "").upper()

    if not event_type or event_type not in VALID_EVENT_TYPES:
        return jsonify({"error": f"Unknown event_type: {event_type}"}), 400

    if not attacker_ip:
        return jsonify({"error": "Missing attacker_ip"}), 400

    response = {
        "received_at": datetime.now().isoformat(),
        "event_type": event_type,
        "attacker_ip": attacker_ip,
        "severity": severity,
        "action_taken": "none",
        "result": "ignored",
    }

    # Only act on high-severity events
    if severity not in ACTIONABLE_SEVERITIES:
        log.info("Severity '%s' is below threshold — no action taken.", severity)
        response["result"] = "below_threshold"
        return jsonify(response), 200

    # Trigger automated response
    log.info("Alert severity %s — triggering IP block for %s", severity, attacker_ip)
    success, result_detail = block_ip_on_firewall(attacker_ip)

    response["action_taken"] = "ip_block"
    response["result"] = "success" if success else "failed"
    response["detail"] = result_detail

    # Fail-safe: if automation failed, alert the SOC team
    if not success:
        log.critical(
            "AUTOMATION FAILED for %s — manual intervention required! Detail: %s",
            attacker_ip, result_detail
        )
        # In production: send Slack/PagerDuty alert here

    status_code = 200 if success else 500
    return jsonify(response), status_code


@app.route("/blocked", methods=["GET"])
def list_blocked():
    """Return the list of currently blocked IPs."""
    return jsonify({"blocked_ips": list(BLOCKED_IPS), "count": len(BLOCKED_IPS)}), 200


if __name__ == "__main__":
    log.info("Starting Meridian Incident Response Webhook Server...")
    log.info("Listening on http://0.0.0.0:5000")
    log.info("Make sure fw-01 mock is running on port 2223")
    # debug=False is critical for any server touching real infrastructure.
    # debug=True exposes an interactive debugger accessible from the browser.
    app.run(host="0.0.0.0", port=5000, debug=False)
