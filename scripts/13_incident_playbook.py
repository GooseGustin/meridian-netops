#!/usr/bin/env python3
"""
scripts/13_incident_playbook.py

End-to-end incident response playbook for Meridian Financial Group.

Pipeline:
  1. Parse auth.log for attack indicators
  2. Enrich attacker IPs with threat intelligence
  3. For confirmed malicious IPs: push blocking ACL to firewall
  4. Generate incident report

This script ties together Labs 4, 5, 6, and 3.
"""

import json
import os
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException

# --- MockCiscoSSH fix ---
# The step_3_contain() function connects to fw-01 (port 2223 mock SSH server).
# Netmiko's standard cisco_ios driver sends "terminal width 511" and expects
# to see it echoed back — the mock server can't satisfy this check.
#
# Override set_terminal_width() in a subclass so it returns "" immediately,
# bypassing the echo-check. This is defined inline to avoid import path issues
# (running scripts/13_incident_playbook.py adds scripts/ not project root to sys.path).
from netmiko.cisco.cisco_ios import CiscoIosSSH

class MockCiscoSSH(CiscoIosSSH):
    """Bypass terminal width/length handshakes for mock Cisco SSH servers.

    Use this instead of ConnectHandler when device_type='cisco_ios' and
    you're connecting to the Python mock SSH server. In GNS3 or real hardware,
    use ConnectHandler directly.
    """
    def set_terminal_width(self, *args, **kwargs):
        return ""   # Bypass "terminal width 511" echo-check
    def set_terminal_length(self, *args, **kwargs):
        return ""   # Bypass "terminal length 0" echo-check

load_dotenv()

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)
LOG_DIR = Path("logs")

# Pre-populated threat intel — in production, query the enrichment API
# (as in Lab 5's 11_threat_intel.py) rather than hardcoding.
ATTACKER_IPS_KNOWN_MALICIOUS = {"185.220.101.47", "185.156.73.42"}

FIREWALL = {
    "device_type": "cisco_ios",
    "host": "127.0.0.1",
    "port": 2223,
    "username": os.getenv("DEVICE_USERNAME"),
    "password": os.getenv("DEVICE_PASSWORD"),
}

FAILED_RE = re.compile(
    r"(\w+ \d+ \d+:\d+:\d+) (\S+) sshd\[\d+\]: Failed password for (\S+) from (\S+) port"
)
SUCCESS_RE = re.compile(
    r"(\w+ \d+ \d+:\d+:\d+) (\S+) sshd\[\d+\]: Accepted (?:password|publickey) for (\S+) from (\S+) port"
)


def step_1_detect(log_path):
    """Parse auth.log and identify attacker IPs and compromised accounts.

    An "attacker" IP is one with >= 10 failed SSH attempts in the log.
    A "compromised" account is a successful login from an attacker IP.
    Both indicators together paint a clear attack timeline.
    """
    print("\n[STEP 1] Parsing auth.log for indicators...")
    failed = defaultdict(list)
    successes = []

    with open(log_path) as f:
        for line in f:
            m = FAILED_RE.search(line)
            if m:
                _, host, user, src = m.groups()
                failed[src].append({"host": host, "user": user})
            m = SUCCESS_RE.search(line)
            if m:
                ts, host, user, src = m.groups()
                successes.append({"timestamp": ts, "host": host, "user": user, "ip": src})

    attackers = {ip for ip, attempts in failed.items() if len(attempts) >= 10}
    print(f"  Identified {len(attackers)} attacker IP(s): {attackers}")

    compromised = [s for s in successes if s["ip"] in attackers]
    if compromised:
        print(f"  COMPROMISE DETECTED: {len(compromised)} successful login(s) from attacker IPs")
        for c in compromised:
            print(f"    -> {c['ip']} logged in as '{c['user']}' on {c['host']} at {c['timestamp']}")

    return attackers, compromised


def step_2_enrich(attacker_ips):
    """Cross-reference attacker IPs against known malicious IP sets.

    In production: call the AbuseIPDB API or MISP threat feed (Lab 5).
    Here: check against ATTACKER_IPS_KNOWN_MALICIOUS (pre-loaded intel).

    Only IPs confirmed malicious proceed to containment.
    Unknown IPs are flagged for human review — automation should not
    block IPs without a confidence threshold.
    """
    print("\n[STEP 2] Enriching IPs with threat intelligence...")
    confirmed_malicious = []

    for ip in attacker_ips:
        if ip in ATTACKER_IPS_KNOWN_MALICIOUS:
            print(f"  {ip} — CONFIRMED MALICIOUS (local feed: abuse score 100)")
            confirmed_malicious.append(ip)
        else:
            print(f"  {ip} — reputation unknown (no feed data)")

    return confirmed_malicious


def step_3_contain(malicious_ips):
    """Push blocking ACL entries to fw-01 for each confirmed malicious IP.

    Uses MockCiscoSSH (not ConnectHandler) to connect to the mock SSH server.
    ConnectHandler would fail here because the mock server doesn't echo
    "terminal width 511" back, causing Netmiko's session setup to time out.

    For each IP, pushes:
    - deny ip host <ip> any log   (block inbound FROM attacker)
    - deny ip any host <ip> log   (block outbound TO attacker — prevents C2 callbacks)
    """
    print("\n[STEP 3] Containing threat — pushing firewall ACLs...")
    blocked = []

    for ip in malicious_ips:
        commands = [
            "ip access-list extended BLOCK_THREATS",
            f"deny ip host {ip} any log",
            f"deny ip any host {ip} log",
            "exit",
        ]
        try:
            # MockCiscoSSH bypasses the terminal width check for the mock server.
            # In a real Cisco device or GNS3 lab, replace MockCiscoSSH with:
            #   with ConnectHandler(**FIREWALL) as conn:
            with MockCiscoSSH(**FIREWALL) as conn:
                conn.send_config_set(commands)
                print(f"  Blocked: {ip} on fw-01")
                blocked.append(ip)
        except NetmikoTimeoutException:
            print(f"  FAILED to block {ip}: firewall timeout")
        except Exception as exc:
            print(f"  FAILED to block {ip}: {exc}")

    return blocked


def step_4_generate_report(attackers, compromised, blocked):
    """Generate a structured incident report.

    The report combines:
    - What happened (attacker IPs, compromised accounts)
    - What was done automatically (IPs blocked)
    - What still requires human action (account disablement, key rotation)

    The incident_id uses a timestamp to make it unique and sortable.
    In production: the ITSM system (ServiceNow, Jira) would assign the ID.
    """
    print("\n[STEP 4] Generating incident report...")

    report = {
        "incident_id": f"MFG-IR-{datetime.now().strftime('%Y%m%d%H%M')}",
        "timestamp": datetime.now().isoformat(),
        "status": "CONTAINED" if blocked else "OPEN",
        "summary": {
            "attacker_ips": list(attackers),
            "compromised_accounts": [c["user"] for c in compromised],
            "compromised_hosts": list({c["host"] for c in compromised}),
            "ips_blocked": blocked,
        },
        "timeline": [
            "Brute-force SSH attack detected on web-01",
            f"Attacker successfully authenticated as '{compromised[0]['user']}'" if compromised else "No successful logins",
            "Outbound C2 beacon blocked by UFW",
            f"{len(blocked)} attacker IP(s) blocked on perimeter firewall",
        ],
        "recommended_actions": [
            f"Disable account '{c['user']}' on {c['host']} immediately" for c in compromised
        ] + [
            "Review all outbound connections from web-01 for the past 24 hours",
            "Rotate SSH keys for all service accounts",
            "Enable fail2ban on all Linux hosts",
            "Implement SSH key-only auth (disable password auth)",
        ],
    }

    path = REPORT_DIR / f"incident_report_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n{'='*60}")
    print(f"INCIDENT REPORT: {report['incident_id']}")
    print(f"Status: {report['status']}")
    print(f"Attacker IPs: {', '.join(report['summary']['attacker_ips'])}")
    print(f"Compromised accounts: {', '.join(report['summary']['compromised_accounts'])}")
    print(f"IPs blocked: {', '.join(report['summary']['ips_blocked'])}")
    print(f"\nReport saved to: {path}")


def main():
    print("=" * 60)
    print("MERIDIAN FINANCIAL GROUP — INCIDENT RESPONSE PLAYBOOK")
    print(f"Initiated: {datetime.now().isoformat()}")
    print("=" * 60)

    log_path = LOG_DIR / "auth.log"
    if not log_path.exists():
        print("auth.log not found. Run scripts/09_generate_logs.py first.")
        return

    attackers, compromised = step_1_detect(log_path)
    malicious = step_2_enrich(attackers)
    blocked = step_3_contain(malicious)
    step_4_generate_report(attackers, compromised, blocked)

    print("\n=== Playbook complete ===")


if __name__ == "__main__":
    main()
