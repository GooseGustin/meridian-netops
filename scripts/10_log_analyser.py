#!/usr/bin/env python3
"""
scripts/10_log_analyser.py

Analyses auth.log for:
  1. SSH brute-force attacks (many failures from one IP)
  2. Successful logins following failures (compromise indicator)
  3. Suspicious outbound connections (C2 beacon indicator)

This is signature + heuristic detection in ~100 lines of Python.
The same logic powers commercial SIEM correlation rules — just at scale.
"""

import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

LOG_FILE = Path("logs/auth.log")

# Detection thresholds — in production these would be tuned per-environment
# to balance true positive rate against analyst alert fatigue
BRUTE_FORCE_THRESHOLD = 10     # failures from one IP within the log window
C2_SUSPICIOUS_PORTS = {4444, 4443, 1337, 31337, 6667}  # known C2 and RAT ports

# Regex patterns for each log event type.
# (\S+) = one or more non-whitespace characters (capturing group)
# \d+   = one or more digits (non-capturing — we don't need the PID)
FAILED_RE = re.compile(
    r"(\w+ \d+ \d+:\d+:\d+) (\S+) sshd\[\d+\]: Failed password for (\S+) from (\S+) port"
)
SUCCESS_RE = re.compile(
    r"(\w+ \d+ \d+:\d+:\d+) (\S+) sshd\[\d+\]: Accepted (?:password|publickey) for (\S+) from (\S+) port"
)
UFW_RE = re.compile(
    r"(\w+ \d+ \d+:\d+:\d+) (\S+) kernel.*UFW BLOCK.*SRC=(\S+) DST=(\S+).*DPT=(\d+)"
)


def analyse_log(log_path):
    """Parse the auth.log and return structured findings.

    defaultdict(list) means: if a key doesn't exist, create it with an
    empty list as the default value. This lets us do failed_attempts[ip].append(...)
    without checking if ip is already in the dict.

    We use continue after each match to avoid running all three regex checks
    on every line (early exit pattern — more efficient).
    """
    failed_attempts = defaultdict(list)   # ip -> list of {time, user, host}
    successful_logins = []
    ufw_blocks = []

    with open(log_path) as f:
        for line in f:
            # Failed passwords
            m = FAILED_RE.search(line)
            if m:
                timestamp, host, user, src_ip = m.groups()
                failed_attempts[src_ip].append({
                    "timestamp": timestamp,
                    "host": host,
                    "user": user,
                })
                continue

            # Successful logins
            m = SUCCESS_RE.search(line)
            if m:
                timestamp, host, user, src_ip = m.groups()
                successful_logins.append({
                    "timestamp": timestamp,
                    "host": host,
                    "user": user,
                    "src_ip": src_ip,
                })
                continue

            # UFW blocks (outbound C2 indicators)
            m = UFW_RE.search(line)
            if m:
                timestamp, host, src, dst, dpt = m.groups()
                ufw_blocks.append({
                    "timestamp": timestamp,
                    "host": host,
                    "src_ip": src,
                    "dst_ip": dst,
                    "dst_port": int(dpt),
                })

    return failed_attempts, successful_logins, ufw_blocks


def detect_brute_force(failed_attempts):
    """Flag IPs exceeding the brute-force threshold.

    Collects the set of targeted usernames to identify if this is
    a targeted attack (one user) or a dictionary scan (many users).
    Dictionary scans targeting many accounts suggest automated tooling.
    """
    alerts = []
    for ip, attempts in failed_attempts.items():
        if len(attempts) >= BRUTE_FORCE_THRESHOLD:
            unique_users = {a["user"] for a in attempts}
            alerts.append({
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
                "attacker_ip": ip,
                "attempt_count": len(attempts),
                "targeted_users": list(unique_users),
                "first_seen": attempts[0]["timestamp"],
                "last_seen": attempts[-1]["timestamp"],
                "affected_host": attempts[0]["host"],
            })
    return alerts


def detect_post_brute_success(failed_attempts, successful_logins):
    """
    Detect IPs that had failed attempts AND a subsequent successful login.

    This is a correlation rule — two events that are individually possible
    (failed login, then successful login from same IP) that together form
    a high-confidence compromise indicator.

    In a real SIEM: this is a "sequence" alert or an "entity enrichment" rule.
    The brute_force_ips set is built first as an O(1) lookup structure,
    then each successful login is checked against it.
    """
    brute_force_ips = {ip for ip, attempts in failed_attempts.items()
                       if len(attempts) >= BRUTE_FORCE_THRESHOLD}
    alerts = []
    for login in successful_logins:
        if login["src_ip"] in brute_force_ips:
            alerts.append({
                "type": "LIKELY_COMPROMISE",
                "severity": "CRITICAL",
                "attacker_ip": login["src_ip"],
                "compromised_user": login["user"],
                "compromised_host": login["host"],
                "login_time": login["timestamp"],
                "message": (
                    f"IP {login['src_ip']} failed {len(failed_attempts[login['src_ip']])} times "
                    f"then successfully logged in as '{login['user']}' on {login['host']}."
                ),
            })
    return alerts


def detect_c2_beacons(ufw_blocks):
    """Flag outbound connections to known C2 ports.

    UFW blocked the connection — the host didn't actually reach the C2 server.
    But the *attempt* proves:
    1. Code on the host initiated an outbound connection to an unusual port.
    2. The host is compromised and attempting to establish a reverse shell or beacon.

    The firewall being the last line of defense here is exactly why
    defence-in-depth matters: SSH brute force succeeded, but UFW caught
    the C2 callback.
    """
    alerts = []
    for block in ufw_blocks:
        if block["dst_port"] in C2_SUSPICIOUS_PORTS:
            alerts.append({
                "type": "C2_BEACON",
                "severity": "CRITICAL",
                "src_ip": block["src_ip"],
                "dst_ip": block["dst_ip"],
                "dst_port": block["dst_port"],
                "host": block["host"],
                "timestamp": block["timestamp"],
                "message": (
                    f"Internal host {block['src_ip']} ({block['host']}) attempted "
                    f"outbound connection to {block['dst_ip']}:{block['dst_port']} — "
                    f"known C2 port."
                ),
            })
    return alerts


def main():
    print("=== Meridian SOC — Log Analysis Engine ===\n")

    if not LOG_FILE.exists():
        print(f"Log file not found: {LOG_FILE}")
        print("Run scripts/09_generate_logs.py first.")
        return

    failed, successes, ufw_blocks = analyse_log(LOG_FILE)

    print(f"Log parsed:")
    print(f"  Failed SSH attempts from {len(failed)} unique IPs")
    print(f"  Successful logins: {len(successes)}")
    print(f"  Outbound blocks: {len(ufw_blocks)}")

    # Run detectors
    brute_alerts = detect_brute_force(failed)
    compromise_alerts = detect_post_brute_success(failed, successes)
    c2_alerts = detect_c2_beacons(ufw_blocks)

    all_alerts = brute_alerts + compromise_alerts + c2_alerts

    print(f"\n=== ALERTS ({len(all_alerts)} total) ===")
    for alert in all_alerts:
        print(f"\n[{alert['severity']}] {alert['type']}")
        for k, v in alert.items():
            if k not in ("type", "severity"):
                print(f"  {k}: {v}")

    # Save
    report = {
        "analysis_time": datetime.now().isoformat(),
        "log_file": str(LOG_FILE),
        "alerts": all_alerts,
        "raw_stats": {
            "unique_attacker_ips": len(failed),
            "total_failed_attempts": sum(len(a) for a in failed.values()),
            "successful_logins": len(successes),
            "outbound_blocks": len(ufw_blocks),
        },
    }
    path = REPORT_DIR / "log_analysis.json"
    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nReport: {path}")
    print("\nThe attack timeline:")
    print("  1. Brute-force from 185.220.101.47 (87 attempts)")
    print("  2. Successful login as 'oracle' — likely compromise")
    print("  3. Outbound C2 beacon to 185.156.73.42:4444")
    print("\nNext: Lab 5 will check these IPs against a threat intelligence feed.")


if __name__ == "__main__":
    main()
