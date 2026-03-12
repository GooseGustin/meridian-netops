#!/usr/bin/env python3
"""
scripts/09_generate_logs.py

Generates a realistic auth.log with embedded brute-force attack.
Run this to create the log file before running the analyser.

The log contains three phases of the attack lifecycle:
  1. Normal baseline activity (before the attack)
  2. Brute-force attack + successful compromise
  3. Post-compromise C2 beacon attempt
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

# Attacker IP from threat intelligence (will appear in Lab 5)
# 185.220.101.47 is a known Tor exit node and brute-force source in real feeds
ATTACKER_IP = "185.220.101.47"
LEGITIMATE_IPS = ["10.50.0.10", "10.50.0.11", "10.50.0.15"]
USERNAMES = ["admin", "root", "ubuntu", "netops", "oracle", "postgres"]

def make_timestamp(base_time, offset_seconds):
    t = base_time + timedelta(seconds=offset_seconds)
    return t.strftime("%b %d %H:%M:%S")

def main():
    base = datetime(2024, 3, 15, 2, 0, 0)  # 2 AM — suspicious time for high-volume activity
    lines = []

    # Normal activity before the attack — legitimate logins via public key auth
    # "Accepted publickey" is the secure pattern (key-based, not password-based)
    for i in range(20):
        ip = random.choice(LEGITIMATE_IPS)
        ts = make_timestamp(base, -3600 + i * 120)
        lines.append(f"{ts} web-01 sshd[1234]: Accepted publickey for netops from {ip} port 49{i:03d} ssh2")
        lines.append(f"{ts} web-01 sshd[1235]: Disconnected from {ip} port 49{i:03d}")

    # Brute-force attack: many failed attempts from ATTACKER_IP within 60 seconds
    # Note: "Accepted password" (not publickey) — attacker is using password auth
    # This means the target has password auth enabled (a misconfiguration)
    print(f"Embedding brute-force attack from {ATTACKER_IP} starting at {make_timestamp(base, 0)}")
    for i in range(87):   # 87 attempts — well above any sane threshold
        ts = make_timestamp(base, i // 3)  # ~30 attempts per 10 seconds
        user = random.choice(USERNAMES)
        port = 51000 + i
        lines.append(
            f"{ts} web-01 sshd[{9000+i}]: Failed password for {user} "
            f"from {ATTACKER_IP} port {port} ssh2"
        )

    # One successful login by attacker (they found a weak account)
    # "oracle" had a guessable password — this is the compromise event
    success_ts = make_timestamp(base, 35)
    lines.append(
        f"{success_ts} web-01 sshd[9100]: Accepted password for oracle "
        f"from {ATTACKER_IP} port 52000 ssh2"
    )
    lines.append(
        f"{success_ts} web-01 sshd[9100]: pam_unix(sshd:session): "
        f"session opened for user oracle from {ATTACKER_IP}"
    )

    # Post-compromise: suspicious outbound connection (C2 beacon)
    # UFW blocked the connection but the attempt is logged.
    # DST=185.156.73.42 (the C2 server), DPT=4444 (Metasploit default listener)
    c2_ts = make_timestamp(base, 90)
    lines.append(
        f"{c2_ts} web-01 kernel: [UFW BLOCK] IN= OUT=eth0 SRC=10.0.10.5 "
        f"DST=185.156.73.42 PROTO=TCP DPT=4444"
    )

    # Normal activity resumes (cover — attack blends into normal traffic)
    for i in range(10):
        ip = random.choice(LEGITIMATE_IPS)
        ts = make_timestamp(base, 300 + i * 60)
        lines.append(f"{ts} web-01 sshd[2000]: Accepted publickey for netops from {ip} port 50{i:03d} ssh2")

    log_path = LOG_DIR / "auth.log"
    with open(log_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Generated {len(lines)} log lines -> {log_path}")
    print("The attack timeline is embedded. Run 10_log_analyser.py to find it.")

if __name__ == "__main__":
    main()
