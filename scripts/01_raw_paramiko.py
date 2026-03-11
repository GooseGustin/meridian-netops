#!/usr/bin/env python3
"""
scripts/01_raw_paramiko.py

Raw Paramiko SSH connection to the mock Cisco device.
Purpose: understand what happens under the hood before using Netmiko.
"""

import os
import time

import paramiko
from dotenv import load_dotenv

load_dotenv()

# --- Connection parameters ---
HOST = "127.0.0.1"
PORT = 2225
USERNAME = os.getenv("DOCKER_USERNAME")
PASSWORD = os.getenv("DOCKER_PASSWORD")
# USERNAME = os.getenv("DEVICE_USERNAME")
# PASSWORD = os.getenv("DEVICE_PASSWORD")


def raw_cisco_session(host, port, username, password):
    """
    Opens a raw SSH interactive shell to a Cisco-like device.
    Returns the collected output as a string.
    """
    client = paramiko.SSHClient()

    # AutoAddPolicy trusts new host keys automatically.
    # In production, use RejectPolicy and pre-populate known_hosts.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print(f"[+] Connecting to {host}:{port} as '{username}'...")
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=10,
        look_for_keys=False,   # Don't try SSH key auth
        allow_agent=False,     # Don't use SSH agent
    )

    transport = client.get_transport()
    print(f"[+] Connected. Cipher: {transport.remote_cipher}")

    # Open an interactive shell channel — this is what Netmiko does internally
    shell = client.invoke_shell(width=200, height=200)

    # Give the device time to send its banner and prompt
    time.sleep(1.5)
    initial = shell.recv(4096).decode("utf-8", errors="ignore")
    print("[+] Initial banner/prompt received:")
    print(initial)

    # --- Helper: send a command and collect output ---
    def send_cmd(command, wait=1.5):
        shell.send(command + "\n")
        time.sleep(wait)
        out = ""
        while shell.recv_ready():
            out += shell.recv(4096).decode("utf-8", errors="ignore")
            time.sleep(0.1)
        return out

    # Cisco-specific: disable output pagination
    send_cmd("terminal length 0", wait=0.5)

    # Run commands
    commands = [
	"uname -a", "ip addr show", "df -h"
        # "show version",
        # "show ip interface brief",
        # "show ip route",
    ]

    all_output = {}
    for cmd in commands:
        print(f"\n[+] Sending: {cmd}")
        output = send_cmd(cmd)
        # Strip the command echo from the output
        lines = output.splitlines()
        clean = [line for line in lines if cmd not in line and line.strip()]
        all_output[cmd] = "\n".join(clean)
        print(all_output[cmd][:400])

    client.close()
    print("\n[+] Disconnected.")
    return all_output


def main():
    output = raw_cisco_session(HOST, PORT, USERNAME, PASSWORD)
    print("\n=== Summary ===")
    for cmd, result in output.items():
        first_line = result.splitlines()[0] if result.splitlines() else "(empty)"
        print(f"  {cmd}: {first_line[:60]}...")


if __name__ == "__main__":
    main()
