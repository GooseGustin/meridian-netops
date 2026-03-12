#!/usr/bin/env python3
"""
scripts/02_netmiko_connect.py

Netmiko connection to the mock Cisco device.
Compare with 01_raw_paramiko.py — same result, a fraction of the code.
"""

import os
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from dotenv import load_dotenv
from netmiko.cisco.cisco_ios import CiscoIosSSH

class MockCiscoSSH(CiscoIosSSH):
    def set_terminal_width(self, *args, **kwargs):
        """Skip terminal width setup — mock server doesn't support it."""
        return ""
    def set_terminal_length(self, *args, **kwargs):
        return ""   # Similarly skip terminal length handshake
    
load_dotenv()


def connect_and_gather(device_dict):
    """Connect to a device and run a set of show commands."""
    host = device_dict["host"]
    print(f"\n[+] Connecting to {host}:{device_dict['port']} ({device_dict['device_type']})...")

    try:
        # ConnectHandler handles: SSH negotiation, banner, prompt detection,
        # terminal length 0, and enable mode — all automatically.
        # with ConnectHandler(**device_dict) as conn:
        with MockCiscoSSH(**device_dict) as conn:
            prompt = conn.find_prompt()
            print(f"[+] Connected. Prompt: {prompt}")

            results = {}

            # commands = ["show version", "show ip interface brief", "show ip route"]
            commands = ["uname -a", "df -h", "free -m"]
            for cmd in commands:
                output = conn.send_command(cmd)
                results[cmd] = output
                # Print a preview
                preview = output.strip().splitlines()
                if preview:
                    print(f"  [{cmd}] -> {preview[0][:70]}...")

            return results

    except NetmikoAuthenticationException:
        print(f"[!] Authentication failed for {host}")
    except NetmikoTimeoutException:
        print(f"[!] Connection timed out for {host}")
    except Exception as exc:
        print(f"[!] Unexpected error on {host}: {exc}")

    return {}


def main():
    # The device dictionary is Netmiko's core abstraction.
    # device_type tells Netmiko which prompt patterns, commands, and
    # quirks to use. "cisco_ios" handles all IOS-style devices.
    edge_router = {
        "device_type": "linux",
        "host": "127.0.0.1",
        "port": 2225,
        "username": os.getenv("DOCKER_USERNAME"),
        "password": os.getenv("DOCKER_PASSWORD"),
        "fast_cli": False,  # Disable fast_cli for better compatibility
        "global_delay_factor": 2,  # Increase delay for slower devices
    }

    results = connect_and_gather(edge_router)

    print("\n=== Full Output: show ip interface brief ===")
    print(results.get("show ip interface brief", "(no output)"))


if __name__ == "__main__":
    main()
