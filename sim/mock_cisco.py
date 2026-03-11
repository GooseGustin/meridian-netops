#!/usr/bin/env python3
"""
sim/mock_cisco.py

Simulates a Cisco IOS SSH device for the Meridian lab.

Usage:
    python sim/mock_cisco.py --config sim/devices/edge-router-01.yaml --port 2222
"""

import argparse
import logging
import socket
import threading
import time

import paramiko
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

# Generate a fresh RSA host key each time the server starts.
# In production, you would load a persistent key from disk.
HOST_KEY = paramiko.RSAKey.generate(2048)


class CiscoSSHServer(paramiko.ServerInterface):
    """Handles the SSH handshake and authentication."""

    def __init__(self, device):
        self.device = device
        self.shell_event = threading.Event()

    def check_auth_password(self, username, password):
        creds = self.device.get("credentials", {})
        if username == creds.get("username") and password == creds.get("password"):
            return paramiko.AUTH_SUCCESSFUL
        log.warning("Authentication failed for user '%s'", username)
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.shell_event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                   pixelwidth, pixelheight, modes):
        return True


class CiscoShell(threading.Thread):
    """
    Runs the interactive shell session on a connected channel.
    Reads characters, assembles lines, and dispatches to handle().
    """

    # Commands that should be silently acknowledged (Netmiko sends these
    # as part of its connection setup — they must not return errors).
    SILENT_CMDS = {
        "terminal length 0",
        "terminal width 511",
        "terminal width 256",
        "terminal width 0",
        "",
    }

    def __init__(self, channel, device):
        super().__init__(daemon=True)
        self.channel = channel
        self.device = device
        self.hostname = device["hostname"]
        self.mode = "exec"   # "exec" or "config"

    @property
    def prompt(self):
        if self.mode == "config":
            return f"{self.hostname}(config)#"
        return f"{self.hostname}#"

    def handle(self, raw_cmd):
        """
        Given a raw command string, return the appropriate response.
        Returns an empty string for commands that should be silently ignored.
        """
        cmd = raw_cmd.strip()
        lower = cmd.lower()

        if cmd in self.SILENT_CMDS:
            return ""

        if lower in ("enable", "disable"):
            return ""

        if lower == "configure terminal":
            self.mode = "config"
            return (
                "Enter configuration commands, one per line.  "
                "End with CNTL/Z."
            )

        if lower in ("end", "exit"):
            self.mode = "exec"
            return ""

        if lower == "show version":
            return self.device.get("show_version", "% Command not available")

        if lower == "show ip interface brief":
            return self._format_ip_brief()

        if lower == "show running-config":
            return self.device.get("running_config", "! no config loaded")

        if lower == "show ip route":
            return self.device.get("show_ip_route", "% No routing table")

        if lower == "show access-lists":
            return self.device.get("show_access_lists", "% No ACLs configured")

        if lower.startswith("show processes cpu"):
            return self.device.get(
                "show_cpu",
                "CPU utilization for five seconds: 8%/0%; one minute: 5%; "
                "five minutes: 6%"
            )

        if lower.startswith("show cdp neighbors"):
            return self.device.get("show_cdp_neighbors", "% CDP not enabled")

        if lower.startswith("show vlan"):
            return self.device.get("show_vlan", "% VLAN not configured")

        if lower.startswith("show ntp"):
            return self.device.get(
                "show_ntp",
                "Clock is synchronized, stratum 3, reference is 10.0.0.254"
            )

        if lower.startswith("show snmp"):
            return self.device.get("show_snmp", "% SNMP not configured")

        if lower in ("write memory", "copy running-config startup-config"):
            return "Building configuration...\n[OK]"

        if lower.startswith("ping"):
            parts = cmd.split()
            target = parts[1] if len(parts) > 1 else "unknown"
            return (
                f"Type escape sequence to abort.\n"
                f"Sending 5, 100-byte ICMP Echos to {target}, timeout is 2 seconds:\n"
                f"!!!!!\n"
                f"Success rate is 100 percent (5/5), round-trip min/avg/max = 1/2/3 ms"
            )

        # In config mode, accept all commands silently (simulate IOS config acceptance)
        if self.mode == "config":
            return ""

        return f"% Unknown command or computer in command: '{cmd}'"

    def _format_ip_brief(self):
        """Format the 'show ip interface brief' table from YAML data."""
        header = (
            f"{'Interface':<23}{'IP-Address':<16}"
            f"{'OK?':<4}{'Method':<8}{'Status':<23}Protocol"
        )
        rows = [header]
        for intf, data in self.device.get("interfaces", {}).items():
            ip = data.get("ip", "unassigned")
            ok = "YES" if ip != "unassigned" else "NO "
            method = data.get("method", "NVRAM")
            status = data.get("status", "up")
            protocol = data.get("protocol", "up")
            rows.append(
                f"{intf:<23}{ip:<16}{ok}  {method:<7} {status:<22}{protocol}"
            )
        return "\n".join(rows)

    def run(self):
        """Main shell loop: read characters, build lines, respond."""
        banner = self.device.get("banner", "")
        if banner:
            self.channel.send(f"\r\n{banner}\r\n".encode())
        self.channel.send(f"\r\n{self.prompt} ".encode())

        buf = ""
        while True:
            try:
                if not self.channel.active:
                    break
                if self.channel.recv_ready():
                    data = self.channel.recv(1024).decode("utf-8", errors="ignore")
                    for char in data:
                        if char in ("\r", "\n"):
                            response = self.handle(buf)
                            echo = f"{buf}\r\n"
                            if response:
                                self.channel.send(
                                    f"\r\n{response}\r\n{self.prompt} ".encode()
                                )
                            else:
                                self.channel.send(
                                    f"\r\n{self.prompt} ".encode()
                                )
                            buf = ""
                        else:
                            buf += char
                time.sleep(0.02)
            except (OSError, EOFError):
                break


def handle_client(client_sock, device):
    """Spin up a Paramiko transport for one incoming SSH connection."""
    transport = paramiko.Transport(client_sock)
    transport.add_server_key(HOST_KEY)
    server_interface = CiscoSSHServer(device)
    try:
        transport.start_server(server=server_interface)
        channel = transport.accept(timeout=30)
        if channel is None:
            log.warning("Client connected but no channel was opened.")
            return
        server_interface.shell_event.wait(timeout=10)
        if not server_interface.shell_event.is_set():
            log.warning("Shell was never requested.")
            return
        shell = CiscoShell(channel, device)
        shell.start()
        shell.join()
    except Exception as exc:
        log.error("Transport error: %s", exc)
    finally:
        transport.close()


def main():
    parser = argparse.ArgumentParser(description="Meridian Mock Cisco SSH Device")
    parser.add_argument("--config", required=True, help="Path to device YAML file")
    parser.add_argument("--port", type=int, default=2222, help="TCP port to listen on")
    args = parser.parse_args()

    with open(args.config) as f:
        device = yaml.safe_load(f)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", args.port))
    sock.listen(10)
    log.info("Mock device '%s' listening on 127.0.0.1:%d", device["hostname"], args.port)

    try:
        while True:
            client, addr = sock.accept()
            log.info("Connection from %s", addr)
            threading.Thread(
                target=handle_client,
                args=(client, device),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        log.info("Shutting down.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
