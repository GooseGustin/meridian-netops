#!/usr/bin/env python3
"""
scripts/06_nmap_scan.py

Runs an Nmap scan against Meridian hosts and saves the results
as a structured JSON report. In a real environment, this would run
against the production subnet; here we target localhost ports.
"""

import json
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

# In WSL, the Docker containers appear on localhost with their mapped ports.
# We model this as "web-01 at 127.0.0.1:2225" = "host 127.0.0.1, port 2225".
# For a real network, you would scan the actual subnet.
SCAN_TARGETS = [
    {"hostname": "web-01", "host": "127.0.0.1", "ports": "2225"},
    {"hostname": "db-01",  "host": "127.0.0.1", "ports": "2226"},
]

# Simulate a broader port scan result for the full Meridian network
# (pretend these came from a real scan of 10.0.0.0/24)
SIMULATED_SCAN_FINDINGS = [
    {
        "hostname": "edge-router-01",
        "ip": "10.0.0.1",
        "open_ports": [
            {"port": 22, "service": "ssh", "version": "OpenSSH 7.4", "state": "open"},
            {"port": 443, "service": "https", "version": "Cisco HTTPS", "state": "open"},
        ],
        "os_guess": "Cisco IOS 15.x",
    },
    {
        "hostname": "fw-01",
        "ip": "10.0.1.1",
        "open_ports": [
            {"port": 22, "service": "ssh", "version": "OpenSSH 7.4", "state": "open"},
            {"port": 23, "service": "telnet", "version": "", "state": "open"},  # Security issue!
        ],
        "os_guess": "Cisco IOS 15.x",
    },
    {
        "hostname": "web-01",
        "ip": "10.0.10.5",
        "open_ports": [
            {"port": 22, "service": "ssh", "version": "OpenSSH 8.9p1", "state": "open"},
            {"port": 80, "service": "http", "version": "Apache 2.4.52", "state": "open"},
            {"port": 443, "service": "https", "version": "Apache 2.4.52", "state": "open"},
        ],
        "os_guess": "Ubuntu 22.04",
    },
    {
        "hostname": "db-01",
        "ip": "10.0.20.5",
        "open_ports": [
            {"port": 22, "service": "ssh", "version": "OpenSSH 8.9p1", "state": "open"},
            {"port": 5432, "service": "postgresql", "version": "PostgreSQL 14", "state": "open"},
            {"port": 3306, "service": "mysql", "version": "MySQL 8.0", "state": "open"},
        ],
        "os_guess": "Ubuntu 22.04",
    },
]


def run_real_nmap(host, ports, output_file):
    """Run Nmap against a real host and return parsed results."""
    cmd = [
        "nmap",
        "-sV",          # Service/version detection
        "-p", ports,    # Specific ports
        "--open",       # Only show open ports
        "-oX", str(output_file),
        host,
    ]
    print(f"  Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        print(f"  Nmap stderr: {result.stderr}")
    return result.returncode == 0


def parse_nmap_xml(xml_file):
    """Parse Nmap XML output into a list of host dicts."""
    hosts = []
    tree = ET.parse(xml_file)
    root = tree.getroot()

    for host_elem in root.findall("host"):
        if host_elem.find("status").get("state") != "up":
            continue

        addr_elem = host_elem.find("address")
        ip = addr_elem.get("addr") if addr_elem is not None else "unknown"

        hostnames = host_elem.find("hostnames")
        hostname = "unknown"
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "unknown")

        open_ports = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                state = port_elem.find("state")
                if state is not None and state.get("state") == "open":
                    service = port_elem.find("service")
                    open_ports.append({
                        "port": int(port_elem.get("portid")),
                        "protocol": port_elem.get("protocol"),
                        "service": service.get("name", "") if service is not None else "",
                        "version": service.get("version", "") if service is not None else "",
                        "state": "open",
                    })

        hosts.append({"ip": ip, "hostname": hostname, "open_ports": open_ports})

    return hosts


def flag_security_issues(scan_results):
    """
    Analyse scan results and flag potential security problems.
    This is the automation value: not just seeing what's open,
    but knowing what *shouldn't* be open.
    """
    HIGH_RISK_SERVICES = {23: "Telnet", 21: "FTP", 80: "HTTP (unencrypted)"}
    DB_PORTS = {5432, 3306, 27017, 1433}
    issues = []

    for host in scan_results:
        hostname = host.get("hostname", host["ip"])
        for port_info in host.get("open_ports", []):
            port = port_info["port"]
            service = port_info.get("service", "")

            if port in HIGH_RISK_SERVICES:
                issues.append({
                    "hostname": hostname,
                    "ip": host["ip"],
                    "issue": f"Insecure service open: {HIGH_RISK_SERVICES[port]} on port {port}",
                    "severity": "HIGH",
                    "recommendation": f"Disable {HIGH_RISK_SERVICES[port]} and migrate to encrypted alternative.",
                })

            if port in DB_PORTS:
                issues.append({
                    "hostname": hostname,
                    "ip": host["ip"],
                    "issue": f"Database port {port} ({service}) exposed",
                    "severity": "MEDIUM",
                    "recommendation": "Restrict database ports to application servers only via ACL.",
                })

    return issues


def main():
    print("=== Meridian Lab — Nmap Scan & Analysis ===\n")

    # Part 1: Run a real Nmap scan against Docker containers
    print("--- Part 1: Real Nmap Scan (Docker containers) ---")
    real_results = []
    for target in SCAN_TARGETS:
        xml_path = REPORT_DIR / f"nmap_{target['hostname']}.xml"
        success = run_real_nmap(target["host"], target["ports"], xml_path)
        if success and xml_path.exists():
            parsed = parse_nmap_xml(xml_path)
            for host in parsed:
                host["hostname"] = target["hostname"]
            real_results.extend(parsed)
            print(f"  {target['hostname']}: {len(parsed[0]['open_ports']) if parsed else 0} open ports")

    # Part 2: Analyse the simulated full-network scan
    print("\n--- Part 2: Simulated Network Analysis ---")
    issues = flag_security_issues(SIMULATED_SCAN_FINDINGS)

    print(f"\n  Security issues found: {len(issues)}")
    for issue in issues:
        print(f"  [{issue['severity']}] {issue['hostname']}: {issue['issue']}")

    # Write report
    report = {
        "scan_time": datetime.now().isoformat(),
        "real_scan_results": real_results,
        "simulated_network": SIMULATED_SCAN_FINDINGS,
        "security_issues": issues,
    }
    report_path = REPORT_DIR / "scan_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nReport: {report_path}")
    print("\nKey finding: fw-01 has Telnet (port 23) open. This violates Meridian policy.")
    print("This will become the starting point for Lab 3's remediation workflow.")


if __name__ == "__main__":
    main()
