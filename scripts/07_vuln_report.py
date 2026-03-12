#!/usr/bin/env python3
"""
scripts/07_vuln_report.py

Creates a simulated vulnerability report (Nessus-style JSON),
filters for critical issues, and produces an actionable remediation list.

In a real environment: load from scanner API or XML export.
Here: we build realistic data to practice the parsing logic.
"""

import json
from datetime import datetime
from pathlib import Path

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

# --- Simulated vulnerability data ---
# CVSS scores: 0-3.9 Low, 4-6.9 Medium, 7-8.9 High, 9-10 Critical
RAW_VULNERABILITIES = [
    {
        "plugin_id": "10881",
        "plugin_name": "SSH Protocol Version 1 Session Key Retrieval",
        "hostname": "fw-01",
        "ip_address": "10.0.1.1",
        "operating_system": "Cisco IOS",
        "cvss_base_score": 7.5,
        "severity": "High",
        "description": "The remote SSH daemon supports SSH protocol version 1.",
        "solution": "Disable SSH v1 and enforce SSH v2 only: 'ip ssh version 2'",
        "port": 22,
        "protocol": "tcp",
    },
    {
        "plugin_id": "10940",
        "plugin_name": "Telnet Service Running",
        "hostname": "fw-01",
        "ip_address": "10.0.1.1",
        "operating_system": "Cisco IOS",
        "cvss_base_score": 9.1,
        "severity": "Critical",
        "description": "Telnet transmits data in cleartext. Credentials can be intercepted.",
        "solution": "Disable Telnet on all VTY lines: 'transport input ssh'",
        "port": 23,
        "protocol": "tcp",
    },
    {
        "plugin_id": "51192",
        "plugin_name": "SSL Certificate Cannot Be Trusted",
        "hostname": "web-01",
        "ip_address": "10.0.10.5",
        "operating_system": "Ubuntu Linux 22.04",
        "cvss_base_score": 6.5,
        "severity": "Medium",
        "description": "The server's SSL certificate is self-signed.",
        "solution": "Replace with a certificate from a trusted CA.",
        "port": 443,
        "protocol": "tcp",
    },
    {
        "plugin_id": "97861",
        "plugin_name": "Linux Kernel Privilege Escalation (CVE-2022-0847)",
        "hostname": "web-01",
        "ip_address": "10.0.10.5",
        "operating_system": "Ubuntu Linux 22.04",
        "cvss_base_score": 7.8,
        "severity": "High",
        "description": "Dirty Pipe — allows overwriting data in read-only files via Linux kernel.",
        "solution": "Upgrade kernel to 5.16.11, 5.15.25, or 5.10.102.",
        "port": None,
        "protocol": "local",
    },
    {
        "plugin_id": "97862",
        "plugin_name": "Linux Kernel Remote Code Execution (CVE-2022-1015)",
        "hostname": "db-01",
        "ip_address": "10.0.20.5",
        "operating_system": "Ubuntu Linux 22.04",
        "cvss_base_score": 8.8,
        "severity": "High",
        "description": "Out-of-bounds write in Linux netfilter allows privilege escalation.",
        "solution": "Upgrade kernel: sudo apt-get update && sudo apt-get upgrade linux-image-generic",
        "port": None,
        "protocol": "local",
    },
    {
        "plugin_id": "11213",
        "plugin_name": "SNMP Agent Default Community Name (public)",
        "hostname": "edge-router-01",
        "ip_address": "10.0.0.1",
        "operating_system": "Cisco IOS",
        "cvss_base_score": 5.3,
        "severity": "Medium",
        "description": "The remote SNMP daemon uses the default 'public' community string.",
        "solution": "Change SNMP community strings to non-default values.",
        "port": 161,
        "protocol": "udp",
    },
    {
        "plugin_id": "38664",
        "plugin_name": "ICMP Timestamp Request Remote Date Disclosure",
        "hostname": "core-sw-01",
        "ip_address": "10.0.2.1",
        "operating_system": "Cisco IOS",
        "cvss_base_score": 2.6,
        "severity": "Low",
        "description": "Timestamp replies can be used by an attacker to determine uptime.",
        "solution": "Disable ICMP timestamp replies: 'no ip icmp time-exceeded'",
        "port": None,
        "protocol": "icmp",
    },
]


def prioritise_vulnerabilities(vulns, min_cvss=7.0):
    """
    Filter and sort vulnerabilities by severity.
    Returns findings at or above the minimum CVSS threshold.
    """
    filtered = [v for v in vulns if v["cvss_base_score"] >= min_cvss]
    # Sort: Critical first (highest CVSS), then High
    filtered.sort(key=lambda x: x["cvss_base_score"], reverse=True)
    return filtered


def group_by_host(vulns):
    """Group vulnerabilities by hostname for remediation planning."""
    groups = {}
    for vuln in vulns:
        host = vuln["hostname"]
        if host not in groups:
            groups[host] = []
        groups[host].append(vuln)
    return groups


def create_remediation_tasks(vulns):
    """
    Create ITSM-style task records from filtered vulnerabilities.
    In a real workflow, this would call the ServiceNow or Jira API.
    """
    tasks = []
    for i, vuln in enumerate(vulns, start=1001):
        task = {
            "task_id": f"MFG-{i}",
            "status": "New",
            "priority": "Critical" if vuln["cvss_base_score"] >= 9.0 else "High",
            "assigned_to": (
                "Network Ops Team" if "Cisco" in vuln["operating_system"]
                else "Linux Admin Team"
            ),
            "affected_host": vuln["hostname"],
            "affected_ip": vuln["ip_address"],
            "cve_or_plugin": vuln["plugin_id"],
            "vulnerability": vuln["plugin_name"],
            "cvss": vuln["cvss_base_score"],
            "solution": vuln["solution"],
            "created": datetime.now().isoformat(),
        }
        tasks.append(task)
    return tasks


def print_remediation_report(tasks):
    """Print a formatted remediation briefing."""
    print("\n" + "=" * 70)
    print("MERIDIAN FINANCIAL GROUP — VULNERABILITY REMEDIATION BRIEF")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 70)

    critical = [t for t in tasks if t["priority"] == "Critical"]
    high = [t for t in tasks if t["priority"] == "High"]

    print(f"\nCRITICAL ({len(critical)} tasks):")
    for task in critical:
        print(f"  [{task['task_id']}] {task['affected_host']}: {task['vulnerability']}")
        print(f"         CVSS: {task['cvss']} | Assigned: {task['assigned_to']}")
        print(f"         Fix: {task['solution'][:80]}")
        print()

    print(f"HIGH ({len(high)} tasks):")
    for task in high:
        print(f"  [{task['task_id']}] {task['affected_host']}: {task['vulnerability']}")
        print(f"         CVSS: {task['cvss']} | Assigned: {task['assigned_to']}")
        print()


def main():
    print("=== Meridian Lab — Vulnerability Report Parser ===\n")
    print(f"Total vulnerabilities in report: {len(RAW_VULNERABILITIES)}")

    # Filter for actionable items
    critical_and_high = prioritise_vulnerabilities(RAW_VULNERABILITIES, min_cvss=7.0)
    print(f"At or above CVSS 7.0 (actionable): {len(critical_and_high)}")

    # Group by host
    by_host = group_by_host(critical_and_high)
    print("\nVulnerabilities by host:")
    for host, vulns in by_host.items():
        print(f"  {host}: {len(vulns)} finding(s)")

    # Create remediation tasks
    tasks = create_remediation_tasks(critical_and_high)

    # Print report
    print_remediation_report(tasks)

    # Save to JSON
    output = {
        "scan_date": datetime.now().isoformat(),
        "total_findings": len(RAW_VULNERABILITIES),
        "actionable_findings": len(critical_and_high),
        "tasks": tasks,
    }
    path = REPORT_DIR / "remediation_tasks.json"
    with open(path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nTasks saved to: {path}")


if __name__ == "__main__":
    main()
