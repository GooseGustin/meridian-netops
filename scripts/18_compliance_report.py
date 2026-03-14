#!/usr/bin/env python3
"""
scripts/18_compliance_report.py

Generates a comprehensive Meridian compliance report.
Reads all audit results and produces:
  - Markdown report (for Git / Obsidian)
  - CSV summary (for spreadsheets / management)

Does NOT connect to any devices — reads from saved JSON reports only.
This decoupling means the report is always producible even if devices are down.
"""

import csv
import json
from datetime import datetime
from pathlib import Path

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)


def load_latest_report(pattern):
    """Load the most recent report matching a glob pattern.

    Reports are named with timestamps (e.g., drift_report_20240315_1430.json).
    Sorting in reverse lexicographic order puts the latest timestamp first.
    Returns None if no matching file exists.
    """
    files = sorted(REPORT_DIR.glob(pattern), reverse=True)
    if not files:
        return None
    with open(files[0]) as f:
        return json.load(f)


def write_markdown_report(devices, docker_hosts, timestamp):
    """Write a Markdown compliance report.

    The report has four sections:
    1. Summary table (device, status, drift counts) — executive overview
    2. Drift details — specific lines that changed, for the engineer
    3. Linux hosts — Docker container findings
    4. Remediation priority list — ordered action items

    This structure mirrors a real compliance report that would go to:
    - The CISO (reads the summary table)
    - The Network Ops team (reads the drift details and remediation list)
    - The auditor (reads everything, wants the Markdown exported to PDF)
    """
    lines = [
        f"# Meridian Financial Group — Compliance Report",
        f"",
        f"**Generated:** {timestamp}  ",
        f"**Policy:** PCI-DSS 4.0 / Internal Security Policy v3.0  ",
        f"**Scope:** Lagos DC — All network devices and servers  ",
        f"",
        f"---",
        f"",
        f"## Network Devices",
        f"",
        f"| Device | Status | Security Drift | Policy Violations | Missing Requirements |",
        f"|:-------|:------:|:--------------:|:-----------------:|:--------------------:|",
    ]

    for d in devices:
        status_badge = "COMPLIANT" if d.get("status") == "COMPLIANT" else "**DRIFT DETECTED**"
        sec_drift = len(d.get("security_drift", []))
        violations = len(d.get("policy_violations", []))
        missing = len(d.get("missing_requirements", []))
        lines.append(
            f"| {d['hostname']} | {status_badge} | {sec_drift} | {violations} | {missing} |"
        )

    lines += ["", "### Drift Details", ""]
    for d in devices:
        if d.get("security_drift") or d.get("policy_violations"):
            lines.append(f"#### {d['hostname']}")
            if d.get("policy_violations"):
                lines.append("")
                lines.append("**Policy Violations:**")
                for v in d["policy_violations"]:
                    lines.append(f"- `[{v['severity']}]` {v['type']}: `{v['line']}`")
            if d.get("security_drift"):
                lines.append("")
                lines.append("**Config Drift (security-relevant):**")
                for line in d["security_drift"]:
                    lines.append(f"- `{line}`")
            lines.append("")

    lines += [
        "---",
        "",
        "## Linux Hosts (Docker)",
        "",
        "| Host | Findings | Key Issues |",
        "|:-----|:--------:|:-----------|",
    ]

    if docker_hosts:
        for h in docker_hosts:
            count = h.get("finding_count", 0)
            issues = ", ".join(
                f['message'][:60] for f in h.get("security_findings", [])
            ) or "None"
            lines.append(f"| {h['container']} | {count} | {issues} |")
    else:
        lines.append("| No Docker audit data available | — | — |")

    lines += [
        "",
        "---",
        "",
        "## Remediation Priority",
        "",
        "| Priority | Item | Device | Action |",
        "|:--------:|:-----|:-------|:-------|",
    ]

    prio = 1
    for d in devices:
        for v in d.get("policy_violations", []):
            lines.append(
                f"| {prio} | {v['line'][:50]} | {d['hostname']} | Remove/Replace |"
            )
            prio += 1
        for m in d.get("missing_requirements", []):
            lines.append(
                f"| {prio} | {m['line'][:50]} | {d['hostname']} | Add to config |"
            )
            prio += 1

    lines += [
        "",
        "---",
        "",
        "*Report generated automatically by Meridian Compliance Engine*",
    ]

    return "\n".join(lines)


def write_csv_report(devices, docker_hosts, csv_path):
    """Write a CSV summary for management reporting.

    newline="" is required by the csv module on Windows to prevent
    double newlines. The quoting mode handles commas within field values.
    """
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Device", "Type", "Status", "Security Drift Count",
            "Policy Violations", "Missing Requirements", "Compliant"
        ])
        for d in devices:
            writer.writerow([
                d["hostname"],
                "Cisco IOS",
                d.get("status", "unknown"),
                len(d.get("security_drift", [])),
                len(d.get("policy_violations", [])),
                len(d.get("missing_requirements", [])),
                "YES" if d.get("status") == "COMPLIANT" else "NO",
            ])
        if docker_hosts:
            for h in docker_hosts:
                writer.writerow([
                    h["container"],
                    "Linux",
                    "REVIEWED",
                    0,
                    h.get("finding_count", 0),
                    0,
                    "NO" if h.get("finding_count", 0) > 0 else "YES",
                ])


def main():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"=== Meridian Compliance Report Generator ===")
    print(f"Timestamp: {timestamp}\n")

    # Load available data — does not connect to any devices
    drift_data = load_latest_report("drift_report_*.json")
    docker_data = load_latest_report("docker_audit_*.json")

    if not drift_data:
        print("No drift report found. Run scripts/14_drift_detect.py first.")
        return

    devices = drift_data if isinstance(drift_data, list) else []

    # Generate reports
    md_content = write_markdown_report(devices, docker_data, timestamp)
    md_path = REPORT_DIR / f"compliance_report_{datetime.now().strftime('%Y%m%d')}.md"
    with open(md_path, "w") as f:
        f.write(md_content)
    print(f"Markdown report: {md_path}")

    csv_path = REPORT_DIR / f"compliance_summary_{datetime.now().strftime('%Y%m%d')}.csv"
    write_csv_report(devices, docker_data, csv_path)
    print(f"CSV summary: {csv_path}")

    # Quick terminal summary
    total = len(devices)
    compliant = sum(1 for d in devices if d.get("status") == "COMPLIANT")
    print(f"\nCompliance rate: {compliant}/{total} devices ({100*compliant//total if total else 0}%)")


if __name__ == "__main__":
    main()
