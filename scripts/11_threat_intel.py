#!/usr/bin/env python3
"""
scripts/11_threat_intel.py

Checks IPs from the log analysis against AbuseIPDB threat intelligence.
Falls back to a static local feed if the API is unavailable.

Get a free API key at: https://www.abuseipdb.com/register
Set it in .env as: ABUSEIPDB_API_KEY=your_key_here
"""

import json
import os
import time
from datetime import datetime
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

REPORT_DIR = Path("reports")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Static local threat feed — used when API is unavailable.
# In production: sync from MISP, AlienVault OTX, or a STIX/TAXII feed.
# Key: IP address. Value: threat data dict matching AbuseIPDB response shape.
LOCAL_THREAT_FEED = {
    "185.220.101.47": {
        "score": 100,
        "reports": 8423,
        "categories": ["SSH brute force", "Port scan"],
        "country": "RU",
        "isp": "Tor exit node",
        "last_seen": "2024-03-14",
        "feed_source": "local_static",
    },
    "185.156.73.42": {
        "score": 98,
        "reports": 1247,
        "categories": ["C2 server", "Malware distribution"],
        "country": "NL",
        "isp": "Bulletproof Hosting Ltd",
        "last_seen": "2024-03-15",
        "feed_source": "local_static",
    },
    "192.168.1.1": {
        "score": 0,
        "reports": 0,
        "categories": [],
        "country": "Private",
        "isp": "RFC1918",
        "last_seen": None,
        "feed_source": "local_static",
    },
}


def check_ip_abuseipdb(ip, api_key):
    """Query AbuseIPDB for IP reputation. Returns None on failure.

    The API response 'data' object contains:
    - abuseConfidenceScore: 0-100 reputation score
    - totalReports: number of community reports
    - countryCode: ISO 3166-1 alpha-2 country code
    - isp: ISP name (often reveals bulletproof hosters)
    - lastReportedAt: ISO timestamp of most recent report
    """
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,   # Only consider reports from the past 90 days
        "verbose": True,
    }
    try:
        resp = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "score": data.get("abuseConfidenceScore", 0),
                "reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "unknown"),
                "isp": data.get("isp", "unknown"),
                "last_seen": data.get("lastReportedAt", None),
                "feed_source": "abuseipdb_api",
            }
        elif resp.status_code == 429:
            print(f"  Rate limited by AbuseIPDB. Falling back to local feed.")
    except requests.RequestException as exc:
        print(f"  API unavailable ({exc}). Using local feed.")
    return None


def check_ip(ip, api_key=None):
    """Check an IP against available threat sources.

    Priority order:
    1. Live AbuseIPDB API (most current)
    2. Local static feed (offline fallback)
    3. No data (IP not in any feed)

    This graceful degradation ensures the script always returns
    a result — even if the internet is unreachable.
    """
    result = {"ip": ip, "threat_data": None, "source": "none"}

    # Try live API first
    if api_key:
        threat_data = check_ip_abuseipdb(ip, api_key)
        if threat_data:
            result["threat_data"] = threat_data
            result["source"] = "abuseipdb"
            return result
        time.sleep(1)  # Respect rate limits between API calls

    # Fall back to local feed
    if ip in LOCAL_THREAT_FEED:
        result["threat_data"] = LOCAL_THREAT_FEED[ip]
        result["source"] = "local_feed"
        return result

    result["threat_data"] = {"score": 0, "reports": 0, "categories": []}
    result["source"] = "no_data"
    return result


def enrich_alerts_with_intel(log_report_path, api_key=None):
    """Load log analysis report and enrich alerts with threat intel.

    Uses a checked_ips set to avoid querying the same IP twice —
    important because a single attacker IP might appear in multiple
    alert types (brute_force + likely_compromise + c2_beacon).

    The {**alert, "threat_intelligence": ...} syntax creates a new dict
    that merges the original alert fields with the new intel field.
    """
    with open(log_report_path) as f:
        report = json.load(f)

    enriched_alerts = []
    checked_ips = set()

    for alert in report["alerts"]:
        # Extract the relevant IP from the alert — field name varies by alert type
        ip = (
            alert.get("attacker_ip")
            or alert.get("src_ip")
            or alert.get("dst_ip")
        )
        if not ip or ip in checked_ips:
            continue
        checked_ips.add(ip)

        print(f"  Checking IP: {ip}...")
        intel = check_ip(ip, api_key)

        enriched_alert = {**alert, "threat_intelligence": intel["threat_data"]}
        score = intel["threat_data"].get("score", 0) if intel["threat_data"] else 0

        # Tiered response based on confidence score
        if score >= 80:
            enriched_alert["confirmed_malicious"] = True
            enriched_alert["severity"] = "CRITICAL"
        elif score >= 40:
            enriched_alert["confirmed_malicious"] = False
            enriched_alert["severity"] = "HIGH"
        else:
            enriched_alert["confirmed_malicious"] = False

        enriched_alerts.append(enriched_alert)

    return enriched_alerts


def main():
    print("=== Meridian SOC — Threat Intelligence Enrichment ===\n")

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        print("No ABUSEIPDB_API_KEY in .env — using local threat feed.\n")

    log_report = REPORT_DIR / "log_analysis.json"
    if not log_report.exists():
        print("Run scripts/10_log_analyser.py first.")
        return

    print("Enriching alerts with threat intelligence...")
    enriched = enrich_alerts_with_intel(log_report, api_key)

    print(f"\n=== ENRICHED ALERTS ===")
    for alert in enriched:
        intel = alert.get("threat_intelligence", {})
        score = intel.get("score", "N/A") if intel else "N/A"
        ip = alert.get("attacker_ip") or alert.get("src_ip") or alert.get("dst_ip")
        print(f"\n[{alert['severity']}] {alert['type']}")
        print(f"  IP: {ip} | Abuse Score: {score}/100")
        if intel:
            print(f"  ISP: {intel.get('isp', 'unknown')} | Country: {intel.get('country', 'unknown')}")
            cats = intel.get('categories', [])
            if cats:
                print(f"  Categories: {', '.join(cats)}")
        if alert.get("confirmed_malicious"):
            print(f"  STATUS: CONFIRMED MALICIOUS — automated response warranted")

    # Save enriched report
    output = {
        "enrichment_time": datetime.now().isoformat(),
        "enriched_alerts": enriched,
    }
    path = REPORT_DIR / "enriched_alerts.json"
    with open(path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nEnriched report: {path}")
    print("\nNext: Lab 6 will automatically block these IPs on the mock firewall.")


if __name__ == "__main__":
    main()
