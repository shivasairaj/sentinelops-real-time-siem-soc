# pip3 install flask flask-cors requests

from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import os
from datetime import datetime, timedelta
from collections import defaultdict

app = Flask(__name__)
CORS(app)

# Path to Wazuh alerts file (NDJSON format)
ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
MAX_LINES = 300

# ------------------------------------------------------------------
# Mock alerts used when the real Wazuh file is unavailable
# ------------------------------------------------------------------
MOCK_ALERTS = [
    {"id": "1001", "timestamp": "2025-03-23T10:01:00.000Z", "rule": {"level": 14, "description": "SQL Injection attempt detected", "id": "31106"}, "data": {"srcip": "192.168.1.45"}, "agent": {"name": "web-server-01", "ip": "10.0.0.5"}, "location": "/var/log/apache2/access.log"},
    {"id": "1002", "timestamp": "2025-03-23T10:03:22.000Z", "rule": {"level": 12, "description": "Brute force attack on SSH", "id": "5712"}, "data": {"srcip": "203.0.113.88"}, "agent": {"name": "bastion-host", "ip": "10.0.0.10"}, "location": "/var/log/auth.log"},
    {"id": "1003", "timestamp": "2025-03-23T10:05:10.000Z", "rule": {"level": 7, "description": "Multiple failed login attempts", "id": "5503"}, "data": {"srcip": "198.51.100.22"}, "agent": {"name": "app-server-02", "ip": "10.0.0.12"}, "location": "/var/log/secure"},
    {"id": "1004", "timestamp": "2025-03-23T10:08:45.000Z", "rule": {"level": 15, "description": "Ransomware behavior detected", "id": "87002"}, "data": {"srcip": "172.16.0.99"}, "agent": {"name": "workstation-07", "ip": "10.0.1.7"}, "location": "syscheck"},
    {"id": "1005", "timestamp": "2025-03-23T10:11:00.000Z", "rule": {"level": 3, "description": "System audit log cleared", "id": "1002"}, "data": {"srcip": ""}, "agent": {"name": "dc-01", "ip": "10.0.0.2"}, "location": "WinEvtLog"},
    {"id": "1006", "timestamp": "2025-03-23T10:14:30.000Z", "rule": {"level": 10, "description": "Port scan detected from external IP", "id": "40501"}, "data": {"srcip": "45.33.32.156"}, "agent": {"name": "firewall-edge", "ip": "10.0.0.1"}, "location": "/var/log/firewall.log"},
    {"id": "1007", "timestamp": "2025-03-23T10:18:05.000Z", "rule": {"level": 8, "description": "Suspicious PowerShell execution", "id": "91234"}, "data": {"srcip": "10.0.1.15"}, "agent": {"name": "workstation-12", "ip": "10.0.1.15"}, "location": "WinEvtLog"},
    {"id": "1008", "timestamp": "2025-03-23T10:22:50.000Z", "rule": {"level": 14, "description": "Privilege escalation attempt", "id": "5401"}, "data": {"srcip": "203.0.113.10"}, "agent": {"name": "linux-srv-03", "ip": "10.0.0.20"}, "location": "/var/log/auth.log"},
    {"id": "1009", "timestamp": "2025-03-23T10:25:00.000Z", "rule": {"level": 6, "description": "Unusual outbound traffic volume", "id": "31530"}, "data": {"srcip": "10.0.2.44"}, "agent": {"name": "db-server-01", "ip": "10.0.0.30"}, "location": "netflow"},
    {"id": "1010", "timestamp": "2025-03-23T10:28:15.000Z", "rule": {"level": 13, "description": "Malware signature matched in file upload", "id": "62002"}, "data": {"srcip": "198.51.100.77"}, "agent": {"name": "web-server-01", "ip": "10.0.0.5"}, "location": "/var/log/clamav/clamd.log"},
    {"id": "1011", "timestamp": "2025-03-23T10:31:40.000Z", "rule": {"level": 4, "description": "User account created outside business hours", "id": "5902"}, "data": {"srcip": ""}, "agent": {"name": "dc-01", "ip": "10.0.0.2"}, "location": "WinEvtLog"},
    {"id": "1012", "timestamp": "2025-03-23T10:35:20.000Z", "rule": {"level": 11, "description": "Suspicious DNS query to known C2 domain", "id": "82101"}, "data": {"srcip": "10.0.1.30"}, "agent": {"name": "workstation-05", "ip": "10.0.1.30"}, "location": "/var/log/named.log"},
    {"id": "1013", "timestamp": "2025-03-23T10:39:00.000Z", "rule": {"level": 9, "description": "Web application firewall rule triggered", "id": "31301"}, "data": {"srcip": "185.220.101.5"}, "agent": {"name": "waf-proxy", "ip": "10.0.0.8"}, "location": "/var/log/modsec_audit.log"},
    {"id": "1014", "timestamp": "2025-03-23T10:42:55.000Z", "rule": {"level": 2, "description": "Config file modified on monitored path", "id": "550"}, "data": {"srcip": ""}, "agent": {"name": "app-server-02", "ip": "10.0.0.12"}, "location": "syscheck"},
    {"id": "1015", "timestamp": "2025-03-23T10:47:10.000Z", "rule": {"level": 14, "description": "Data exfiltration pattern detected", "id": "99001"}, "data": {"srcip": "91.189.91.23"}, "agent": {"name": "db-server-01", "ip": "10.0.0.30"}, "location": "netflow"},
]


# ------------------------------------------------------------------
# Severity mapping based on Wazuh rule level
# ------------------------------------------------------------------
def get_severity(level):
    """Map numeric Wazuh rule level to a severity label."""
    try:
        level = int(level)
    except (ValueError, TypeError):
        return "LOW"
    if level >= 13:
        return "CRIT"
    elif level >= 10:
        return "HIGH"
    elif level >= 6:
        return "MED"
    else:
        return "LOW"


# ------------------------------------------------------------------
# File reading helpers
# ------------------------------------------------------------------
def wazuh_file_available():
    """Return True if the Wazuh alerts file exists and is readable."""
    return os.path.isfile(ALERTS_FILE) and os.access(ALERTS_FILE, os.R_OK)


def read_last_n_lines(filepath, n=300):
    """Efficiently read the last N lines from a potentially large file."""
    try:
        with open(filepath, "rb") as f:
            # Seek from end to gather roughly n lines without loading entire file
            f.seek(0, 2)
            file_size = f.tell()
            block_size = 8192
            lines = []
            remaining = file_size

            while remaining > 0 and len(lines) < n + 1:
                read_size = min(block_size, remaining)
                remaining -= read_size
                f.seek(remaining)
                chunk = f.read(read_size)
                lines = chunk.splitlines() + lines

        # Return last n non-empty lines as decoded strings
        result = []
        for line in lines[-n:]:
            if isinstance(line, bytes):
                line = line.decode("utf-8", errors="replace")
            line = line.strip()
            if line:
                result.append(line)
        return result
    except Exception as e:
        print(f"[SentinelOPS] Error reading alerts file: {e}")
        return []


def parse_alert(raw):
    """Parse a single raw alert dict into the standardised dashboard structure."""
    return {
        "id": str(raw.get("id", "")),
        "timestamp": raw.get("timestamp", ""),
        "severity": get_severity(raw.get("rule", {}).get("level", 0)),
        "message": raw.get("rule", {}).get("description", "Unknown"),
        "source_ip": raw.get("data", {}).get(
            "srcip", raw.get("agent", {}).get("ip", "Unknown")
        ),
        "rule_id": str(raw.get("rule", {}).get("id", "")),
        "rule_name": raw.get("rule", {}).get("description", ""),
        "agent": raw.get("agent", {}).get("name", "unknown"),
        "location": raw.get("location", ""),
    }


def load_alerts():
    """
    Load and parse alerts.
    Returns a list of parsed alert dicts, newest first.
    Falls back to mock data if the file is unavailable.
    """
    parsed = []

    if wazuh_file_available():
        lines = read_last_n_lines(ALERTS_FILE, MAX_LINES)
        for line in lines:
            try:
                raw = json.loads(line)
                parsed.append(parse_alert(raw))
            except json.JSONDecodeError as e:
                # A single malformed line must never crash the server
                print(f"[SentinelOPS] Skipping malformed alert line: {e}")
            except Exception as e:
                print(f"[SentinelOPS] Unexpected error parsing alert: {e}")
    else:
        # Development fallback: use built-in mock alerts
        print("[SentinelOPS] Wazuh alerts file not found — using mock data.")
        for raw in MOCK_ALERTS:
            try:
                parsed.append(parse_alert(raw))
            except Exception as e:
                print(f"[SentinelOPS] Error parsing mock alert: {e}")

    # Sort newest first based on timestamp string (ISO 8601 sorts lexicographically)
    parsed.sort(key=lambda a: a.get("timestamp", ""), reverse=True)
    return parsed


# ------------------------------------------------------------------
# API Endpoints
# ------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    """Health check — reports whether the Wazuh file is reachable."""
    return jsonify({
        "status": "ok",
        "wazuh_connected": wazuh_file_available()
    })


@app.route("/api/events", methods=["GET"])
def events():
    """Return the 50 most recent alerts, newest first."""
    alerts = load_alerts()
    return jsonify(alerts[:50])


@app.route("/api/stats", methods=["GET"])
def stats():
    """Return aggregate counts broken down by severity."""
    alerts = load_alerts()

    counts = {"CRIT": 0, "HIGH": 0, "MED": 0, "LOW": 0}
    for alert in alerts:
        sev = alert.get("severity", "LOW")
        if sev in counts:
            counts[sev] += 1

    critical_count = counts["CRIT"]
    return jsonify({
        "total_24h": len(alerts),
        "critical": critical_count,
        "high": counts["HIGH"],
        "medium": counts["MED"],
        "low": counts["LOW"],
        # Multiplied for demo realism
        "threats_blocked": critical_count * 247,
    })


@app.route("/api/attackers", methods=["GET"])
def attackers():
    """Return the top 10 source IPs ranked by alert frequency."""
    alerts = load_alerts()

    ip_data = defaultdict(lambda: {"count": 0, "last_seen": "", "attack_type": ""})

    for alert in alerts:
        ip = alert.get("source_ip", "")
        # Skip empty or placeholder IPs
        if not ip or ip == "Unknown":
            continue
        ip_data[ip]["count"] += 1
        # Keep the most recent timestamp
        ts = alert.get("timestamp", "")
        if ts > ip_data[ip]["last_seen"]:
            ip_data[ip]["last_seen"] = ts
            ip_data[ip]["attack_type"] = alert.get("rule_name", "")

    # Build and sort the result list
    result = [
        {
            "ip": ip,
            "count": data["count"],
            "last_seen": data["last_seen"],
            "attack_type": data["attack_type"],
        }
        for ip, data in ip_data.items()
    ]
    result.sort(key=lambda x: x["count"], reverse=True)
    return jsonify(result[:10])


@app.route("/api/chart/hourly", methods=["GET"])
def chart_hourly():
    """
    Return an array of 24 integers — alert counts per hour over the last 24 hours.
    Index 0 = oldest hour, index 23 = current (most recent) hour.
    """
    alerts = load_alerts()
    now = datetime.utcnow()
    # Build a bucket for each of the last 24 hours
    buckets = [0] * 24

    for alert in alerts:
        ts_str = alert.get("timestamp", "")
        if not ts_str:
            continue
        try:
            # Handle both with and without sub-second precision
            ts_str_clean = ts_str.replace("Z", "").split("+")[0]
            # Try microseconds first, fall back to seconds
            try:
                ts = datetime.strptime(ts_str_clean, "%Y-%m-%dT%H:%M:%S.%f")
            except ValueError:
                ts = datetime.strptime(ts_str_clean, "%Y-%m-%dT%H:%M:%S")

            delta = now - ts
            hours_ago = int(delta.total_seconds() // 3600)

            # Only include alerts within the last 24 hours
            if 0 <= hours_ago < 24:
                # Index 23 = current hour, index 0 = 23 hours ago
                bucket_index = 23 - hours_ago
                buckets[bucket_index] += 1
        except Exception as e:
            print(f"[SentinelOPS] Could not parse timestamp '{ts_str}': {e}")

    return jsonify(buckets)


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------
if __name__ == "__main__":
    print("[SentinelOPS] Starting Flask backend on 0.0.0.0:5000 ...")
    app.run(host="0.0.0.0", port=5000, debug=False)