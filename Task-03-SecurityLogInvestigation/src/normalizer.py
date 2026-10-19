"""
Security Log Normalizer & Data Enrichment Pipeline
Task 03 - EdVyro Cybersecurity Internship

This module normalizes raw heterogeneous authentication event logs into a
structured, defensible schema suitable for SIEM ingestion and security analysis:
- Normalizes ISO-8601 timestamps to UTC and extracts temporal deltas.
- Classifies IP addresses into RFC 5737 documentation subnets and security zones.
- Standardizes user account identifiers and roles.
- Normalizes action types into standardized taxonomy (AUTHENTICATION, DEFENSE, SESSION).
- Normalizes outcome results (SUCCESS, FAILURE, BLOCKED).
- Normalizes device user-agents into standardized categories.
"""

import csv
import ipaddress
from datetime import datetime
from typing import Dict, List, Any


# RFC 5737 Documentation Network Mapping & Trust Classification
RFC_5737_NETWORKS = {
    ipaddress.ip_network("192.0.2.0/24"): {
        "network_label": "TEST-NET-1",
        "zone": "Internal / Campus Network",
        "trust_level": "Trusted"
    },
    ipaddress.ip_network("198.51.100.0/24"): {
        "network_label": "TEST-NET-2",
        "zone": "External ISP / Remote Student",
        "trust_level": "Untrusted - Standard"
    },
    ipaddress.ip_network("203.0.113.0/24"): {
        "network_label": "TEST-NET-3",
        "zone": "External Hosting / Anonymized Proxy",
        "trust_level": "Hostile / Suspect"
    }
}

EVENT_ACTION_TAXONOMY = {
    "password_login": {
        "category": "AUTHENTICATION",
        "description": "Interactive password-based login attempt",
        "is_interactive": True
    },
    "account_lock": {
        "category": "DEFENSIVE_CONTROL",
        "description": "Server-side account lockout triggered by policy",
        "is_interactive": False
    },
    "rate_limit": {
        "category": "DEFENSIVE_CONTROL",
        "description": "Per-IP or per-endpoint throttling block triggered",
        "is_interactive": False
    },
    "refresh_token": {
        "category": "SESSION_MANAGEMENT",
        "description": "OAuth2 / JWT session token renewal request",
        "is_interactive": False
    }
}

RESULT_MAPPING = {
    "success": {"normalized": "SUCCESS", "security_status": "ALLOW", "http_equiv": 200},
    "failure": {"normalized": "FAILURE", "security_status": "DENY", "http_equiv": 401},
    "blocked": {"normalized": "BLOCKED", "security_status": "BLOCK", "http_equiv": 429}
}

DEVICE_MAPPING = {
    "android": {"type": "Mobile", "os": "Android", "anomaly_flag": False},
    "ios": {"type": "Mobile", "os": "iOS", "anomaly_flag": False},
    "windows": {"type": "Desktop", "os": "Windows", "anomaly_flag": False},
    "server": {"type": "Infrastructure", "os": "Internal Server Daemon", "anomaly_flag": False},
    "unknown": {"type": "Unknown", "os": "Missing / Automated Script / Scraper", "anomaly_flag": True}
}


def classify_ip(ip_str: str) -> Dict[str, str]:
    """Classifies an IP address into RFC 5737 networks and trust zones."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        for network, meta in RFC_5737_NETWORKS.items():
            if ip_obj in network:
                return {
                    "source_ip": str(ip_obj),
                    "subnet": str(network),
                    "network_label": meta["network_label"],
                    "network_zone": meta["zone"],
                    "trust_level": meta["trust_level"]
                }
        return {
            "source_ip": str(ip_obj),
            "subnet": "Unknown",
            "network_label": "PUBLIC-OTHER",
            "network_zone": "External Internet",
            "trust_level": "Untrusted"
        }
    except ValueError:
        return {
            "source_ip": ip_str,
            "subnet": "Invalid",
            "network_label": "INVALID-IP",
            "network_zone": "Malformed",
            "trust_level": "Corrupt"
        }


def normalize_record(raw_record: Dict[str, str], previous_timestamp: datetime = None) -> Dict[str, Any]:
    """Normalizes a single authentication event log record."""
    raw_ts = raw_record["timestamp"].strip()
    dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
    iso_utc = dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    delta_seconds = None
    if previous_timestamp is not None:
        delta_seconds = int((dt - previous_timestamp).total_seconds())

    # User Account Normalization
    raw_user = raw_record["user_id"].strip().lower()

    # IP Classification
    ip_meta = classify_ip(raw_record["source_ip"])

    # Action Taxonomy
    raw_event = raw_record["event"].strip().lower()
    event_meta = EVENT_ACTION_TAXONOMY.get(raw_event, {
        "category": "UNKNOWN",
        "description": "Unrecognized security event",
        "is_interactive": False
    })

    # Result Normalization
    raw_res = raw_record["result"].strip().lower()
    res_meta = RESULT_MAPPING.get(raw_res, {
        "normalized": raw_res.upper(),
        "security_status": "UNKNOWN",
        "http_equiv": 500
    })

    # Device Normalization
    raw_dev = raw_record["device"].strip().lower()
    dev_meta = DEVICE_MAPPING.get(raw_dev, {
        "type": "Unrecognized",
        "os": raw_dev,
        "anomaly_flag": True
    })

    return {
        "timestamp_iso": iso_utc,
        "timestamp_epoch": int(dt.timestamp()),
        "delta_seconds_from_prev": delta_seconds if delta_seconds is not None else 0,
        "user_id": raw_user,
        "source_ip": ip_meta["source_ip"],
        "subnet": ip_meta["subnet"],
        "network_label": ip_meta["network_label"],
        "network_zone": ip_meta["network_zone"],
        "trust_level": ip_meta["trust_level"],
        "event_raw": raw_event,
        "event_category": event_meta["category"],
        "is_interactive": event_meta["is_interactive"],
        "result_normalized": res_meta["normalized"],
        "security_status": res_meta["security_status"],
        "http_status_equiv": res_meta["http_equiv"],
        "device_raw": raw_dev,
        "device_type": dev_meta["type"],
        "device_os": dev_meta["os"],
        "device_anomaly": dev_meta["anomaly_flag"]
    }


def normalize_log_file(input_csv_path: str, output_csv_path: str = None) -> List[Dict[str, Any]]:
    """Loads a raw CSV log file, normalizes all records, and optionally writes output."""
    normalized_records = []
    prev_dt = None

    with open(input_csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            record = normalize_record(row, prev_dt)
            prev_dt = datetime.fromisoformat(record["timestamp_iso"].replace("Z", "+00:00"))
            normalized_records.append(record)

    if output_csv_path:
        if normalized_records:
            fieldnames = list(normalized_records[0].keys())
            with open(output_csv_path, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(normalized_records)

    return normalized_records


if __name__ == "__main__":
    import os
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    in_path = os.path.join(base_dir, "data", "raw_authentication_log.csv")
    out_path = os.path.join(base_dir, "data", "normalized_authentication_log.csv")
    recs = normalize_log_file(in_path, out_path)
    print(f"[+] Successfully normalized {len(recs)} records to {out_path}")
