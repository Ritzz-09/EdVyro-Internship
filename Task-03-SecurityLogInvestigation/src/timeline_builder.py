"""
Incident Timeline & Evidence Reconstruction Builder
Task 03 - EdVyro Cybersecurity Internship

Reconstructs the full forensic sequence of events, strictly demarcating:
1. Empirical Log Evidence: Indisputable facts directly verifiable from log telemetry.
2. Analytical Assumptions: Hypotheses, threat context, and working theories requiring external verification.
"""

from typing import List, Dict, Any


def build_forensic_timeline(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Builds a structured chronological forensic timeline from normalized records."""
    timeline = []

    # Concrete contextual knowledge for the 12 events
    annotations = {
        "2026-08-01T09:00:12Z": {
            "phase": "Baseline Normal Activity",
            "evidence": "Account 'stu-104' logged in successfully with password from 192.0.2.18 (TEST-NET-1, Campus) via Android.",
            "assumptions": "Assumed to be a legitimate student accessing portal on campus Wi-Fi at start of academic day.",
            "defensive_outcome": "Allowed (HTTP 200). Baseline established."
        },
        "2026-08-01T09:03:44Z": {
            "phase": "Incident 1 - Targeted Brute Force",
            "evidence": "Account 'stu-117' failed password login from 198.51.100.27 (TEST-NET-2, External ISP) via Windows desktop.",
            "assumptions": "Could be user mistyping password, or external actor testing credentials against 'stu-117'.",
            "defensive_outcome": "Denied (HTTP 401). Failure count = 1."
        },
        "2026-08-01T09:04:01Z": {
            "phase": "Incident 1 - Targeted Brute Force",
            "evidence": "Account 'stu-117' failed password login again from same IP 198.51.100.27 (+17s later) via Windows desktop.",
            "assumptions": "User re-attempting or automated tool testing second password variation.",
            "defensive_outcome": "Denied (HTTP 401). Failure count = 2."
        },
        "2026-08-01T09:04:18Z": {
            "phase": "Incident 1 - Targeted Brute Force",
            "evidence": "Account 'stu-117' failed password login a 3rd time from 198.51.100.27 (+17s later) via Windows desktop.",
            "assumptions": "Consistent 17-second cadence strongly indicates automated script or rapid frantic manual entry.",
            "defensive_outcome": "Denied (HTTP 401). Threshold reached (3 consecutive failures in 34s)."
        },
        "2026-08-01T09:05:03Z": {
            "phase": "Incident 1 - Defensive Enforcement",
            "evidence": "Server-side daemon logged 'account_lock' event for 'stu-117' from 198.51.100.27 (+45s after 3rd failure). Result: success.",
            "assumptions": "Account lockout security control automatically triggered to prevent further password guessing. Account is now locked.",
            "defensive_outcome": "Enforced (Account Lockout Policy). Threat mitigated, but DoS condition created for stu-117."
        },
        "2026-08-01T09:21:10Z": {
            "phase": "Incident 2 - Password Spray Attack",
            "evidence": "Account 'stu-209' failed password login from external IP 203.0.113.42 (TEST-NET-3). Device reported as 'unknown'.",
            "assumptions": "Originating from untrusted hosting range with missing/generic User-Agent header; indicates automated attack script.",
            "defensive_outcome": "Denied (HTTP 401). Failure recorded."
        },
        "2026-08-01T09:21:13Z": {
            "phase": "Incident 2 - Password Spray Attack",
            "evidence": "Account 'stu-311' failed password login from 203.0.113.42 (+3s later). Device: 'unknown'.",
            "assumptions": "Rapid horizontal traversal to different user ID demonstrates automated password spraying (trying common password across accounts).",
            "defensive_outcome": "Denied (HTTP 401). Failure recorded."
        },
        "2026-08-01T09:21:17Z": {
            "phase": "Incident 2 - Password Spray Attack",
            "evidence": "Account 'stu-415' failed password login from 203.0.113.42 (+4s later). Device: 'unknown'.",
            "assumptions": "Third distinct account targeted in 7 seconds. Spray pattern confirmed.",
            "defensive_outcome": "Denied (HTTP 401). Failure recorded."
        },
        "2026-08-01T09:21:22Z": {
            "phase": "Incident 2 - Password Spray Attack",
            "evidence": "Account 'stu-502' failed password login from 203.0.113.42 (+5s later). Device: 'unknown'.",
            "assumptions": "Fourth distinct account targeted. Total duration of spray: 12 seconds across 4 accounts.",
            "defensive_outcome": "Denied (HTTP 401). Exceeded IP request rate threshold."
        },
        "2026-08-01T09:22:01Z": {
            "phase": "Incident 2 - Defensive Enforcement",
            "evidence": "Server-side daemon logged 'rate_limit' event blocking subsequent request from 203.0.113.42 referencing 'stu-209'. Result: blocked.",
            "assumptions": "Defensive rate limiting control successfully engaged against source IP 203.0.113.42, dropping further spray attempts.",
            "defensive_outcome": "Blocked (HTTP 429 / Edge Dropped). Attacker IP temporarily throttled."
        },
        "2026-08-01T10:15:32Z": {
            "phase": "Baseline Normal Activity",
            "evidence": "Account 'stu-104' executed 'refresh_token' from 192.0.2.18 via Android client. Result: success.",
            "assumptions": "Standard background OAuth2/JWT token refresh by student's active mobile session from morning login.",
            "defensive_outcome": "Allowed (HTTP 200). Normal operation confirmed."
        },
        "2026-08-01T11:47:09Z": {
            "phase": "Incident 3 - Unusual Access / Potential Compromise",
            "evidence": "Account 'stu-311' achieved successful password login from 192.0.2.99 (TEST-NET-1, Campus) via iOS mobile device.",
            "assumptions": "HYPOTHESIS 1 (Benign): Legitimate student arrived on campus and signed in on iPhone. HYPOTHESIS 2 (Compromise): Adversary used harvested credentials via campus Wi-Fi or compromised device. Out-of-band verification required.",
            "defensive_outcome": "Allowed (HTTP 200). Flagged for Priority SOC Follow-up."
        }
    }

    for r in records:
        ts = r["timestamp_iso"]
        ann = annotations.get(ts, {
            "phase": "General Activity",
            "evidence": f"User {r['user_id']} performed {r['event_raw']} from {r['source_ip']}.",
            "assumptions": "Standard logged event.",
            "defensive_outcome": r["result_normalized"]
        })

        item = {
            "timestamp": ts,
            "delta_seconds": r.get("delta_seconds_from_prev", 0),
            "phase": ann["phase"],
            "user_id": r["user_id"],
            "source_ip": r["source_ip"],
            "network_zone": r.get("network_zone", "Unknown"),
            "device": f"{r.get('device_raw', 'unknown')} ({r.get('device_type', 'Unknown')})",
            "action": r.get("event_raw"),
            "result": r.get("result_normalized"),
            "empirical_evidence": ann["evidence"],
            "analytical_assumptions": ann["assumptions"],
            "defensive_outcome": ann["defensive_outcome"]
        }
        timeline.append(item)

    return timeline


def format_timeline_markdown(timeline: List[Dict[str, Any]]) -> str:
    """Formats forensic timeline into structured GitHub Markdown."""
    md = [
        "# Forensic Incident Timeline: Evidence vs. Assumptions Reconstruction\n",
        "> **Methodology:** Every entry in this timeline strictly distinguishes between **Indisputable Log Evidence** (facts directly observed in telemetry) and **Analytical Assumptions** (working hypotheses, threat intelligence, and inferential deductions).\n\n",
        "| Time (UTC) | Phase | User | Source IP & Zone | Device | Action | Result | Empirical Log Evidence | Analytical Assumptions | Defensive Status |\n",
        "|:---|:---|:---:|:---|:---:|:---:|:---:|:---|:---|:---:|\n"
    ]

    for t in timeline:
        md.append(
            f"| `{t['timestamp']}` | **{t['phase']}** | `{t['user_id']}` | `{t['source_ip']}`<br><small>{t['network_zone']}</small> | `{t['device']}` | `{t['action']}` | **{t['result']}** | {t['empirical_evidence']} | *{t['analytical_assumptions']}* | `{t['defensive_outcome']}` |\n"
        )

    return "".join(md)


if __name__ == "__main__":
    import os
    from normalizer import normalize_log_file

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    in_path = os.path.join(base_dir, "data", "raw_authentication_log.csv")
    recs = normalize_log_file(in_path)
    timeline = build_forensic_timeline(recs)
    md_content = format_timeline_markdown(timeline)

    out_file = os.path.join(base_dir, "TIMELINE.md")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(md_content)

    print(f"[+] Reconstructed forensic timeline written to {out_file}")
