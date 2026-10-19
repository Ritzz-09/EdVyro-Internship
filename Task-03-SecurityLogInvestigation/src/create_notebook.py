"""
Jupyter Notebook Generator for Task 03 Security Log Investigation
Creates a fully self-contained, valid .ipynb notebook with markdown documentation,
code cells, analysis, detection algorithms, and visualizations.
"""

import json
import os

def build_notebook():
    cells = []

    def md(text):
        cells.append({
            "cell_type": "markdown",
            "metadata": {},
            "source": text.strip().splitlines(keepends=True)
        })

    def code(text):
        cells.append({
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": text.strip().splitlines(keepends=True)
        })

    # Header
    md("""
# 🛡️ Task 03: Security Log Investigation & DFIR Analysis
**Track:** Cyber Security | **Institution:** EdVyro Internship  
**Author:** RITHISH S P (`@Ritzz-09`) | **Repository:** [EdVyro-Internship](https://github.com/Ritzz-09/EdVyro-Internship)  

---

## 🎯 Executive Overview & Objectives
This notebook performs an end-to-end digital forensics and incident response (DFIR) investigation on a synthetic student portal authentication log.

### 📋 Passing Checklist Objectives:
1. **Normalize Data:** Standardize timestamps (UTC ISO-8601), IPs (RFC 5737 documentation networks), accounts, action taxonomy, and result fields.
2. **Define Detection Rules:** Implement defensible detection logic for:
   - **Targeted Brute-Force** (Vertical password guessing)
   - **Password Spraying** (Horizontal password guessing across accounts)
   - **Unusual Access Anomaly** (Anomalous post-spray activity)
3. **Reconstruct Evidentiary Timeline:** Reconstruct the chronology while strictly separating **empirical log evidence** from **analytical assumptions**.
4. **Portfolio Upgrade:** Provide actionable containment playbooks and logging architecture recommendations.
""")

    # Step 1: Loading
    md("""
## 1. Environment Setup & Raw Log Ingestion
We begin by importing forensic analysis packages (`pandas`, `datetime`, `ipaddress`, `matplotlib`) and inspecting the raw synthetic log dataset.
""")

    code("""
import os
import ipaddress
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime

# Load raw synthetic authentication logs
data_path = os.path.join("..", "data", "raw_authentication_log.csv")
df_raw = pd.read_csv(data_path)
print(f"Total raw log events ingested: {len(df_raw)}")
df_raw
""")

    # Step 2: Normalization
    md("""
## 2. Field Normalization & Network Enrichment

Raw logs often feature inconsistent timestamps, missing network context, and unclassified user agents.
In this step, we:
- Parse timestamps into UTC datetime objects and calculate inter-event deltas ($\Delta t$).
- Map IP addresses into **RFC 5737** documentation networks (`TEST-NET-1`, `TEST-NET-2`, `TEST-NET-3`) and assign trust boundaries.
- Normalize events into a standardized action taxonomy (`AUTHENTICATION`, `DEFENSIVE_CONTROL`, `SESSION_MANAGEMENT`).
- Standardize outcomes (`SUCCESS`, `FAILURE`, `BLOCKED`) and map equivalent HTTP response codes.
- Classify client devices and flag user-agent anomalies (`unknown` = scraper / script).
""")

    code("""
RFC_5737 = {
    ipaddress.ip_network("192.0.2.0/24"): ("TEST-NET-1", "Internal / Campus Network", "Trusted"),
    ipaddress.ip_network("198.51.100.0/24"): ("TEST-NET-2", "External ISP / Remote Student", "Untrusted - Standard"),
    ipaddress.ip_network("203.0.113.0/24"): ("TEST-NET-3", "External Hosting / Anonymized Proxy", "Hostile / Suspect")
}

def classify_ip_network(ip_str):
    ip_obj = ipaddress.ip_address(ip_str.strip())
    for net, (label, zone, trust) in RFC_5737.items():
        if ip_obj in net:
            return pd.Series([label, zone, trust])
    return pd.Series(["OTHER", "Public Internet", "Untrusted"])

df_norm = df_raw.copy()
df_norm['timestamp_dt'] = pd.to_datetime(df_norm['timestamp'])
df_norm = df_norm.sort_values('timestamp_dt').reset_index(drop=True)
df_norm['delta_seconds'] = df_norm['timestamp_dt'].diff().dt.total_seconds().fillna(0).astype(int)

# Enrich IP classification
df_norm[['network_label', 'network_zone', 'trust_level']] = df_norm['source_ip'].apply(classify_ip_network)

# Normalize actions and outcomes
event_map = {
    'password_login': 'AUTHENTICATION',
    'account_lock': 'DEFENSIVE_CONTROL',
    'rate_limit': 'DEFENSIVE_CONTROL',
    'refresh_token': 'SESSION_MANAGEMENT'
}
df_norm['event_category'] = df_norm['event'].map(event_map)
df_norm['result_normalized'] = df_norm['result'].str.upper()
df_norm['device_anomaly'] = df_norm['device'].apply(lambda d: True if d == 'unknown' else False)

print("[+] Normalization Complete. Enriched DataFrame:")
df_norm[['timestamp', 'delta_seconds', 'user_id', 'source_ip', 'network_label', 'event', 'result_normalized', 'device', 'device_anomaly']]
""")

    # Step 3: Statistical Profiling
    md("""
## 3. Exploratory Log Profiling & Cluster Analysis
To identify anomalies, we analyze:
1. Failed vs Successful events per IP.
2. Distinct accounts targeted per IP.
3. Rapid succession time intervals between requests.
""")

    code("""
# Aggregate event metrics by source IP
ip_summary = df_norm.groupby('source_ip').agg(
    total_events=('event', 'count'),
    distinct_users=('user_id', 'nunique'),
    failures=('result_normalized', lambda x: (x == 'FAILURE').sum()),
    successes=('result_normalized', lambda x: (x == 'SUCCESS').sum()),
    blocked=('result_normalized', lambda x: (x == 'BLOCKED').sum()),
    devices=('device', lambda x: list(x.unique()))
).reset_index()

ip_summary
""")

    # Step 4: Detection Rules
    md("""
## 4. Defensible Detection Rules Engine
We define three formal detection rules grounded in **MITRE ATT&CK**:

### Rule 1: Targeted Vertical Brute Force (`T1110.001`)
- **Criteria:** $\ge 3$ failed `password_login` events targeting the same `user_id` within 120 seconds.
- **Intent:** Detects dictionary guessing against an individual victim account.

### Rule 2: Horizontal Password Spraying (`T1110.003`)
- **Criteria:** $\ge 3$ distinct `user_id`s targeted with failed logins from a single `source_ip` within 300 seconds.
- **Intent:** Detects broad credential attacks designed to evade per-account lockouts.

### Rule 3: Unusual Access / Post-Attack Anomaly (`T1078`)
- **Criteria:** Successful login for an account previously targeted during an attack within a 4-hour window, especially from a different network zone.
- **Intent:** Flags potential account takeover or credential compromise.
""")

    code("""
def evaluate_detections(df):
    alerts = []
    
    # Rule 1: Targeted Brute Force
    for uid, group in df[df['result_normalized'] == 'FAILURE'].groupby('user_id'):
        if len(group) >= 3:
            span = (group['timestamp_dt'].max() - group['timestamp_dt'].min()).total_seconds()
            if span <= 120:
                alerts.append({
                    "rule_id": "RULE-01-BRUTE-FORCE",
                    "severity": "HIGH",
                    "mitre": "T1110.001",
                    "target": uid,
                    "ip": group['source_ip'].iloc[0],
                    "attempts": len(group),
                    "span_seconds": span,
                    "summary": f"{len(group)} rapid failed logins on account '{uid}' within {span}s."
                })
                
    # Rule 2: Password Spraying
    for ip, group in df[df['result_normalized'] == 'FAILURE'].groupby('source_ip'):
        distinct_u = group['user_id'].nunique()
        if distinct_u >= 3:
            span = (group['timestamp_dt'].max() - group['timestamp_dt'].min()).total_seconds()
            if span <= 300:
                alerts.append({
                    "rule_id": "RULE-02-PASSWORD-SPRAY",
                    "severity": "CRITICAL",
                    "mitre": "T1110.003",
                    "target": list(group['user_id'].unique()),
                    "ip": ip,
                    "attempts": len(group),
                    "span_seconds": span,
                    "summary": f"IP '{ip}' targeted {distinct_u} distinct accounts within {span}s with 'unknown' device."
                })

    # Rule 3: Unusual Access Post-Spray
    spray_users = set([u for a in alerts if a['rule_id'] == 'RULE-02-PASSWORD-SPRAY' for u in a['target']])
    success_logins = df[(df['event'] == 'password_login') & (df['result_normalized'] == 'SUCCESS')]
    for _, row in success_logins.iterrows():
        if row['user_id'] in spray_users:
            alerts.append({
                "rule_id": "RULE-03-UNUSUAL-ACCESS",
                "severity": "HIGH",
                "mitre": "T1078",
                "target": row['user_id'],
                "ip": row['source_ip'],
                "attempts": 1,
                "span_seconds": "N/A",
                "summary": f"Account '{row['user_id']}' targeted in spray achieved successful login from {row['source_ip']} ({row['device']})."
            })
            
    return pd.DataFrame(alerts)

alerts_df = evaluate_detections(df_norm)
alerts_df
""")

    # Step 5: Timeline
    md("""
## 5. Forensic Incident Timeline: Evidence vs. Assumptions

A critical requirement of professional security investigations is **separating empirical log evidence from analytical assumptions**.

| Category | Definition | Example in this Case |
|:---|:---|:---|
| **Empirical Evidence** | Directly observed, tamper-evident telemetry recorded in log records. | `stu-117` failed 3 logins at 17-second intervals from `198.51.100.27`. |
| **Analytical Assumptions** | Deductions, hypotheses, and threat intelligence inferences requiring further verification. | Attacker script targeted `stu-117`; account lockout prevented further credential guessing. |
""")

    code("""
from timeline_builder import build_forensic_timeline

timeline_data = build_forensic_timeline(df_norm.to_dict('records'))
timeline_df = pd.DataFrame(timeline_data)
timeline_df[['timestamp', 'phase', 'user_id', 'source_ip', 'empirical_evidence', 'analytical_assumptions', 'defensive_outcome']]
""")

    # Step 6: Visualizations
    md("""
## 6. Investigative Visualizations
We generate timeline and distribution charts to visually illustrate the incident phases.
""")

    code("""
# Set temporary matplotlib backend and style
os.environ['MPLCONFIGDIR'] = '/tmp/mpl_cache'
plt.figure(figsize=(10, 4))

colors = {'SUCCESS': '#2ecc71', 'FAILURE': '#e74c3c', 'BLOCKED': '#e67e22'}
plt.scatter(
    df_norm['timestamp_dt'],
    df_norm['user_id'],
    c=df_norm['result_normalized'].map(colors),
    s=150,
    edgecolors='black',
    zorder=5
)

for _, row in df_norm.iterrows():
    plt.annotate(
        f"{row['event']} ({row['result_normalized']})",
        (row['timestamp_dt'], row['user_id']),
        textcoords="offset points",
        xytext=(0, 10),
        ha='center',
        fontsize=8
    )

plt.title("Authentication Activity Timeline & Outcome Distribution", fontsize=12, fontweight='bold')
plt.xlabel("Timestamp (UTC)", fontsize=10)
plt.ylabel("User Account", fontsize=10)
plt.grid(True, linestyle='--', alpha=0.5)
plt.tight_layout()
plt.show()
""")

    # Step 7: Recommendations
    md("""
## 7. Containment Playbook & Logging Recommendations

### 🛑 Immediate Containment Actions:
1. **Revoke Active Sessions:** Invalidate active JWT/session tokens for `stu-311` and force credential rotation pending out-of-band identity verification.
2. **IP Null-Routing / Edge Drop:** Add `203.0.113.42` to boundary WAF / firewall blocklist.
3. **Account Unlocking with Verification:** Unlock `stu-117` only following student password reset via registered secondary email or SMS.

### 🛡️ Improved Logging Controls:
1. **Full User-Agent Telemetry:** Log complete HTTP `User-Agent` strings, TLS cipher suites, and JA3/JA4 fingerprints instead of generic device labels.
2. **Contextual Geolocation & ASN Metadata:** Enrich authentication events with autonomous system number (ASN) and geo-coordinates in real-time.
3. **Correlated Request IDs:** Implement distributed tracing `X-Request-ID` across web proxies, auth services, and database layers to link failed attempts to exact network sessions.
""")

    nb = {
        "cells": cells,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3"
            },
            "language_info": {
                "name": "python",
                "version": "3.11"
            }
        },
        "nbformat": 4,
        "nbformat_minor": 5
    }

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    nb_path = os.path.join(base_dir, "notebooks", "security_investigation.ipynb")
    with open(nb_path, "w", encoding="utf-8") as f:
        json.dump(nb, f, indent=2)

    print(f"[+] Successfully generated Jupyter notebook at: {nb_path}")

if __name__ == "__main__":
    build_notebook()
