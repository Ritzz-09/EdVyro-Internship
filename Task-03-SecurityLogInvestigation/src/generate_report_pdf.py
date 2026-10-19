"""
Publication-Grade Incident Report PDF Generator
Task 03 - EdVyro Cybersecurity Internship

Uses Matplotlib to generate forensic charts and WeasyPrint to compile an
executive Incident Report PDF with complete evidence vs. assumptions separation,
threat model assessment, detection rules, and containment playbooks.
"""

import os
import base64
import json
import csv
from datetime import datetime

# Prevent matplotlib directory permissions issue in restricted environments
os.environ['MPLCONFIGDIR'] = '/tmp/mpl_cache'
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import weasyprint


def generate_charts(records, assets_dir):
    """Generates forensic timeline and event distribution charts."""
    os.makedirs(assets_dir, exist_ok=True)

    # 1. Timeline Chart
    timestamps = [datetime.fromisoformat(r["timestamp_iso"].replace("Z", "+00:00")) for r in records]
    users = [r["user_id"] for r in records]
    results = [r["result_normalized"] for r in records]

    color_map = {
        "SUCCESS": "#10b981",  # Green
        "FAILURE": "#ef4444",  # Red
        "BLOCKED": "#f59e0b"   # Amber
    }
    colors = [color_map.get(res, "#6b7280") for res in results]

    plt.figure(figsize=(10, 4.5), dpi=200)
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')

    for i, (ts, u, res, col) in enumerate(zip(timestamps, users, results, colors)):
        plt.scatter(ts, u, color=col, s=160, zorder=4, edgecolors='#1e293b', linewidths=1.5)
        event_label = records[i]["event_raw"]
        plt.annotate(
            f"{event_label} ({res})",
            (ts, u),
            textcoords="offset points",
            xytext=(0, 10 if i % 2 == 0 else -18),
            ha='center',
            fontsize=8,
            fontweight='bold',
            color='#334155'
        )

    plt.title("Authentication Activity Timeline & Outcome Distribution (2026-08-01)", fontsize=13, fontweight='bold', pad=15)
    plt.xlabel("Time (UTC)", fontsize=10, fontweight='bold')
    plt.ylabel("Target Account (User ID)", fontsize=10, fontweight='bold')
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()

    timeline_img_path = os.path.join(assets_dir, "timeline_chart.png")
    plt.savefig(timeline_img_path, format="png")
    plt.close()

    # 2. Event Distribution Breakdown
    event_counts = {}
    for r in records:
        key = f"{r['event_raw']}:{r['result_normalized']}"
        event_counts[key] = event_counts.get(key, 0) + 1

    labels = list(event_counts.keys())
    counts = [event_counts[k] for k in labels]
    bar_colors = ["#ef4444" if "FAILURE" in l else "#10b981" if "SUCCESS" in l else "#f59e0b" for l in labels]

    plt.figure(figsize=(8, 3.5), dpi=200)
    bars = plt.barh(labels, counts, color=bar_colors, edgecolor='#1e293b', height=0.55)
    plt.title("Authentication Events by Type and Result", fontsize=12, fontweight='bold')
    plt.xlabel("Total Event Count", fontsize=10, fontweight='bold')
    for bar in bars:
        w = bar.get_width()
        plt.text(w + 0.1, bar.get_y() + bar.get_height() / 2, f"{int(w)}", va='center', fontweight='bold', color='#1e293b')
    plt.xlim(0, max(counts) + 1.5)
    plt.grid(axis='x', linestyle='--', alpha=0.6)
    plt.tight_layout()

    dist_img_path = os.path.join(assets_dir, "event_distribution.png")
    plt.savefig(dist_img_path, format="png")
    plt.close()

    return timeline_img_path, dist_img_path


def img_to_base64(path):
    with open(path, "rb") as f:
        return f"data:image/png;base64,{base64.b64encode(f.read()).decode('utf-8')}"


def generate_pdf_report(records, timeline_events, output_pdf_path):
    """Compiles the HTML template and renders the executive PDF using WeasyPrint."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assets_dir = os.path.join(base_dir, "reports", "assets")
    timeline_img, dist_img = generate_charts(records, assets_dir)

    timeline_b64 = img_to_base64(timeline_img)
    dist_b64 = img_to_base64(dist_img)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Incident Report - Security Log Investigation</title>
<style>
    @page {{
        size: A4;
        margin: 1.8cm 1.5cm 2cm 1.5cm;
        @bottom-right {{
            content: "Page " counter(page) " of " counter(pages);
            font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
            font-size: 8pt;
            color: #64748b;
        }}
        @bottom-left {{
            content: "EdVyro Cybersecurity Internship • SEC-INC-2026-0801";
            font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
            font-size: 8pt;
            color: #64748b;
        }}
    }}

    body {{
        font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
        color: #1e293b;
        line-height: 1.45;
        font-size: 9.5pt;
        margin: 0;
        padding: 0;
    }}

    .header-table {{
        width: 100%;
        border-collapse: collapse;
        border-bottom: 3px solid #1e3a8a;
        padding-bottom: 12px;
        margin-bottom: 18px;
    }}
    .header-table td {{
        vertical-align: middle;
    }}
    .org-title {{
        font-size: 18pt;
        font-weight: 800;
        color: #1e3a8a;
        margin: 0;
        letter-spacing: -0.5px;
    }}
    .doc-subtitle {{
        font-size: 11pt;
        font-weight: 600;
        color: #475569;
        margin-top: 4px;
    }}
    .meta-box {{
        background: #f1f5f9;
        border: 1px solid #cbd5e1;
        border-radius: 6px;
        padding: 8px 12px;
        font-size: 8.5pt;
    }}
    .meta-box p {{
        margin: 2px 0;
    }}

    h1, h2, h3, h4 {{
        color: #0f172a;
        font-weight: 700;
        margin-top: 14pt;
        margin-bottom: 6pt;
    }}
    h2 {{
        font-size: 13pt;
        border-bottom: 1.5px solid #e2e8f0;
        padding-bottom: 4px;
        color: #1e3a8a;
    }}
    h3 {{
        font-size: 10.5pt;
        color: #334155;
    }}

    .alert-banner {{
        background-color: #fef2f2;
        border-left: 4px solid #ef4444;
        padding: 8px 12px;
        margin: 12px 0;
        border-radius: 0 4px 4px 0;
    }}
    .alert-banner strong {{
        color: #991b1b;
    }}

    .info-box {{
        background-color: #f8fafc;
        border-left: 4px solid #3b82f6;
        padding: 8px 12px;
        margin: 10px 0;
        border-radius: 0 4px 4px 0;
    }}

    table.data-table {{
        width: 100%;
        border-collapse: collapse;
        margin: 10px 0 16px 0;
        font-size: 8pt;
    }}
    table.data-table th, table.data-table td {{
        border: 1px solid #cbd5e1;
        padding: 5px 7px;
        text-align: left;
    }}
    table.data-table th {{
        background-color: #1e293b;
        color: #ffffff;
        font-weight: 600;
        font-size: 8pt;
    }}
    table.data-table tr:nth-child(even) {{
        background-color: #f8fafc;
    }}

    .badge {{
        display: inline-block;
        padding: 2px 6px;
        border-radius: 3px;
        font-size: 7.5pt;
        font-weight: bold;
        text-transform: uppercase;
    }}
    .badge-success {{ background-color: #d1fae5; color: #065f46; }}
    .badge-failure {{ background-color: #fee2e2; color: #991b1b; }}
    .badge-blocked {{ background-color: #fef3c7; color: #92400e; }}
    .badge-high {{ background-color: #fee2e2; color: #b91c1c; }}
    .badge-crit {{ background-color: #7f1d1d; color: #ffffff; }}

    .page-break {{
        page-break-before: always;
    }}

    .chart-container {{
        text-align: center;
        margin: 14px 0;
    }}
    .chart-img {{
        width: 100%;
        max-width: 680px;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
    }}

    .threat-card {{
        background: #f8fafc;
        border: 1px solid #cbd5e1;
        border-radius: 6px;
        padding: 10px 14px;
        margin-bottom: 12px;
    }}
    .threat-card h4 {{
        margin: 0 0 6px 0;
        color: #1e3a8a;
        font-size: 10pt;
    }}
    .threat-item {{
        margin: 3px 0;
    }}
    .threat-item strong {{
        color: #475569;
    }}
</style>
</head>
<body>

<!-- HEADER -->
<table class="header-table">
    <tr>
        <td style="width: 65%;">
            <div class="org-title">🛡️ INCIDENT INVESTIGATION REPORT</div>
            <div class="doc-subtitle">Synthetic Authentication Log Forensics & Threat Assessment</div>
            <div style="font-size: 8pt; color: #64748b; margin-top: 3px;">
                EdVyro Cybersecurity Internship • Portfolio Task 03
            </div>
        </td>
        <td style="width: 35%;">
            <div class="meta-box">
                <p><strong>Incident Ref:</strong> SEC-INC-2026-0801</p>
                <p><strong>Date of Event:</strong> 2026-08-01</p>
                <p><strong>Analyst:</strong> RITHISH S P (<code>@Ritzz-09</code>)</p>
                <p><strong>Classification:</strong> Confidential / TLP:AMBER</p>
                <p><strong>Overall Severity:</strong> <span class="badge badge-high">HIGH</span></p>
            </div>
        </td>
    </tr>
</table>

<!-- EXECUTIVE SUMMARY -->
<h2>1. Executive Summary</h2>
<p>
Between <strong>09:00:12 UTC</strong> and <strong>11:47:09 UTC on August 1, 2026</strong>, security telemetry on the fictional student portal recorded 12 discrete authentication events spanning three distinct network subnets (RFC 5737 documentation blocks). DFIR analysis revealed two coordinated credential attack patterns and one critical access anomaly:
</p>
<ul>
    <li><strong>Incident Vector 1 (Targeted Brute-Force):</strong> 3 rapid, consecutive failed password logins against student account <code>stu-117</code> within 34 seconds from external IP <code>198.51.100.27</code> (Windows client). The attack was automatically arrested at 09:05:03 UTC by the server-side account lockout policy.</li>
    <li><strong>Incident Vector 2 (Password Spraying):</strong> An automated horizontal credential attack originating from untrusted proxy IP <code>203.0.113.42</code> targeting 4 distinct accounts (<code>stu-209</code>, <code>stu-311</code>, <code>stu-415</code>, <code>stu-502</code>) within 12 seconds with missing/generic User-Agent (<code>unknown</code>). The attack was mitigated at 09:22:01 UTC by the edge rate-limiting daemon.</li>
    <li><strong>Incident Vector 3 (Unusual Access Anomaly):</strong> At 11:47:09 UTC (145 minutes post-spray), sprayed user <code>stu-311</code> authenticated successfully from an internal campus network IP <code>192.0.2.99</code> on an <code>iOS</code> device. While consistent with legitimate student mobility, this warrants out-of-band verification to definitively rule out credential compromise.</li>
</ul>

<div class="alert-banner">
    <strong>Detection Status:</strong> Existing automated controls successfully locked <code>stu-117</code> and throttled <code>203.0.113.42</code>. However, horizontal spraying bypassed per-account lockout thresholds, proving the urgent need for IP-level velocity rules, MFA enforcement, and token invalidation protocols.
</div>

<!-- ENVIRONMENT & SCOPE -->
<h2>2. Scope, Environment & Network Baselines</h2>
<p>
The investigation was conducted under the <strong>EdVyro Defensive Lab</strong> authorization guidelines in an isolated environment. Network sources utilize RFC 5737 reserved documentation ranges:
</p>
<table class="data-table">
    <thead>
        <tr>
            <th>Subnet Range</th>
            <th>RFC 5737 Label</th>
            <th>Environment Role</th>
            <th>Observed IPs</th>
            <th>Assigned Trust Level</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td><code>192.0.2.0/24</code></td>
            <td>TEST-NET-1</td>
            <td>Internal Campus Wi-Fi / Student Dorms</td>
            <td><code>192.0.2.18</code>, <code>192.0.2.99</code></td>
            <td><span class="badge badge-success">Trusted Internal</span></td>
        </tr>
        <tr>
            <td><code>198.51.100.0/24</code></td>
            <td>TEST-NET-2</td>
            <td>External Commercial ISP / Remote Student</td>
            <td><code>198.51.100.27</code></td>
            <td><span class="badge badge-blocked">Untrusted External</span></td>
        </tr>
        <tr>
            <td><code>203.0.113.0/24</code></td>
            <td>TEST-NET-3</td>
            <td>Anonymized Proxy / VPS Hosting</td>
            <td><code>203.0.113.42</code></td>
            <td><span class="badge badge-high">Hostile / Suspect</span></td>
        </tr>
    </tbody>
</table>

<!-- VISUAL FORENSIC ARTIFACTS -->
<div class="page-break"></div>
<h2>3. Visual Forensic Evidence & Cluster Analysis</h2>
<p>The timeline diagram below displays event distribution across time, highlighting failures, defensive enforcements, and baseline logins:</p>

<div class="chart-container">
    <img src="{timeline_b64}" class="chart-img" alt="Timeline Chart">
</div>

<div class="chart-container">
    <img src="{dist_b64}" class="chart-img" alt="Event Distribution Chart" style="max-height: 240px; width: 85%;">
</div>

<!-- STEP BY STEP FORENSIC TIMELINE -->
<div class="page-break"></div>
<h2>4. Forensic Incident Timeline: Evidence vs. Assumptions</h2>
<p>
A core requirement of defensive DFIR investigations is strictly separating <strong>Empirical Log Evidence</strong> (provable facts) from <strong>Analytical Assumptions</strong> (working hypotheses).
</p>

<table class="data-table">
    <thead>
        <tr>
            <th style="width: 13%;">Time (UTC)</th>
            <th style="width: 9%;">User</th>
            <th style="width: 14%;">Source IP</th>
            <th style="width: 14%;">Action & Outcome</th>
            <th style="width: 25%;">Empirical Log Evidence</th>
            <th style="width: 25%;">Analytical Assumptions & Hypotheses</th>
        </tr>
    </thead>
    <tbody>"""

    for item in timeline_events:
        res_badge = "badge-success" if item["result"] == "SUCCESS" else "badge-failure" if item["result"] == "FAILURE" else "badge-blocked"
        html_content += f"""
        <tr>
            <td><code>{item['timestamp'][11:19]}</code></td>
            <td><strong>{item['user_id']}</strong></td>
            <td><code>{item['source_ip']}</code><br><small>{item['network_zone']}</small></td>
            <td>{item['action']}<br><span class="badge {res_badge}">{item['result']}</span></td>
            <td>{item['empirical_evidence']}</td>
            <td><em>{item['analytical_assumptions']}</em></td>
        </tr>"""

    html_content += f"""
    </tbody>
</table>

<!-- THREAT MODEL ASSESSMENT -->
<div class="page-break"></div>
<h2>5. Threat Model Assessment (Defensive Lab Framework)</h2>
<p>Structured in accordance with the required 6-part EdVyro Defensive Incident Template:</p>

<div class="threat-card">
    <h4>Threat Scenario 1: Vertical Brute-Force Password Guessing</h4>
    <div class="threat-item"><strong>1. Asset and Owner:</strong> Student Portal Authentication Service & Account Credentials (Owner: Campus IT & <code>stu-117</code>).</div>
    <div class="threat-item"><strong>2. Trust Boundary & Entry Point:</strong> External perimeter to Authentication API (<code>POST /api/v1/auth/login</code>) via public ISP range <code>198.51.100.0/24</code>.</div>
    <div class="threat-item"><strong>3. Threat Scenario & Precondition:</strong> External actor attempts dictionary password guessing against <code>stu-117</code>. Precondition: Valid username known to attacker.</div>
    <div class="threat-item"><strong>4. Existing Control & Evidence:</strong> Account lockout policy triggered after 3 consecutive failures within 34s (09:03:44Z to 09:04:18Z). Logged <code>account_lock</code> event at 09:05:03Z.</div>
    <div class="threat-item"><strong>5. Risk Rating & Rationale:</strong> <strong>MEDIUM</strong> (Residual). Unauthorized access was blocked; however, lockout induces an unauthenticated Denial of Service (DoS) against legitimate student.</div>
    <div class="threat-item"><strong>6. Recommended Mitigation & Verification:</strong> Replace aggressive immediate lockout with exponential backoff delay (CAPTCHA after 3 failures; temporary 5-minute freeze). Verify via automated replay test.</div>
</div>

<div class="threat-card">
    <h4>Threat Scenario 2: Horizontal Password Spraying from External Proxy</h4>
    <div class="threat-item"><strong>1. Asset and Owner:</strong> Student Portal User Directory & Directory Services (Owner: University Registrar & IT).</div>
    <div class="threat-item"><strong>2. Trust Boundary & Entry Point:</strong> Boundary between untrusted hosting range (<code>203.0.113.0/24</code>) and student login portal.</div>
    <div class="threat-item"><strong>3. Threat Scenario & Precondition:</strong> Automated bot sprays 1 common password across multiple usernames (<code>stu-209</code>, <code>stu-311</code>, <code>stu-415</code>, <code>stu-502</code>) within 12 seconds to circumvent per-user lockout limits. Precondition: User enumeration list acquired by attacker.</div>
    <div class="threat-item"><strong>4. Existing Control & Evidence:</strong> Edge rate limiter blocked subsequent requests from <code>203.0.113.42</code> at 09:22:01Z (<code>rate_limit:blocked</code>).</div>
    <div class="threat-item"><strong>5. Risk Rating & Rationale:</strong> <strong>CRITICAL</strong>. Password spray attacks are notoriously effective against universities with weak default passwords. Rate limit engaged only after 4 accounts were targeted.</div>
    <div class="threat-item"><strong>6. Recommended Mitigation & Verification:</strong> Enforce Mandatory Multi-Factor Authentication (MFA); deploy IP velocity threshold (< 3 distinct failed accounts per 5m = auto-jail); block missing/unknown User-Agents at WAF.</div>
</div>

<div class="threat-card">
    <h4>Threat Scenario 3: Potential Post-Spray Account Takeover (stu-311)</h4>
    <div class="threat-item"><strong>1. Asset and Owner:</strong> Academic records, personal data, and active session of student <code>stu-311</code>.</div>
    <div class="threat-item"><strong>2. Trust Boundary & Entry Point:</strong> Campus Wi-Fi perimeter (<code>192.0.2.0/24</code>) accessing web portal.</div>
    <div class="threat-item"><strong>3. Threat Scenario & Precondition:</strong> Account targeted during 09:21:13Z spray authenticates successfully at 11:47:09Z. Precondition: Either genuine student login OR attacker compromised credentials out-of-band.</div>
    <div class="threat-item"><strong>4. Existing Control & Evidence:</strong> Password auth succeeded (HTTP 200) on iOS device. No step-up MFA challenge was recorded.</div>
    <div class="threat-item"><strong>5. Risk Rating & Rationale:</strong> <strong>HIGH</strong>. Discrepancy between external spray and internal successful login poses dual hypothesis; cannot be dismissed without out-of-band user verification.</div>
    <div class="threat-item"><strong>6. Recommended Mitigation & Verification:</strong> Force session token revocation; contact <code>stu-311</code> to verify iOS login; correlate Wi-Fi MAC address with campus registration.</div>
</div>

<!-- CONTAINMENT & LOGGING CONTROLS -->
<div class="page-break"></div>
<h2>6. Containment Playbook & Logging Hardening (Portfolio Upgrade)</h2>

<h3>🛑 Immediate Tactical Containment</h3>
<ol>
    <li><strong>Temporary Credential Revocation for <code>stu-311</code>:</strong> Trigger immediate session termination across all active JWT/cookies; mandate self-service password reset with SMS/email MFA validation upon next login.</li>
    <li><strong>Edge WAF Null-Routing:</strong> Add <code>203.0.113.42/32</code> to perimeter firewall drop rules for 72 hours.</li>
    <li><strong>Guided Remediation for <code>stu-117</code>:</strong> Assist locked user through out-of-band identity verification to restore access while monitoring for secondary brute-force vectors.</li>
</ol>

<h3>🏗️ Strategic Logging & Telemetry Improvements</h3>
<table class="data-table">
    <thead>
        <tr>
            <th>Telemetry Gap</th>
            <th>Observed Vulnerability</th>
            <th>Required Control Improvement</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td><strong>Device Header Blindspot</strong></td>
            <td>Device logged as <code>unknown</code> without granular telemetry.</td>
            <td>Log complete RFC 7231 <code>User-Agent</code> strings, client TLS cipher suites, and JA3/JA4 cryptographic fingerprints to unmask headless bots.</td>
        </tr>
        <tr>
            <td><strong>Missing Geolocation & ASN</strong></td>
            <td>IPs logged without autonomous system context.</td>
            <td>Enrich authentication logs in real-time with MaxMind GeoIP2 ASN, VPN/Tor proxy classification flags, and datacenter IP tags.</td>
        </tr>
        <tr>
            <td><strong>Absence of MFA Telemetry</strong></td>
            <td>No second-factor prompt records present.</td>
            <td>Implement FIDO2 / WebAuthn MFA; log discrete MFA prompt, method (push, TOTP, hardware key), and verification latency.</td>
        </tr>
        <tr>
            <td><strong>Distributed Tracing</strong></td>
            <td>Individual log records lack common request IDs.</td>
            <td>Inject unique <code>X-Request-ID</code> / W3C Trace Context across edge reverse proxies, auth microservices, and database query layers.</td>
        </tr>
    </tbody>
</table>

<!-- SIGN-OFF -->
<div style="margin-top: 35px; border-top: 1.5px solid #cbd5e1; padding-top: 10px;">
    <table style="width: 100%;">
        <tr>
            <td style="width: 50%;">
                <p><strong>Lead Forensic Investigator:</strong></p>
                <p style="font-size: 11pt; font-weight: bold; color: #1e3a8a;">RITHISH S P</p>
                <p style="font-size: 8pt; color: #64748b;">Cybersecurity Engineering Intern • EdVyro</p>
            </td>
            <td style="width: 50%; text-align: right;">
                <p><strong>Incident Investigation Status:</strong></p>
                <p style="font-size: 10pt; font-weight: bold; color: #065f46;">CLOSED / CONTAINMENT COMPLETED</p>
                <p style="font-size: 8pt; color: #64748b;">Signature: <em>RithishSP_DFIR_Verified</em></p>
            </td>
        </tr>
    </table>
</div>

</body>
</html>
"""

    weasyprint.HTML(string=html_content).write_pdf(output_pdf_path)
    print(f"[+] Publication-grade Incident Report PDF successfully generated at: {output_pdf_path}")


if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    from normalizer import normalize_log_file
    from timeline_builder import build_forensic_timeline

    csv_path = os.path.join(base_dir, "data", "raw_authentication_log.csv")
    records = normalize_log_file(csv_path)
    timeline_events = build_forensic_timeline(records)

    # Output to both reports/INCIDENT-REPORT.pdf and root Task-03 folder
    out_pdf_1 = os.path.join(base_dir, "reports", "INCIDENT-REPORT.pdf")
    out_pdf_2 = os.path.join(base_dir, "INCIDENT-REPORT.pdf")

    generate_pdf_report(records, timeline_events, out_pdf_1)
    generate_pdf_report(records, timeline_events, out_pdf_2)
