"""
Security Log Investigation - SOC Investigation Dashboard & Lab Instance
Task 03 - EdVyro Cybersecurity Internship
Author: RITHISH S P (@Ritzz-09)
"""

import os
import sys
from flask import Flask, render_template, jsonify, send_file, request

# Add src/ to path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "src"))

from normalizer import normalize_log_file
from detection_engine import DetectionEngine
from timeline_builder import build_forensic_timeline

app = Flask(__name__)

# State for containment simulation
CONTAINMENT_ACTIONS = []
BLOCKED_IPS = set()
LOCKED_ACCOUNTS = {"stu-117"}
REVOKED_USERS = set()

def load_data():
    csv_path = os.path.join(BASE_DIR, "data", "raw_authentication_log.csv")
    normalized_records = normalize_log_file(csv_path)
    engine = DetectionEngine()
    alerts = engine.run_all_detections(normalized_records)
    timeline = build_forensic_timeline(normalized_records)
    return normalized_records, [a.to_dict() for a in alerts], timeline

@app.route("/")
def index():
    records, alerts, timeline = load_data()
    return render_template(
        "index.html",
        records=records,
        alerts=alerts,
        timeline=timeline,
        blocked_ips=list(BLOCKED_IPS),
        locked_accounts=list(LOCKED_ACCOUNTS),
        revoked_users=list(REVOKED_USERS),
        containment_log=CONTAINMENT_ACTIONS
    )

@app.route("/api/health")
def api_health():
    return jsonify({
        "status": "online",
        "service": "Task 03 - Security Log Investigation Lab",
        "intern": "RITHISH S P (@Ritzz-09)",
        "track": "Cyber Security"
    })

@app.route("/api/logs")
def api_logs():
    records, _, _ = load_data()
    return jsonify(records)

@app.route("/api/alerts")
def api_alerts():
    _, alerts, _ = load_data()
    return jsonify(alerts)

@app.route("/api/timeline")
def api_timeline():
    _, _, timeline = load_data()
    return jsonify(timeline)

@app.route("/api/containment/<action>", methods=["POST"])
def api_containment(action):
    data = request.get_json() or {}
    target = data.get("target", "")

    if action == "block_ip":
        ip = target or "203.0.113.42"
        BLOCKED_IPS.add(ip)
        msg = f"Null-routed hostile IP {ip} at edge perimeter WAF."
        CONTAINMENT_ACTIONS.insert(0, {"action": "BLOCK_IP", "target": ip, "message": msg, "time": "Just now"})
        return jsonify({"success": True, "message": msg, "blocked_ips": list(BLOCKED_IPS)})

    elif action == "revoke_session":
        user = target or "stu-311"
        REVOKED_USERS.add(user)
        msg = f"Revoked active JWT & refresh tokens for account {user}."
        CONTAINMENT_ACTIONS.insert(0, {"action": "REVOKE_SESSION", "target": user, "message": msg, "time": "Just now"})
        return jsonify({"success": True, "message": msg, "revoked_users": list(REVOKED_USERS)})

    elif action == "unlock_account":
        user = target or "stu-117"
        if user in LOCKED_ACCOUNTS:
            LOCKED_ACCOUNTS.remove(user)
        msg = f"Unlocked account {user} following out-of-band identity challenge."
        CONTAINMENT_ACTIONS.insert(0, {"action": "UNLOCK_ACCOUNT", "target": user, "message": msg, "time": "Just now"})
        return jsonify({"success": True, "message": msg, "locked_accounts": list(LOCKED_ACCOUNTS)})

    return jsonify({"success": False, "error": "Unknown containment action"}), 400

@app.route("/download/report")
def download_report():
    pdf_path = os.path.join(BASE_DIR, "INCIDENT-REPORT.pdf")
    if os.path.exists(pdf_path):
        return send_file(pdf_path, as_attachment=False, mimetype="application/pdf")
    return "Report PDF not found. Run generate_report_pdf.py first.", 404

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print("==================================================================")
    print(" 🛡️  TASK 03 - SECURITY LOG INVESTIGATION SOC CONSOLE")
    print(f" Strict Localhost Binding: http://127.0.0.1:{port}")
    print(" Authorized Laboratory Environment - EdVyro Cybersecurity Internship")
    print("==================================================================")
    app.run(host="127.0.0.1", port=port, debug=False)
