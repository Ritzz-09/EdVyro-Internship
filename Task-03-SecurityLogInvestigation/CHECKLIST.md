# ✅ Task 03: Passing Checklist & Submission Verification

> **Intern:** RITHISH S P (`@Ritzz-09`)  
> **Repository:** [https://github.com/Ritzz-09/EdVyro-Internship](https://github.com/Ritzz-09/EdVyro-Internship)  
> **Track:** Cyber Security | **Task 03:** Security Log Investigation  

---

## 📋 Required Passing Checklist

- [x] **1. Normalize timestamps, IPs, accounts, actions, and result fields.**
  - **Implementation:** Built [`src/normalizer.py`](./src/normalizer.py).
  - **Artifact:** [`data/normalized_authentication_log.csv`](./data/normalized_authentication_log.csv).
  - **Verification:** Normalized all 12 events to ISO-8601 UTC timestamps, calculated inter-event $\Delta t$ deltas, mapped IP addresses into RFC 5737 documentation networks (`TEST-NET-1`, `TEST-NET-2`, `TEST-NET-3`), categorized action events (`AUTHENTICATION`, `DEFENSIVE_CONTROL`, `SESSION_MANAGEMENT`), standardized result codes (`SUCCESS`, `FAILURE`, `BLOCKED`), and classified device categories.

- [x] **2. Define detection rules for spraying, brute force, and unusual access.**
  - **Implementation:** Built [`src/detection_engine.py`](./src/detection_engine.py).
  - **Rule Specifications:**
    - `RULE-01-BRUTE-FORCE`: Targeted Vertical Brute Force (T1110.001) — Detected 3 rapid failures on `stu-117` in 34 seconds from `198.51.100.27`.
    - `RULE-02-PASSWORD-SPRAY`: Horizontal Password Spraying (T1110.003) — Detected single IP `203.0.113.42` targeting 4 distinct accounts (`stu-209`, `stu-311`, `stu-415`, `stu-502`) in 12 seconds with `unknown` device header.
    - `RULE-03-UNUSUAL-ACCESS`: Post-Attack Unusual Access Anomaly (T1078) — Detected successful authentication on sprayed account `stu-311` from campus network `192.0.2.99` (iOS) 145 minutes post-spray.
  - **SIEM Rules:** Formatted into production-grade Sigma (`rules/sigma_rules.yml`) and Splunk SPL queries (`rules/siem_queries.spl`).

- [x] **3. Create a timeline and separate evidence from assumptions.**
  - **Implementation:** Built [`src/timeline_builder.py`](./src/timeline_builder.py).
  - **Artifact:** [`TIMELINE.md`](./TIMELINE.md) and [`INCIDENT-REPORT.pdf`](./INCIDENT-REPORT.pdf).
  - **Verification:** Reconstructed all 12 events in strict chronological order with dedicated columns distinguishing between **Empirical Log Evidence** (indisputable observed telemetry) and **Analytical Assumptions** (working hypotheses and deductive inferences).

- [x] **4. Put work and a short explanation in one public or view-only link.**
  - **Deliverable Repository:** [https://github.com/Ritzz-09/EdVyro-Internship](https://github.com/Ritzz-09/EdVyro-Internship)
  - **Task Directory:** [`./Task-03-SecurityLogInvestigation/`](./)
  - **Supporting Files Included in Same Repository:**
    - Interactive Jupyter Notebook: [`notebooks/security_investigation.ipynb`](./notebooks/security_investigation.ipynb)
    - Publication-Grade Incident Report: [`INCIDENT-REPORT.pdf`](./INCIDENT-REPORT.pdf)
    - Automated Unit Test Suite: [`tests/test_detection_engine.py`](./tests/test_detection_engine.py)

---

## 🌟 Optional Portfolio Upgrade Checklist

- [x] **Recommend containment and improved logging controls.**
  - **Artifact:** [`HARDENING-AND-CONTAINMENT.md`](./HARDENING-AND-CONTAINMENT.md).
  - **Containment Playbook:** Tactical 3-phase response covering immediate edge IP null-routing (`203.0.113.42`), session token revocation for `stu-311`, and out-of-band identity verification for `stu-117`.
  - **Defensive Architecture:** Multi-tier Dual Token-Bucket rate limiter enforcing IP-to-account velocity limits to stop horizontal spraying before lockout thresholds are reached.
  - **Logging Hardening:** JA3/JA4 TLS fingerprinting to unmask headless scraper bots, real-time GeoIP ASN enrichment, FIDO2/WebAuthn MFA event telemetry, and distributed tracing (`X-Request-ID`).
