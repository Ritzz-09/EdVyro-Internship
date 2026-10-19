# 🛡️ Executive Incident Report: Synthetic Authentication Log Investigation

> **Incident Reference:** `SEC-INC-2026-0801`  
> **Date of Incident:** 2026-08-01 (09:00:12Z – 11:47:09Z)  
> **Lead Forensic Analyst:** RITHISH S P (`@Ritzz-09`)  
> **Classification:** TLP:AMBER / Confidential  
> **Overall Risk Level:** 🔴 **HIGH**  
> **Deliverable Format:** Markdown & Publication-Grade PDF ([`INCIDENT-REPORT.pdf`](./INCIDENT-REPORT.pdf))

---

## 1. Executive Summary

During the morning hours of **August 1, 2026**, the Student Information System portal recorded 12 discrete authentication transactions across three documentation subnets (`192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`). Forensic correlation and automated detection analysis uncovered two distinct credential attack vectors and one anomalous post-attack access event:

1. **Targeted Vertical Brute Force (T1110.001):** External host `198.51.100.27` executed three rapid login attempts against account `stu-117` in 34 seconds (09:03:44Z, 09:04:01Z, 09:04:18Z) with exact 17-second cadence. The attack was halted when the portal's account lockout policy locked `stu-117` at 09:05:03Z.
2. **Horizontal Password Spraying (T1110.003):** Hostile proxy host `203.0.113.42` targeted four distinct student accounts (`stu-209`, `stu-311`, `stu-415`, `stu-502`) with failed logins within 12 seconds (09:21:10Z – 09:21:22Z) using an anomalous `unknown` device User-Agent. The source IP was blocked by edge rate limiting at 09:22:01Z.
3. **Post-Spray Access Anomaly (T1078):** At 11:47:09Z, account `stu-311` (targeted during the earlier spray) successfully logged in from internal campus IP `192.0.2.99` on an `iOS` client. While likely a legitimate student on campus Wi-Fi, forensic hygiene requires treating this as a potential credential compromise until verified out-of-band.

Existing perimeter controls mitigated further automated attacks, but horizontal spraying successfully circumvented per-account lockout thresholds, emphasizing the necessity of IP velocity throttling and mandatory MFA.

---

## 2. Scope & Network Baseline Classification

All IP addresses observed belong to **RFC 5737** reserved documentation ranges:

| IP Range | RFC 5737 Tag | Network Zone | Observed IPs | Trust Classification |
|:---|:---|:---|:---|:---:|
| `192.0.2.0/24` | `TEST-NET-1` | Internal Campus Network / Wi-Fi | `192.0.2.18`, `192.0.2.99` | **Trusted Internal** |
| `198.51.100.0/24` | `TEST-NET-2` | External Commercial ISP | `198.51.100.27` | **Untrusted External** |
| `203.0.113.0/24` | `TEST-NET-3` | Anonymized Proxy / Datacenter | `203.0.113.42` | **Hostile / Suspect** |

---

## 3. Comprehensive Incident Chronology (12 Events)

| # | Timestamp (UTC) | User ID | Source IP | Action | Result | Device | Phase & Forensic Description |
|:---:|:---|:---:|:---:|:---:|:---:|:---:|:---|
| **01** | `2026-08-01T09:00:12Z` | `stu-104` | `192.0.2.18` | `password_login` | **SUCCESS** | `android` | **Baseline:** Legitimate student login from campus Wi-Fi. |
| **02** | `2026-08-01T09:03:44Z` | `stu-117` | `198.51.100.27` | `password_login` | **FAILURE** | `windows` | **Attack 1:** 1st failed password attempt against `stu-117`. |
| **03** | `2026-08-01T09:04:01Z` | `stu-117` | `198.51.100.27` | `password_login` | **FAILURE** | `windows` | **Attack 1:** 2nd failed attempt (+17s delta). |
| **04** | `2026-08-01T09:04:18Z` | `stu-117` | `198.51.100.27` | `password_login` | **FAILURE** | `windows` | **Attack 1:** 3rd failed attempt (+17s delta). Threshold reached. |
| **05** | `2026-08-01T09:05:03Z` | `stu-117` | `198.51.100.27` | `account_lock` | **SUCCESS** | `server` | **Mitigation:** Server locks account `stu-117` (+45s later). |
| **06** | `2026-08-01T09:21:10Z` | `stu-209` | `203.0.113.42` | `password_login` | **FAILURE** | `unknown` | **Attack 2:** Spray attempt 1 against `stu-209`. |
| **07** | `2026-08-01T09:21:13Z` | `stu-311` | `203.0.113.42` | `password_login` | **FAILURE** | `unknown` | **Attack 2:** Spray attempt 2 against `stu-311` (+3s delta). |
| **08** | `2026-08-01T09:21:17Z` | `stu-415` | `203.0.113.42` | `password_login` | **FAILURE** | `unknown` | **Attack 2:** Spray attempt 3 against `stu-415` (+4s delta). |
| **09** | `2026-08-01T09:21:22Z` | `stu-502` | `203.0.113.42` | `password_login` | **FAILURE** | `unknown` | **Attack 2:** Spray attempt 4 against `stu-502` (+5s delta). |
| **10** | `2026-08-01T09:22:01Z` | `stu-209` | `203.0.113.42` | `rate_limit` | **BLOCKED** | `server` | **Mitigation:** Server throttles/blocks `203.0.113.42`. |
| **11** | `2026-08-01T10:15:32Z` | `stu-104` | `192.0.2.18` | `refresh_token` | **SUCCESS** | `android` | **Baseline:** Expected OAuth2 token renewal for `stu-104`. |
| **12** | `2026-08-01T11:47:09Z` | `stu-311` | `192.0.2.99` | `password_login` | **SUCCESS** | `ios` | **Anomaly:** Sprayed user `stu-311` logs in from campus iOS device. |

---

## 4. Separation of Evidence vs. Assumptions

| Event Phase | Empirical Log Evidence (Facts) | Analytical Assumptions & Hypotheses |
|:---|:---|:---|
| **Incident 1 (`stu-117`)** | 3 failed logins occurred at 17-second intervals from IP `198.51.100.27` using a `windows` device string, followed by `account_lock`. | Consistent 17-second pacing indicates automated tool or frantic guessing. Lockout mitigated credential breach but created a Denial of Service for `stu-117`. |
| **Incident 2 (Spray)** | Single IP `203.0.113.42` targeted 4 distinct accounts (`stu-209`, `stu-311`, `stu-415`, `stu-502`) in 12 seconds with missing User-Agent (`unknown`). Followed by `rate_limit:blocked`. | High-velocity horizontal spray attempting 1 password per user to evade lockout. `unknown` device proves headless script (curl/requests/hydra). |
| **Incident 3 (`stu-311`)** | Account `stu-311` was targeted in spray at 09:21:13Z. At 11:47:09Z, `stu-311` logged in successfully from campus IP `192.0.2.99` via `ios`. | **Hypothesis 1:** Student arrived on campus and logged in normally.<br>**Hypothesis 2:** Attacker obtained password through alternative vector and authenticated via campus proxy. Out-of-band verification required. |

---

## 5. Defensive Threat Model Evaluation

Structured according to the **EdVyro Defensive Lab Brief** 6-part framework:

### Threat Scenario 1: Vertical Brute Force
1. **Asset & Owner:** Student authentication portal and user credentials (`stu-117`).
2. **Trust Boundary & Entry Point:** Internet boundary (TEST-NET-2) to public login endpoint `/api/v1/auth/login`.
3. **Threat Scenario & Precondition:** External adversary guesses passwords against single victim account. Precondition: Valid username known.
4. **Existing Control & Evidence:** Account lockout after 3 failures (logged `account_lock` at 09:05:03Z).
5. **Risk Rating & Rationale:** **MEDIUM**. Unauthorized access prevented; victim locked out (DoS).
6. **Recommended Mitigation & Verification:** Implement CAPTCHA after 2 failures; replace hard lockout with progressive 5-minute delays.

### Threat Scenario 2: Horizontal Password Spraying
1. **Asset & Owner:** Enterprise directory and student identity store (University IT).
2. **Trust Boundary & Entry Point:** External perimeter from hostile proxy (`203.0.113.42`) to login API.
3. **Threat Scenario & Precondition:** Bot sprays common password across multiple accounts within seconds to evade single-user lockouts.
4. **Existing Control & Evidence:** Edge rate limit triggered at 09:22:01Z (`rate_limit:blocked`).
5. **Risk Rating & Rationale:** **CRITICAL**. Spray attacks exploit weak passwords across wide user populations before thresholds trigger.
6. **Recommended Mitigation & Verification:** Mandatory MFA; IP velocity throttling (< 3 unique users per IP per 5 mins); drop `unknown` User-Agents.

### Threat Scenario 3: Anomalous Access Post-Spray
1. **Asset & Owner:** Academic records, financial details, and portal session of student `stu-311`.
2. **Trust Boundary & Entry Point:** Internal campus network (TEST-NET-1) to web portal.
3. **Threat Scenario & Precondition:** Sprayed account successfully logs in from campus network without MFA challenge.
4. **Existing Control & Evidence:** Standard password verification succeeded (HTTP 200).
5. **Risk Rating & Rationale:** **HIGH**. Dual hypothesis demands investigation to exclude compromise.
6. **Recommended Mitigation & Verification:** Revoke active tokens; contact student out-of-band; correlate campus Wi-Fi DHCP logs.

---

## 6. Containment & Logging Hardening Playbook

### Tactical Response
- **Token Invalidation:** Revoke all JWT/session tokens for `stu-311` pending identity re-verification.
- **Firewall Rule:** Block IP `203.0.113.42` at border firewall for 72 hours.
- **Identity Verification:** Provide out-of-band identity challenge to unlock `stu-117`.

### Telemetry Enhancements
- Capture full HTTP `User-Agent`, JA3/JA4 TLS fingerprints, and TLS cipher suites.
- Ingest real-time ASN and proxy/datacenter flags from threat intelligence feeds.
- Implement distributed trace IDs (`X-Request-ID`) across reverse proxies and auth servers.
