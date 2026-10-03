# 📊 Task 02: Qualitative Risk Register & Matrix

> **Intern:** Ritzz (`@Ritzz-09`)  
> **Internship Track:** EdVyro Cybersecurity Internship  
> **Application:** SecureAuth (Node.js/Express Defensive Authentication Service)  
> **Framework:** OWASP Risk Rating Methodology & Qualitative Impact Scoring  
> **Format:** Hybrid Risk Governance Narrative & Evaluated Risk Matrix

---

## 1. Intern's Risk Governance Philosophy: Balancing Usability & Defense

In defensive engineering, security cannot exist in a vacuum—controls must be evaluated against operational usability:
- Imposing a 100-character complex password policy frustrates users without guaranteeing security; enforcing an **8-character minimum with salted bcrypt** provides high entropy while remaining usable.
- Setting a rate limit too aggressively (e.g. 1 attempt per minute) locks out legitimate users experiencing typos; a **sliding window of 5 attempts per 15 minutes** accurately isolates automated brute-force scripts while accommodating human error.
- Enforcing `Secure: true` unconditionally breaks local developer testing; implementing **environment-aware dynamic cookie flags** (`process.env.NODE_ENV === 'production'`) secures production without degrading developer velocity.

---

## 2. Risk Evaluation Methodology

Each identified risk scenario is scored based on:
- **Likelihood:** Low (1), Medium (2), High (3)
- **Impact:** Low (1), Medium (2), High (3), Critical (4)
- **Overall Qualitative Score:** `Likelihood × Impact`
  - **Critical (9–12):** Immediate operational vulnerability; requires immediate architectural mitigation.
  - **High (6–8):** Significant potential for privilege compromise or credential exposure.
  - **Medium (3–5):** Moderate operational risk; mitigated by defense-in-depth controls.
  - **Low (1–2):** Minor residual risk or edge-case scenario.

---

## 3. Qualitative Risk Register Matrix

| Risk ID | Threat Scenario | Pre-Mitigation Likelihood | Pre-Mitigation Impact | Inherent Risk | Defensive Mitigation Implemented | Post-Mitigation Rating | Status |
|:---:|:---|:---:|:---:|:---:|:---|:---:|:---:|
| **RR-01** | **Brute-Force & Credential Stuffing** | High (3) | High (3) | **High (9)** | Express-rate-limit throttling to 5 attempts / 15 minutes per IP returning HTTP 429. | Low (2) | ✅ Mitigated |
| **RR-02** | **Session Hijacking via Script Injection** | Medium (2) | Critical (4) | **High (8)** | `HttpOnly: true` prevents DOM cookie access; `SameSite: 'lax'` restricts cross-site dispatch. | Low (2) | ✅ Mitigated |
| **RR-03** | **Credential Storage Exposure** | Low (1) | Critical (4) | **Medium (4)** | Cryptographic salted bcrypt hashing (work factor 10, $2^{10}$ rounds); zero plaintext on disk or memory. | Negligible (1) | ✅ Mitigated |
| **RR-04** | **Targeted User Enumeration** | High (3) | Medium (2) | **Medium (6)** | Generic error message (`"Invalid username or password."`) and constant-time dummy comparisons. | Negligible (1) | ✅ Mitigated |
| **RR-05** | **Session Fixation** | Medium (2) | High (3) | **Medium (6)** | Session ID regenerated (`req.session.regenerate()`) upon valid login. | Negligible (1) | ✅ Mitigated |
| **RR-06** | **Bcrypt Algorithmic DoS** | Medium (2) | High (3) | **Medium (6)** | Strict input validation capping password length at 128 characters prior to hashing. | Negligible (1) | ✅ Mitigated |
| **RR-07** | **Insecure Session Replay Post-Logout** | Medium (2) | High (3) | **Medium (6)** | Explicit server-side session destruction (`req.session.destroy()`) and client cookie clearance. | Negligible (1) | ✅ Mitigated |
| **RR-08** | **Parameter Injection / Malformed JSON** | Medium (2) | Low (1) | **Low (2)** | Strict server-side type and regex validation (`/^[a-zA-Z0-9_]+$/`). | Negligible (1) | ✅ Mitigated |

---

## 4. Residual Risk Analysis

Following the deployment of defensive security controls and automated test validation, all evaluated risks have been driven to **Low** or **Negligible**. Residual risks are confined to multi-server scaling scenarios (which require a distributed Redis session store rather than local in-memory storage) and TLS enforcement in live production environments.
