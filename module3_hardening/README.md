# Module 3: FIDO2 / Passkey Defense & Hardening Engine

**Owner:** Vaishnavi  
**Branch:** `vaishnavi/hardening`  
**Role:** Implement defensive recommendations that explain how organizations can eliminate Adversary-in-the-Middle (AiTM) risk using phishing-resistant authentication and security controls.

---

## 1. Executive Summary

Adversary-in-the-Middle (AiTM) phishing attacks place a transparent reverse proxy (such as Evilginx or Modlishka) between the victim and the genuine Identity Provider (IdP). Because traditional authentication credentials—including passwords, SMS OTPs, email magic links, and conventional mobile authenticator push notifications—are not cryptographically bound to the genuine origin, the proxy relays them to the real service in real time, intercepts the resulting authenticated session cookies, and compromises the account.

**Module 3 implements the defense and hardening engine** for the AiTM Phishing Defense platform. It:
1. Evaluates detection verdicts and composite telemetry produced by **Module 2 (Detection Engine)**.
2. Maps risks to a transparent triage hierarchy:
   - `LOW` &rarr; Continue monitoring & maintain baseline telemetry.
   - `MEDIUM` &rarr; Investigate authentication activity, check context drift, and apply conditional step-up MFA.
   - `HIGH` &rarr; Immediately revoke session tokens, force step-up re-authentication using FIDO2/passkeys, and isolate attacker infrastructure.
3. Produces a machine-readable **FIDO2/Passkey Hardening Checklist** aligned with CISA guidelines and NIST SP 800-63B.
4. Provides deep technical breakdowns explaining why **FIDO2 / WebAuthn origin-binding** and **OAuth 2.0 DPoP (RFC 9449) token binding** render AiTM proxy attacks mathematically ineffective.
5. Exposes a clean Python interface and FastAPI REST endpoints ready for consumption by **Module 4 (SOC Dashboard & User Training)**.

---

## 2. Why FIDO2 / Passkeys Defeat AiTM Phishing

Conventional MFA authenticates the user to whatever server the user's browser is currently connected to. If that server is an attacker's reverse proxy, the credentials and one-time codes are delivered directly into the attacker's hands.

### The Origin-Binding Invariant

FIDO2 / WebAuthn completely eliminates shared secrets and relayable codes by leveraging asymmetric public-key cryptography bound to the verified transport layer:

```
+-------------------------------------------------------------------------------+
| Victim User Browser (at https://evil-login.phish.com)                         |
|                                                                               |
| 1. Legitimate IdP issues challenge for rpId: "login.microsoft.com"            |
| 2. AiTM Proxy forwards challenge to user browser                              |
| 3. Browser executes navigator.credentials.get()                               |
| 4. BROWSER KERNEL constructs clientDataJSON:                                  |
|      {                                                                        |
|        "type": "webauthn.get",                                                |
|        "challenge": "dGVzdC1jaGFsbGVuZ2U...",                                 |
|        "origin": "https://evil-login.phish.com"   <-- BROWSER INJECTS THIS    |
|      }                                                                        |
| 5. Browser validates rpId ("login.microsoft.com") against active origin.      |
|    ==> "evil-login.phish.com" != "login.microsoft.com"                        |
|    ==> Browser raises SecurityError and REFUSES to invoke the authenticator!  |
+-------------------------------------------------------------------------------+
```

Even if the proxy tampers with the webpage to set `rpId: "evil-login.phish.com"`, the authenticator signs `origin: "https://evil-login.phish.com"`. When forwarded to the legitimate IdP (`login.microsoft.com`), the IdP validates the signature against its own domain. Because the origins do not match, the authentication is rejected immediately.

### Authentication Method Comparison

| Authentication Factor | NIST SP 800-63B Level | AiTM Resistance | Reason / Failure Mode |
|---|---|---|---|
| **Password Only** | AAL1 | **VULNERABLE** | Plaintext credential intercepted directly by proxy. |
| **Password + SMS / Voice OTP** | AAL2 (Restricted) | **VULNERABLE** | 6-digit code relayed by proxy to IdP within valid window. |
| **Password + Email Link / OTP** | AAL2 | **VULNERABLE** | Intercepted via proxy form or session replay. |
| **Password + Authenticator (TOTP)** | AAL2 | **VULNERABLE** | Time-based code relayed to IdP within 30-second window. |
| **Mobile Push (Approve/Deny)** | AAL2 | **VULNERABLE** | Subject to MFA prompt fatigue; approves relayed proxy session. |
| **Push with Number Matching** | AAL2 | **PARTIALLY RESISTANT** | Mitigates fatigue, but proxy displays 2-digit number to user. |
| **FIDO2 Hardware Key (YubiKey)** | **AAL3** | **PHISHING RESISTANT** | **Immune.** Browser enforces origin-bound `clientDataJSON`. |
| **Platform Passkey (Touch ID/Hello)** | **AAL3** | **PHISHING RESISTANT** | **Immune.** TPM-backed private key + origin binding. |
| **Synced Passkey (iCloud/Google)** | **AAL2 / AAL3** | **PHISHING RESISTANT** | **Immune.** End-to-end encrypted keychain + WebAuthn binding. |
| **OAuth 2.0 DPoP (RFC 9449)** | AAL3 Token Defense | **PHISHING RESISTANT** | **Immune to Replay.** Intercepted token unusable without client key. |

---

## 3. Module 3 Component Architecture

```
module3_hardening/
├── __init__.py                 # Package exports and public interface
├── models.py                   # Data models (RiskLevel, AuthMethodProfile, HardeningPlan, etc.)
├── auth_defense.py             # Technical analysis & origin/token binding knowledge base
├── hardening_checklist.py      # Machine-readable checklist (NIST & CISA aligned)
├── recommendation_engine.py    # Core recommendation engine consuming Module 2 outputs
├── api.py                      # FastAPI REST API & Python helper functions
├── run_defense.py              # End-to-end CLI demonstration runner
├── README.md                   # Complete module documentation
└── tests/
    ├── test_auth_defense.py            # Tests auth method matrix and explanations
    ├── test_hardening_checklist.py     # Tests checklist schema, filtering, and JSON export
    ├── test_recommendation_engine.py   # Tests LOW/MEDIUM/HIGH mapping and signal rules
    └── test_end_to_end_pipeline.py     # Tests Module 1 -> Module 2 -> Module 3 flow
```

---

## 4. Risk-Based Recommendation Hierarchy

The recommendation engine consumes detection results from Module 2 and maps them to clear, standardized operational playbooks:

### 🟢 LOW RISK (Risk Score < 30 / 100)
- **Primary Recommendations:**
  - `Continue monitoring`
  - `Maintain baseline authentication logging`
  - `Ensure standard session timeout policies apply`
- **SOC Action:** Routine logging; no user friction or session disruption.

### 🟡 MEDIUM RISK (30 &le; Risk Score < 50 / 100)
- **Primary Recommendations:**
  - `Investigate authentication activity`
  - `Monitor unusual authentication sessions`
  - `Monitor suspicious redirect behavior`
  - `Evaluate device context and IP transition telemetry`
  - `Prepare conditional step-up challenge for sensitive operations`
- **SOC Action:** Flagged for analyst queue; enforce step-up MFA if accessing sensitive cloud resources.

### 🔴 HIGH RISK (Risk Score &ge; 50 / 100)
- **Primary Recommendations:**
  - `Investigate session`
  - `Re-authenticate user`
  - `Prefer FIDO2/passkey`
  - `Enable FIDO2/passkeys`
  - `Prefer phishing-resistant MFA`
  - `Revoke active session tokens and refresh tokens`
  - `Isolate suspicious session from sensitive services`
- **SOC Action:** Immediate automated session invalidation (`revokeSignInSessions`), force FIDO2/passkey re-authentication, block intermediate proxy domains at SWG/DNS.

---

## 5. Machine-Readable Hardening Checklist

Module 3 includes a structured, machine-readable hardening checklist structured across six architectural categories:

```json
{
  "recommendations": [
    "Enable FIDO2/passkeys",
    "Prefer phishing-resistant MFA",
    "Monitor unusual authentication sessions",
    "Monitor suspicious redirect behavior",
    "Re-authenticate suspicious sessions",
    "Implement cryptographic token binding (DPoP/mTLS)",
    "Enforce strict Relying Party ID origin validation"
  ],
  "checklist": [
    {
      "id": "CHK-IDP-01",
      "category": "IDP_POLICY",
      "title": "Enforce FIDO2 / Passkeys for All Privileged Accounts",
      "priority": "CRITICAL",
      "nist_reference": "NIST SP 800-63B Section 5.1.7 (AAL3 Requirement)",
      "cisa_guidance": "CISA Advisory: Transition to Phishing-Resistant MFA Immediately"
    },
    {
      "id": "CHK-WEBAUTHN-01",
      "category": "WEBAUTHN_CONFIG",
      "title": "Enforce Strict Relying Party ID Origin Verification",
      "priority": "CRITICAL",
      "nist_reference": "W3C WebAuthn Section 7.2"
    },
    {
      "id": "CHK-TOKEN-01",
      "category": "TOKEN_BINDING",
      "title": "Deploy OAuth 2.0 DPoP (Demonstrating Proof-of-Possession)",
      "priority": "CRITICAL",
      "nist_reference": "IETF RFC 9449 OAuth 2.0 DPoP"
    }
  ]
}
```

---

## 6. How to Run and Verify

### Run Module 3 Automated Unit & Integration Tests
```powershell
python -m unittest discover -s module3_hardening/tests -v
```

### Run Full End-to-End Pipeline Demonstration
```powershell
python module3_hardening/run_defense.py
```

### Run Module 3 REST API Server (for Module 4 Dashboard)
```powershell
python module3_hardening/api.py
```
*API interactive documentation will be accessible at: `http://127.0.0.1:8000/docs`*

---

## 7. REST API Endpoints for Module 4 (Dashboard)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/defense/recommendations` | Consumes Module 2 detection JSON and returns complete `HardeningPlan`. |
| `GET` | `/api/defense/recommendations/{tier}` | Quick retrieval of recommendations for `LOW`, `MEDIUM`, or `HIGH`. |
| `GET` | `/api/defense/checklist` | Returns full machine-readable hardening checklist with NIST/CISA links. |
| `GET` | `/api/defense/auth-methods` | Returns comparative matrix of authentication factors. |
| `GET` | `/api/defense/origin-binding` | Returns technical explanation of FIDO2 origin-binding mechanics. |
| `GET` | `/api/defense/token-binding` | Returns technical explanation of DPoP and mTLS token binding. |
| `GET` | `/api/defense/health` | Health check endpoint. |
