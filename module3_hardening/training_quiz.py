"""
User Awareness Training & Interactive Quiz Engine (Screen 08 & Deliverable 6).
Provides structured educational lessons, interactive domain-verification exercises,
and a 8-question certification quiz for employees and security analysts.
"""

from typing import Any


LESSONS: list[dict[str, Any]] = [
    {
        "lesson_id": "LES-01",
        "title": "Understanding Adversary-in-the-Middle (AiTM) Phishing",
        "category": "Attack Mechanics",
        "summary": "How modern reverse proxies bypass passwords, SMS codes, and authenticator push notifications.",
        "content_markdown": """
### What is AiTM Phishing?
In a traditional credential phishing attack, attackers create a static fake page (e.g. `fakemicrosoft.com`) to steal your username and password. However, when companies enable **Multi-Factor Authentication (MFA)**, stolen passwords alone are useless to attackers.

To bypass MFA, attackers created **Adversary-in-the-Middle (AiTM)** phishing (using tools like *Evilginx2* and *Morker*).

#### The Attack Flow:
1. **The Bait**: Victim receives an email directing them to a lookalike domain (e.g., `login.microsoftonline.corp-auth-check.invalid`).
2. **The Relay**: An attacker-controlled **Reverse Proxy** sits between your browser and the genuine Microsoft/Google sign-in servers.
3. **Transparent Proxying**: Every request you make is forwarded to the real identity provider. You see genuine login screens, real branding, and real MFA prompts.
4. **Session Theft**: Once you approve your MFA, the real identity provider issues a **Session Token / Cookie**. The attacker's proxy steals this session token and uses it immediately to access your account without needing your password or MFA ever again.
        """,
        "key_takeaway": "A correct password, successful MFA approval, and a working login do NOT mean your connection is secure if an attacker is proxying your session."
    },
    {
        "lesson_id": "LES-02",
        "title": "Warning Signs & Domain Verification",
        "category": "Detection & Vigilance",
        "summary": "How to inspect the address bar and recognize abnormal authentication redirect behavior.",
        "content_markdown": """
### Why Traditional Phishing Defenses Fail:
- **The HTTPS Green Padlock**: HTTPS only means your connection to the *displayed domain* is encrypted. Attackers obtain legitimate, free SSL certificates (via Let's Encrypt) for their proxy domains.
- **URL Blocklists**: Attackers register brand new domains hours before launching a campaign. Blocklists haven't indexed them yet.
- **Visual Clones**: Because the proxy relays the real login page, visual logos and CSS are 100% authentic.

### What You Must Look For:
1. **The Exact Hostname in the Address Bar**: Check the root domain carefully. 
   - Genuine: `https://login.microsoftonline.com/...`
   - Attacker Proxy: `https://login.microsoftonline.com.secure-verify-session.net/...`
2. **Unexpected Redirect Loops**: Noticeable lag, flashing URL transitions, or landing on an unexpected intermediate page before reaching the dashboard.
3. **Unprompted MFA Prompts**: If you get an authenticator push notification or SMS code when you weren't actively logging in, do NOT approve it.
        """,
        "key_takeaway": "Always verify the address bar domain before typing your password or approving an authenticator prompt."
    },
    {
        "lesson_id": "LES-03",
        "title": "Phishing-Resistant Authentication: Passkeys & FIDO2",
        "category": "Hardening & Prevention",
        "summary": "Why FIDO2/WebAuthn completely neutralizes AiTM reverse proxies.",
        "content_markdown": """
### Why Passkeys (FIDO2 / WebAuthn) Cannot Be Phished:
Unlike passwords or 6-digit OTP codes, FIDO2 passkeys are **cryptographically origin-bound**.

#### How Origin-Binding Stops AiTM:
1. Your browser directly inspects the true destination website's domain (`rpId`).
2. If you are on an attacker's proxy (`evil-login.net`), the browser binds the cryptographic signature to `evil-login.net`.
3. When the attacker's proxy forwards that signature to the genuine identity provider (`login.microsoftonline.com`), the identity provider detects that the origin signature does not match its domain.
4. **The authentication is instantly rejected by cryptographic mathematics!**

#### Emergency Response if You Suspect Compromise:
- Immediately report the email to your SOC using the "Report Phishing" button.
- Have the SOC **revoke all active sessions and refresh tokens** immediately.
- Update credentials and enroll in hardware security keys or passkeys.
        """,
        "key_takeaway": "FIDO2 passkeys mathematically prevent AiTM phishing by binding authentication to the genuine browser URL origin."
    }
]

QUIZ_QUESTIONS: list[dict[str, Any]] = [
    {
        "question_id": "Q-01",
        "question": "In an Adversary-in-the-Middle (AiTM) phishing attack, what is the primary objective of the attacker's reverse proxy?",
        "options": [
            "To permanently disable the victim's internet connection",
            "To relay real authentication traffic and capture a usable post-authentication session token",
            "To crack the victim's password hash using rainbow tables",
            "To send spam emails directly from the user's browser"
        ],
        "correct_index": 1,
        "explanation": "AiTM reverse proxies sit between the victim and legitimate identity provider to intercept and replay the authenticated session cookie/token (MITRE ATT&CK T1539/T1550.004)."
    },
    {
        "question_id": "Q-02",
        "question": "Why does a valid HTTPS certificate (lock icon) NOT protect a user from an AiTM phishing attack?",
        "options": [
            "HTTPS has been deprecated by web browsers",
            "HTTPS only encrypts the traffic between the browser and the displayed domain; attackers can obtain valid certificates for domains they control",
            "Certificates are only used for payment gateways, not authentication",
            "AiTM attacks only work on unencrypted HTTP connections"
        ],
        "correct_index": 1,
        "explanation": "A valid TLS certificate proves encryption to the destination domain, but does not prove that the domain belongs to the legitimate organization. Attackers easily obtain valid TLS certs for lookalike proxy domains."
    },
    {
        "question_id": "Q-03",
        "question": "Why can an attacker bypass conventional MFA (SMS OTP or Mobile App Push) using an AiTM proxy?",
        "options": [
            "The attacker hacks into the cellular carrier's SMS towers",
            "The attacker's reverse proxy relays the OTP prompt to the victim and forwards the victim's valid approval to the real IdP in real-time",
            "Conventional MFA algorithms have a known cryptographic backdoor",
            "Mobile authenticator apps do not work when WiFi is enabled"
        ],
        "correct_index": 1,
        "explanation": "Because the relay is live and transparent, the user receives and approves the genuine MFA prompt. Once the IdP validates it, the proxy captures the resulting session cookie."
    },
    {
        "question_id": "Q-04",
        "question": "Which authentication technology mathematically prevents AiTM credential and session theft?",
        "options": [
            "Longer alphanumeric passwords with special characters",
            "SMS text message verification codes",
            "FIDO2 / WebAuthn Passkeys with cryptographic origin binding",
            "Security questions regarding mother's maiden name"
        ],
        "correct_index": 2,
        "explanation": "FIDO2 / WebAuthn passkeys bind the cryptographic authentication signature to the exact origin (rpId) in the address bar. The attacker's proxy domain causes an origin mismatch, causing the genuine IdP to reject the login."
    },
    {
        "question_id": "Q-05",
        "question": "What is the primary action a SOC analyst must execute immediately upon confirming an AiTM session hijacking alert?",
        "options": [
            "Wait 24 hours to see if more events occur",
            "Immediately revoke the affected user's active session tokens and initiate credential reset",
            "Delete the user's mailbox",
            "Reboot the corporate domain controller"
        ],
        "correct_index": 1,
        "explanation": "Revoking the user's active session tokens immediately invalidates the stolen cookie in the attacker's possession, neutralizing their unauthorized access."
    },
    {
        "question_id": "Q-06",
        "question": "What does Cryptographic Token Protection (such as OAuth 2.0 DPoP or mTLS) do to protect sessions?",
        "options": [
            "Encrypts the user's hard drive",
            "Cryptographically binds the session token to the client's private key, making a stolen token useless on the attacker's machine",
            "Forces users to change passwords every 30 days",
            "Prevents users from opening multiple browser tabs"
        ],
        "correct_index": 1,
        "explanation": "Token binding (Proof of Possession) ensures that even if an attacker steals the session token, they cannot replay it without holding the client's private device key."
    },
    {
        "question_id": "Q-07",
        "question": "In the AiTM Sentinel risk formula R = 30D + 20C + 25S + 15E + 10A, what does the variable 'S' represent?",
        "options": [
            "Server downtime indicator",
            "Session-replay indicator (correlating token reuse from incompatible client/IP contexts)",
            "System RAM memory usage",
            "Spam email volume count"
        ],
        "correct_index": 1,
        "explanation": "S represents the Session-Replay indicator (weight 25), detecting when a synthetic session token is replayed from a divergent context or after revocation."
    },
    {
        "question_id": "Q-08",
        "question": "Why should detection systems avoid relying solely on IP address changes to flag session compromise?",
        "options": [
            "IP addresses are completely static and never change in modern networks",
            "Legitimate factors like corporate VPNs, mobile network handoffs, and CDNs frequently cause legitimate IP address shifts",
            "IP addresses cannot be logged by web servers",
            "Attackers never change their IP address"
        ],
        "correct_index": 1,
        "explanation": "Benign events like switching between WiFi and mobile data or toggling a corporate VPN produce IP shifts. A robust detector correlates IP shifts with redirect chains, TLS anomalies, and token binding to minimize false positives."
    }
]


def evaluate_quiz_submission(answers: dict[str, int]) -> dict[str, Any]:
    """
    Evaluates a user's quiz submission.
    answers: dict mapping question_id -> selected_index (0 to 3)
    Returns score, percentage, detailed question results, and pass/fail certification status.
    """
    total = len(QUIZ_QUESTIONS)
    correct_count = 0
    feedback: list[dict[str, Any]] = []

    for q in QUIZ_QUESTIONS:
        qid = q["question_id"]
        chosen = answers.get(qid)
        is_correct = (chosen == q["correct_index"])
        if is_correct:
            correct_count += 1

        feedback.append({
            "question_id": qid,
            "question": q["question"],
            "selected_index": chosen,
            "correct_index": q["correct_index"],
            "is_correct": is_correct,
            "explanation": q["explanation"]
        })

    pct = round((correct_count / total) * 100, 1)
    passed = pct >= 75.0

    return {
        "total_questions": total,
        "correct_answers": correct_count,
        "score_percentage": pct,
        "passed": passed,
        "certificate_eligible": passed,
        "feedback": feedback,
        "status_message": (
            "Congratulations! You demonstrated strong awareness of AiTM phishing mechanics and FIDO2 defense."
            if passed else
            "Review the lesson materials on reverse proxies and passkey origin binding, then re-take the quiz."
        )
    }
