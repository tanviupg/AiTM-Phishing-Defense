"""
User-Training & Interactive Phishing-Awareness Quiz Service for Module 4.

Reuses and extends Module 3's `module3_hardening.training_quiz` (LESSONS,
QUIZ_QUESTIONS, evaluate_quiz_submission) and `AuthDefenseKnowledgeBase`
without duplicating or modifying Module 3 files.

Provides:
- 9 comprehensive beginner-friendly cybersecurity awareness lessons covering every
  required AiTM phishing defense topic (with explanations, practical examples,
  warning signs, and prevention techniques).
- 12 multiple-choice quiz questions (8 imported from Module 3 + 4 extended
  Module 4 questions) with immediate per-question feedback, final score,
  percentage, and pass/fail completion certificate status.
"""

import sys
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from module3_hardening.training_quiz import (
        LESSONS as M3_LESSONS,
        QUIZ_QUESTIONS as M3_QUIZ_QUESTIONS,
    )
    M3_TRAINING_AVAILABLE = True
except ImportError:
    M3_TRAINING_AVAILABLE = False
    M3_LESSONS = []
    M3_QUIZ_QUESTIONS = []


def _m3_lesson_summary(lesson_id: str, default: str) -> str:
    for lesson in M3_LESSONS:
        if lesson.get("lesson_id") == lesson_id:
            return str(lesson.get("key_takeaway", default))
    return default


TRAINING_LESSONS: list[dict[str, Any]] = [
    {
        "lesson_id": "TRN-01",
        "order": 1,
        "title": "What is AiTM Phishing?",
        "category": "Fundamentals",
        "duration_min": 4,
        "source_module_ref": "Extends Module 3 LES-01",
        "simple_explanation": (
            "Adversary-in-the-Middle (AiTM) phishing is an advanced type of phishing where "
            "an attacker places a live server between you and the real website you are trying "
            "to sign into. Instead of showing a clumsy fake webpage, the attacker's server "
            "forwards the real Microsoft, Google, or corporate login page to your screen in real time."
        ),
        "practical_example": (
            "You receive an urgent email claiming your payroll document needs review. You click "
            "the link and see a login page that looks 100% identical to your company portal. "
            "Even though the page looks authentic, the web address belongs to an attacker proxy "
            "such as login.microsoftonline.corp-auth-check.invalid."
        ),
        "warning_signs": [
            "Urgent emails pushing you to sign in immediately for payroll, HR, or password expiry.",
            "A domain name that contains familiar brand words (like 'microsoftonline') inside a longer, unfamiliar root domain.",
            "Unexpected login prompts triggered from links inside emails or chat messages instead of bookmarks.",
        ],
        "prevention_techniques": [
            "Access sensitive work portals only through saved bookmarks or your company app launcher.",
            "Always read the root domain (just before the first '/') before entering any credentials.",
            "Enable phishing-resistant passkeys (FIDO2) so passwords cannot be phished.",
        ],
        "module3_takeaway": _m3_lesson_summary(
            "LES-01",
            "A working login screen and valid MFA prompt do not prove you are connected directly to the real site.",
        ),
    },
    {
        "lesson_id": "TRN-02",
        "order": 2,
        "title": "How Reverse-Proxy Phishing Works",
        "category": "Attack Mechanics",
        "duration_min": 5,
        "source_module_ref": "Module 1 Lab Proxy + Module 3 LES-01",
        "simple_explanation": (
            "A reverse proxy acts like a hidden translator sitting in the middle of a conversation. "
            "Your browser talks to the attacker's proxy, and the proxy immediately opens a separate "
            "connection to the genuine Identity Provider (IdP). Every button, logo, and error message "
            "from the real website is passed back to you—and everything you type passes through the attacker."
        ),
        "practical_example": (
            "In our safe lab simulation (Module 1), the lab proxy on port 5002 forwards traffic "
            "to the mock IdP on port 5001, rewriting links and redirect headers on the fly so "
            "the victim stays routed through the proxy during the entire sign-in flow."
        ),
        "warning_signs": [
            "Subtle login delays or flickering redirects while the proxy translates upstream responses.",
            "Address bar showing a different domain from your organization's official SSO portal.",
            "Browser autofill (password manager) refusing to fill in your saved password because the domain does not match.",
        ],
        "prevention_techniques": [
            "Trust your password manager: if it refuses to autofill, STOP and inspect the URL immediately.",
            "Use FIDO2/WebAuthn passkeys, which refuse to sign for reverse-proxy domains.",
            "Deploy multi-signal SOC monitoring (Module 2) to spot abnormal proxy redirect hops.",
        ],
        "module3_takeaway": "Reverse proxies relay real authentication traffic transparently in real time.",
    },
    {
        "lesson_id": "TRN-03",
        "order": 3,
        "title": "How Attackers Attempt Session-Token Theft",
        "category": "Attack Mechanics",
        "duration_min": 5,
        "source_module_ref": "MITRE ATT&CK T1539 / T1550.004",
        "simple_explanation": (
            "Once you finish logging in and approve MFA, the real website hands your browser a "
            "digital 'wristband' called a session cookie or token so you don't have to log in on "
            "every click. Because the AiTM proxy sits in the middle of the HTTP response, it copies "
            "that session token ('Set-Cookie') and reuses it from the attacker's own computer."
        ),
        "practical_example": (
            "Bob signs in through a proxy link and approves his 6-digit code. The real IdP issues "
            "an authenticated session token. Moments later, the attacker replays that synthetic "
            "session from an external Linux host (Scenario SCN-004) without ever needing Bob's password again."
        ),
        "warning_signs": [
            "Account activity notifications from unfamiliar cities, browsers, or operating systems right after you logged in.",
            "Security alerts showing a single session ID appearing from two different IP addresses or devices.",
            "Inbox rules created without your knowledge (common post-compromise automation).",
        ],
        "prevention_techniques": [
            "If you suspect a phishing click, report it immediately so the SOC can revoke active session tokens (Module 3 Containment).",
            "Use cryptographic token binding (OAuth 2.0 DPoP / mTLS) that ties tokens to your device's private key.",
            "Monitor active sessions and sign out unknown devices immediately.",
        ],
        "module3_takeaway": "Revoking stolen session tokens immediately neutralizes attacker replay access.",
    },
    {
        "lesson_id": "TRN-04",
        "order": 4,
        "title": "Why Traditional URL Blocklists Can Fail",
        "category": "Defense Gaps",
        "duration_min": 4,
        "source_module_ref": "Extends Module 3 LES-02",
        "simple_explanation": (
            "URL blocklists work like a 'Most Wanted' poster: security tools only block a website "
            "after researchers discover and report it. Modern AiTM attackers register brand-new "
            "domains minutes before sending phishing emails and even hide their login page from "
            "automated security scanners ('cloaking')."
        ),
        "practical_example": (
            "An attacker buys 'auth-portal-verify.invalid' at 09:00 AM and launches emails at 09:15 AM. "
            "Automated email scanners visiting from known cloud IP ranges are shown a harmless 404 page, "
            "while real employee browsers see the live reverse-proxy login screen."
        ),
        "warning_signs": [
            "Assuming a link is safe just because your email client didn't block it or because it has a green HTTPS padlock.",
            "Newly created lookalike domains using hyphens or extra subdomains.",
            "Links wrapped inside URL shorteners or open-redirect tracking links.",
        ],
        "prevention_techniques": [
            "Never rely solely on the HTTPS lock icon—attackers get free, valid SSL certificates in seconds.",
            "Combine domain vigilance with behavioral detection (redirect chains, TLS telemetry, session tracking).",
            "Rely on cryptographic origin-bound MFA (passkeys) rather than blocklists alone.",
        ],
        "module3_takeaway": _m3_lesson_summary(
            "LES-02",
            "Always verify the address bar domain before typing your password or approving MFA.",
        ),
    },
    {
        "lesson_id": "TRN-05",
        "order": 5,
        "title": "How to Identify Fake Login Pages",
        "category": "Detection & Vigilance",
        "duration_min": 4,
        "source_module_ref": "Module 4 Practical Awareness",
        "simple_explanation": (
            "With AiTM phishing, the page itself looks real because it is copied live from the "
            "legitimate provider! That means checking the logo or spelling on the page is no longer "
            "enough. Instead, you must inspect the browser address bar, TLS certificate details, "
            "and password-manager behavior."
        ),
        "practical_example": (
            "Compare `https://login.microsoftonline.com/common/oauth2` (legitimate root: `microsoftonline.com`) "
            "with `https://login.microsoftonline.com.secure-verify-session.invalid/` (real root: `secure-verify-session.invalid`). "
            "Everything before the first single `/` is the hostname—read from right to left!"
        ),
        "warning_signs": [
            "Lookalike root domains (`micros0ft`, `corp-auth-check.invalid`) or brand names placed as subdomains.",
            "Password manager icon showing zero matching credentials on a familiar-looking sign-in form.",
            "Unexpected cookie prompts or missing corporate single sign-on (SSO) seamless login.",
        ],
        "prevention_techniques": [
            "Read the domain right-to-left starting just before the first `/`.",
            "Use a password manager or browser passkey prompt as an automatic domain verifier.",
            "When in doubt, close the tab and open the portal directly from a trusted bookmark.",
        ],
        "module3_takeaway": "Visual accuracy no longer guarantees authenticity—always verify the root domain.",
    },
    {
        "lesson_id": "TRN-06",
        "order": 6,
        "title": "How to Identify Suspicious Redirects",
        "category": "Detection & Vigilance",
        "duration_min": 4,
        "source_module_ref": "Module 2 Redirect Analyzer",
        "simple_explanation": (
            "Normal logins usually follow a clean, predictable path: App -> Identity Provider -> App. "
            "AiTM proxies often introduce extra hops, cyclic loops (bouncing back and forth through "
            "an unknown relay domain), or noticeably slow transitions as pages are rewritten."
        ),
        "practical_example": (
            "In Scenario SCN-003, authentication hops through `portal.corp.local` -> "
            "`reverse-proxy.attacker-relay.invalid` -> `login.microsoftonline.com` -> `portal.corp.local` "
            "(4 hops with a cyclic loop), triggering Module 2's `SUSPICIOUS_REDIRECT_CYCLE` rule."
        ),
        "warning_signs": [
            "Address bar rapidly flashing through multiple unfamiliar domains before settling on a login form.",
            "Links in emails that go through third-party redirectors to mask the final login host.",
            "Noticeable lag when loading login assets or submitting your username.",
        ],
        "prevention_techniques": [
            "Hover over links before clicking to preview the true destination URL.",
            "Close the window immediately if you observe unexpected intermediate domains during SSO.",
            "SOC teams monitor redirect hop counts (>3) and cyclic patterns via Module 2 telemetry.",
        ],
        "module3_takeaway": "Abnormal multi-hop or cyclic redirects are a primary signal of proxy interception.",
    },
    {
        "lesson_id": "TRN-07",
        "order": 7,
        "title": "Why Traditional MFA May Not Stop Every AiTM Attack",
        "category": "Authentication Security",
        "duration_min": 5,
        "source_module_ref": "Module 3 AuthDefenseKnowledgeBase",
        "simple_explanation": (
            "SMS codes, email one-time links, 6-digit authenticator app codes (TOTP), and simple "
            "'Approve/Deny' push notifications prove that YOU entered a code—but they do NOT check "
            "which website asked for it. Because the AiTM proxy relays the prompt to you live, "
            "your approval is forwarded straight to the real service."
        ),
        "practical_example": (
            "You enter a 6-digit TOTP code into `evil-proxy.invalid`. That code is valid for 30 seconds. "
            "The proxy submits it to `login.microsoftonline.com` in under 1 second, beats the timer, "
            "and walks away with your authenticated session cookie."
        ),
        "warning_signs": [
            "Receiving an MFA push notification or SMS code when you did not just start a sign-in.",
            "Number-matching push prompts where the login location on your phone doesn't match where you are.",
            "Being asked to re-enter an OTP code repeatedly due to 'verification errors'.",
        ],
        "prevention_techniques": [
            "Never approve an MFA prompt you did not initiate—deny it and report it to your SOC.",
            "Upgrade from SMS/TOTP to phishing-resistant FIDO2/WebAuthn passkeys.",
            "Organizations should phase out SMS/Voice OTP for high-value accounts (NIST SP 800-63B).",
        ],
        "module3_takeaway": "Passwords, SMS codes, and TOTP codes are not bound to the browser's genuine URL origin.",
    },
    {
        "lesson_id": "TRN-08",
        "order": 8,
        "title": "How FIDO2 and Passkeys Protect Users",
        "category": "Hardening & Prevention",
        "duration_min": 5,
        "source_module_ref": "Extends Module 3 LES-03 & Origin-Binding",
        "simple_explanation": (
            "FIDO2 hardware security keys and device passkeys (like Windows Hello, Touch ID, or Face ID) "
            "use public-key cryptography instead of typed secrets. Your browser automatically locks the "
            "cryptographic signature to the exact domain (`rpId`) shown in the address bar."
        ),
        "practical_example": (
            "If an AiTM proxy at `evil-login.invalid` asks for your passkey, your browser inspects the "
            "address bar, sees `evil-login.invalid` instead of `login.microsoftonline.com`, and refuses "
            "to sign (`SecurityError`). Even if forced, the signature contains `evil-login.invalid` and "
            "is mathematically rejected by Microsoft."
        ),
        "warning_signs": [
            "A phishing site claiming 'Passkey is temporarily unavailable, please sign in with password + SMS instead' (downgrade trick).",
            "Prompts asking you to export or share security keys—real passkeys never leave your device.",
        ],
        "prevention_techniques": [
            "Register a FIDO2 hardware key or platform passkey as your primary login factor.",
            "Reject unexpected 'downgrade to SMS/password' prompts on unfamiliar domains.",
            "Enforce WebAuthn strict `clientDataJSON.origin` validation on the backend (Module 3).",
        ],
        "module3_takeaway": _m3_lesson_summary(
            "LES-03",
            "FIDO2 passkeys mathematically prevent AiTM phishing by binding authentication to the genuine browser URL origin.",
        ),
    },
    {
        "lesson_id": "TRN-09",
        "order": 9,
        "title": "Best Practices for Account Protection",
        "category": "Best Practices",
        "duration_min": 4,
        "source_module_ref": "Module 3 HardeningChecklist & Containment",
        "simple_explanation": (
            "Strong account defense combines smart daily habits with modern security controls: "
            "using passkeys, trusting password managers, keeping devices managed, and acting fast "
            "if a suspicious click ever happens."
        ),
        "practical_example": (
            "An employee accidentally clicks a suspicious link and enters credentials before realizing "
            "the domain looked wrong. Because they immediately notify the SOC, the analyst revokes the "
            "session in seconds (HTTP 401 blocked in Scenario SCN-005) and resets the account cleanly."
        ),
        "warning_signs": [
            "Hesitating to report a suspicious click out of embarrassment—speed of revocation is critical.",
            "Reusing passwords across personal and corporate accounts.",
            "Leaving old, unused devices or legacy SMS fallback active on critical accounts.",
        ],
        "prevention_techniques": [
            "Enroll in FIDO2/Passkeys and remove weak SMS/Voice MFA fallbacks.",
            "Use a dedicated password manager to catch domain mismatches automatically.",
            "Report suspected phishing immediately so the SOC can revoke active sessions and refresh tokens.",
            "Ensure device compliance (MDM, OS updates) and support token binding (DPoP/CAE) where available.",
        ],
        "module3_takeaway": "Combine phishing-resistant passkeys, domain vigilance, and rapid session revocation.",
    },
]


# Additional Module 4 questions extending Module 3's 8 questions (total = 12 >= 10)
MODULE4_EXTRA_QUESTIONS: list[dict[str, Any]] = [
    {
        "question_id": "Q-09",
        "question": "Why do traditional URL blocklists frequently miss newly launched AiTM phishing campaigns?",
        "options": [
            "URL blocklists only inspect PDF attachments, never web links",
            "Attackers register brand-new domains hours before an attack and use cloaking to hide from security scanners",
            "Web browsers ignore all security blocklists when HTTPS is active",
            "AiTM proxies do not use domain names or IP addresses"
        ],
        "correct_index": 1,
        "explanation": "Zero-day lookalike domains are used before blocklists index them, and advanced AiTM kits serve benign pages to automated crawler IPs while proxying real victims."
    },
    {
        "question_id": "Q-10",
        "question": "When inspecting a login URL like 'https://login.microsoftonline.com.verify-auth.invalid/login', what is the actual root domain serving the page?",
        "options": [
            "microsoftonline.com",
            "login.microsoftonline.com",
            "verify-auth.invalid",
            "oauth2.login"
        ],
        "correct_index": 2,
        "explanation": "You must read the hostname just before the first single '/'. In this example, 'login.microsoftonline.com' is merely a deceptive subdomain of the attacker's root domain 'verify-auth.invalid'."
    },
    {
        "question_id": "Q-11",
        "question": "Which browser behavior is a reliable clue that you may have landed on an AiTM reverse-proxy page?",
        "options": [
            "The company logo is displayed in high resolution",
            "Your password manager refuses to autofill saved credentials because the domain does not match",
            "The website uses HTTPS encryption",
            "The page asks for your username before your password"
        ],
        "correct_index": 1,
        "explanation": "AiTM proxies render genuine logos over HTTPS, so visual appearance isn't enough. However, password managers strictly match the true domain and will not autofill on lookalike proxy domains."
    },
    {
        "question_id": "Q-12",
        "question": "What pattern in authentication telemetry strongly indicates an AiTM reverse-proxy redirect chain?",
        "options": [
            "A single direct hop to the approved corporate Identity Provider",
            "A cyclic multi-hop redirect sequence passing through an unapproved intermediary domain",
            "Using a FIDO2 hardware security key on the official company domain",
            "Signing out cleanly at the end of a workday"
        ],
        "correct_index": 1,
        "explanation": "Legitimate SSO follows a clean canonical path (SP -> IdP -> SP). Cyclic hops (>3 redirects) traversing an unapproved intermediary relay indicate reverse-proxy insertion."
    },
]


def _get_all_questions() -> list[dict[str, Any]]:
    """Combines Module 3's 8 questions with Module 4's 4 extended questions (12 total)."""
    combined: list[dict[str, Any]] = []
    if M3_TRAINING_AVAILABLE and M3_QUIZ_QUESTIONS:
        combined.extend(M3_QUIZ_QUESTIONS)
    combined.extend(MODULE4_EXTRA_QUESTIONS)
    return combined


class TrainingService:
    """Provides lessons, sanitized quiz questions, immediate feedback, and scoring."""

    PASSING_THRESHOLD_PCT = 75.0

    def get_lessons(self) -> list[dict[str, Any]]:
        return TRAINING_LESSONS

    def get_quiz_questions(self) -> list[dict[str, Any]]:
        questions = _get_all_questions()
        return [
            {
                "question_id": q["question_id"],
                "question": q["question"],
                "options": q["options"],
            }
            for q in questions
        ]

    def check_single_question(self, question_id: str, selected_index: int) -> dict[str, Any]:
        """Provides immediate feedback and explanation for one question."""
        questions = _get_all_questions()
        q = next((item for item in questions if item["question_id"] == question_id), None)
        if not q:
            raise ValueError(f"Unknown question_id: {question_id}")

        is_correct = selected_index == q["correct_index"]
        return {
            "question_id": question_id,
            "selected_index": selected_index,
            "correct_index": q["correct_index"],
            "is_correct": is_correct,
            "explanation": q["explanation"],
        }

    def grade_quiz(self, answers: dict[str, int]) -> dict[str, Any]:
        """Grades the full quiz submission and returns score, percentage, and feedback."""
        questions = _get_all_questions()
        total = len(questions)
        correct_count = 0
        feedback: list[dict[str, Any]] = []

        for q in questions:
            qid = q["question_id"]
            chosen = answers.get(qid)
            is_correct = chosen == q["correct_index"]
            if is_correct:
                correct_count += 1
            feedback.append({
                "question_id": qid,
                "question": q["question"],
                "selected_index": chosen,
                "correct_index": q["correct_index"],
                "is_correct": is_correct,
                "explanation": q["explanation"],
            })

        pct = round((correct_count / total) * 100, 1) if total > 0 else 0.0
        passed = pct >= self.PASSING_THRESHOLD_PCT

        return {
            "total_questions": total,
            "correct_answers": correct_count,
            "score_percentage": pct,
            "passing_threshold_pct": self.PASSING_THRESHOLD_PCT,
            "passed": passed,
            "certificate_eligible": passed,
            "feedback": feedback,
            "status_message": (
                "Certification Passed! You demonstrated strong readiness against AiTM phishing and passkey defense."
                if passed
                else "Keep practicing! Review the AiTM reverse-proxy and FIDO2 passkey lessons, then restart the quiz."
            ),
        }
