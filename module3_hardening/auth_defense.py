"""
Authentication Defense Knowledge Base (Module 3).
Provides comprehensive technical analyses of authentication mechanisms,
explaining their vulnerabilities to Adversary-in-the-Middle (AiTM) reverse-proxy attacks
and detailing why FIDO2/WebAuthn origin-binding provides mathematical immunity to credential theft.
"""

from typing import Any, Optional
from module3_hardening.models import (
    AuthMethodProfile,
    AuthMethodType,
    AuthResistanceRating,
)


class AuthDefenseKnowledgeBase:
    """
    Authoritative reference repository on authentication security architectures,
    NIST SP 800-63B Authenticator Assurance Levels (AAL), and AiTM proxy resistance.
    """

    def __init__(self) -> None:
        self._profiles: dict[AuthMethodType, AuthMethodProfile] = self._build_profiles()

    def get_profile(self, method_type: AuthMethodType) -> AuthMethodProfile:
        """Retrieve profile for a specific authentication method."""
        return self._profiles[method_type]

    def get_all_profiles(self) -> list[AuthMethodProfile]:
        """Return all authentication method profiles."""
        return list(self._profiles.values())

    def get_phishing_resistant_methods(self) -> list[AuthMethodProfile]:
        """Filter and return only phishing-resistant authentication methods."""
        return [
            p for p in self._profiles.values()
            if p.resistance_rating == AuthResistanceRating.PHISHING_RESISTANT
        ]

    def get_vulnerable_methods(self) -> list[AuthMethodProfile]:
        """Filter and return methods vulnerable to AiTM relay attacks."""
        return [
            p for p in self._profiles.values()
            if p.resistance_rating == AuthResistanceRating.VULNERABLE
        ]

    def explain_origin_binding(self) -> dict[str, Any]:
        """
        Returns a concise, deep technical explanation of why FIDO2 / WebAuthn origin binding
        makes AiTM reverse-proxy attacks mathematically impossible.
        """
        return {
            "title": "Why FIDO2 / WebAuthn Origin Binding Resists AiTM Phishing",
            "executive_summary": (
                "Conventional MFA authenticates the user to whatever server the browser is connected to "
                "(which is the attacker's reverse proxy in an AiTM attack). "
                "In contrast, FIDO2 / WebAuthn cryptographically binds the authentication assertion "
                "to the browser-verified Fully Qualified Domain Name (FQDN) in the address bar. "
                "Because an attacker cannot obtain a trusted TLS certificate for the real domain on their proxy, "
                "the browser sends the attacker's domain in clientDataJSON, causing the genuine IdP to reject "
                "the signature, or causing the browser to abort before the authenticator ever signs."
            ),
            "protocol_breakdown": [
                {
                    "step": 1,
                    "name": "Challenge Initiation",
                    "actor": "Legitimate IdP",
                    "description": (
                        "The Identity Provider (e.g. login.microsoft.com) sends a cryptographic challenge "
                        "and its Relying Party Identifier (rpId: 'login.microsoft.com') over HTTPS."
                    ),
                },
                {
                    "step": 2,
                    "name": "Proxy Relay Attempt",
                    "actor": "AiTM Reverse Proxy",
                    "description": (
                        "The reverse proxy (e.g. at evil-login.com) intercepts the challenge and forwards "
                        "it to the victim user's browser, attempting to solicit a valid signature."
                    ),
                },
                {
                    "step": 3,
                    "name": "Browser Origin Attachment (The Security Invariant)",
                    "actor": "Victim's Web Browser",
                    "description": (
                        "The browser executes navigator.credentials.get(). Crucially, JavaScript cannot forge "
                        "the origin parameter. The browser kernel inspects its own active TLS connection and constructs "
                        "clientDataJSON containing: { 'type': 'webauthn.get', 'challenge': '...', 'origin': 'https://evil-login.com' }."
                    ),
                },
                {
                    "step": 4,
                    "name": "Relying Party ID (rpId) Validation Enforced by Browser",
                    "actor": "Victim's Web Browser Kernel",
                    "description": (
                        "The browser validates that rpId ('login.microsoft.com') is a registrable domain suffix of "
                        "the current origin ('evil-login.com'). Because 'evil-login.com' does not match or terminate in "
                        "'login.microsoft.com', the browser raises a SecurityError and TERMINATES the request immediately. "
                        "The user's security key or biometric sensor is NEVER even touched."
                    ),
                },
                {
                    "step": 5,
                    "name": "IdP Signature Verification (Defense-in-Depth)",
                    "actor": "Legitimate IdP",
                    "description": (
                        "Even if an attacker configured the proxy to advertise rpId='evil-login.com', the authenticator "
                        "signs clientDataJSON with origin='https://evil-login.com'. When the proxy relays this assertion "
                        "to login.microsoft.com, the genuine IdP checks the origin field in clientDataJSON. "
                        "Because 'https://evil-login.com' != 'https://login.microsoft.com', the genuine IdP immediately "
                        "rejects the assertion as invalid."
                    ),
                },
            ],
            "key_takeaway": (
                "Passkeys and FIDO2 eliminate shared secrets (passwords) and relayable tokens (OTPs). "
                "Authentication is tied to public-key cryptography where the private key never leaves the hardware/TPM, "
                "and signatures are mathematically invalid for any domain other than the genuine service."
            ),
        }

    def explain_token_binding(self) -> dict[str, Any]:
        """
        Returns technical explanation of Cryptographic Token Binding (DPoP / mTLS)
        and how it neutralizes stolen session tokens.
        """
        return {
            "title": "Cryptographic Token Binding: Neutralizing Stolen Session Cookies",
            "executive_summary": (
                "AiTM attacks succeed because standard HTTP session cookies and OAuth bearer tokens "
                "are 'bearer' instruments: anyone who presents them (including an attacker who intercepted "
                "them via a reverse proxy) is granted full access. Token Binding converts bearer tokens into "
                "Proof-of-Possession (PoP) tokens, binding them to a client-side private key."
            ),
            "mechanisms": [
                {
                    "standard": "RFC 9449 - OAuth 2.0 Demonstrating Proof-of-Possession (DPoP)",
                    "operation": (
                        "The legitimate browser generates an ephemeral asymmetric key pair in IndexedDB / WebCrypto. "
                        "With every request to the API, the client signs an HTTP-specific JWT (DPoP proof) containing "
                        "the HTTP method, target URI, and current timestamp. The access token is thumbprint-bound to "
                        "the client's public key."
                    ),
                    "aitm_neutralization": (
                        "If an AiTM proxy steals the access token, the attacker cannot replay it from their own machine "
                        "because they lack the client's non-exportable private key required to generate valid DPoP proof headers."
                    ),
                },
                {
                    "standard": "RFC 8705 - Mutual-TLS (mTLS) Client-Certificate-Bound Tokens",
                    "operation": (
                        "The client presents a client TLS certificate during the handshake with the IdP and resource server. "
                        "The issued access token embeds the SHA-256 hash of the client certificate (cnf claim). "
                        "The resource server verifies that the TLS connection client certificate matches the cnf claim."
                    ),
                    "aitm_neutralization": (
                        "The attacker's server connects to the IdP over a separate TLS session with a different or missing "
                        "client certificate, causing the IdP to reject token issuance or the API to reject replayed requests."
                    ),
                },
            ],
        }

    def _build_profiles(self) -> dict[AuthMethodType, AuthMethodProfile]:
        """Constructs canonical authentication profiles."""
        return {
            AuthMethodType.PASSWORD_ONLY: AuthMethodProfile(
                method_type=AuthMethodType.PASSWORD_ONLY,
                display_name="Password Only (Single Factor)",
                resistance_rating=AuthResistanceRating.VULNERABLE,
                nist_aal_level="NIST AAL1",
                mechanism_summary="Shared secret memorized by user and sent in plaintext/hashed form to server.",
                aitm_failure_mechanism=(
                    "Reverse proxy transparently intercepts the HTTP POST request containing credentials, "
                    "logs the username/password in attacker storage, and forwards them to the real service."
                ),
                aitm_resistance_explanation=(
                    "Completely vulnerable. Zero origin binding and zero secondary verification."
                ),
                origin_bound=False,
                requires_user_presence=True,
                requires_user_verification=False,
                recommended_action="DEPRECATE IMMEDIATELY: Enforce multi-factor authentication across all accounts.",
            ),
            AuthMethodType.PASSWORD_SMS_OTP: AuthMethodProfile(
                method_type=AuthMethodType.PASSWORD_SMS_OTP,
                display_name="Password + SMS / Voice OTP",
                resistance_rating=AuthResistanceRating.VULNERABLE,
                nist_aal_level="NIST AAL2 (Restricted)",
                mechanism_summary="Out-of-band 6-digit numeric code transmitted over cellular SS7 network.",
                aitm_failure_mechanism=(
                    "Proxy relays the user's password to the IdP, triggering an SMS code to the user's phone. "
                    "The victim enters the SMS code on the proxy login page. The proxy relays the code to the IdP "
                    "within its 3-5 minute validity window, successfully completing login and intercepting the session token."
                ),
                aitm_resistance_explanation=(
                    "Completely vulnerable to AiTM relay. SMS codes have no cryptographic binding to the genuine domain "
                    "and are easily relayed by automated proxies (Evilginx, Modlishka)."
                ),
                origin_bound=False,
                requires_user_presence=True,
                requires_user_verification=False,
                recommended_action="TRANSITION: Disable SMS/Voice OTP in favor of Authenticator apps or Passkeys.",
            ),
            AuthMethodType.PASSWORD_EMAIL_OTP: AuthMethodProfile(
                method_type=AuthMethodType.PASSWORD_EMAIL_OTP,
                display_name="Password + Email Magic Link / OTP",
                resistance_rating=AuthResistanceRating.VULNERABLE,
                nist_aal_level="NIST AAL2",
                mechanism_summary="Single-use numeric code or hyperlink dispatched to registered email mailbox.",
                aitm_failure_mechanism=(
                    "Like SMS, the proxy requests the code, victim inputs code on proxied page, proxy replays code to IdP. "
                    "Magic links opened in browser can be redirected through proxy or session cookies intercepted."
                ),
                aitm_resistance_explanation=(
                    "Vulnerable. Plain numeric codes lack channel and origin binding."
                ),
                origin_bound=False,
                requires_user_presence=True,
                requires_user_verification=False,
                recommended_action="TRANSITION: Discontinue email OTP for administrative and sensitive identities.",
            ),
            AuthMethodType.PASSWORD_TOTP_APP: AuthMethodProfile(
                method_type=AuthMethodType.PASSWORD_TOTP_APP,
                display_name="Password + Authenticator App (RFC 6238 TOTP)",
                resistance_rating=AuthResistanceRating.VULNERABLE,
                nist_aal_level="NIST AAL2",
                mechanism_summary="Time-based One-Time Password generated via HMAC-SHA1 over shared secret seed (e.g. Google Authenticator).",
                aitm_failure_mechanism=(
                    "Victim opens authenticator app and enters 6-digit code on proxied page. "
                    "The proxy submits the code to the real IdP within the 30-second time window. "
                    "Authentication succeeds and session token is stolen."
                ),
                aitm_resistance_explanation=(
                    "Vulnerable to real-time relay. Although TOTP resists credential stuffing, it cannot detect "
                    "that the recipient of the 6-digit code is an intermediary reverse proxy rather than the real host."
                ),
                origin_bound=False,
                requires_user_presence=True,
                requires_user_verification=False,
                recommended_action="TRANSITION: Upgrade users from standard TOTP to FIDO2 / Passkeys.",
            ),
            AuthMethodType.CONVENTIONAL_PUSH: AuthMethodProfile(
                method_type=AuthMethodType.CONVENTIONAL_PUSH,
                display_name="Password + Mobile Push Notification (Approve/Deny)",
                resistance_rating=AuthResistanceRating.VULNERABLE,
                nist_aal_level="NIST AAL2",
                mechanism_summary="Out-of-band push message sent to registered mobile device prompting single-tap approval.",
                aitm_failure_mechanism=(
                    "Proxy submits username/password to real IdP, triggering push prompt to user's mobile device. "
                    "Victim taps 'Approve' assuming it was triggered by their own login attempt. "
                    "IdP issues session token to proxy, completing the attack."
                ),
                aitm_resistance_explanation=(
                    "Vulnerable to AiTM relay and MFA fatigue / prompt-bombing attacks. "
                    "The approval action is decoupled from the browser session's TLS origin."
                ),
                origin_bound=False,
                requires_user_presence=True,
                requires_user_verification=True,
                recommended_action="UPGRADE: Enforce Number Matching and Geographic Context on push notifications.",
            ),
            AuthMethodType.PUSH_NUMBER_MATCHING: AuthMethodProfile(
                method_type=AuthMethodType.PUSH_NUMBER_MATCHING,
                display_name="Mobile Push with Number Matching & Location Context",
                resistance_rating=AuthResistanceRating.PARTIALLY_RESISTANT,
                nist_aal_level="NIST AAL2",
                mechanism_summary="IdP displays 2-digit number in browser that user must enter into authenticator app.",
                aitm_failure_mechanism=(
                    "The proxy captures the 2-digit number returned by the genuine IdP and renders it on the proxied page. "
                    "The victim sees the number on the fake page and types it into the mobile app, allowing the proxy "
                    "to capture the session. (Mitigates accidental approval, but vulnerable to active proxy relay)."
                ),
                aitm_resistance_explanation=(
                    "Partially resistant: Prevents blind MFA fatigue attacks, but an attentive victim tricked by the proxy "
                    "login UI will still complete the number match."
                ),
                origin_bound=False,
                requires_user_presence=True,
                requires_user_verification=True,
                recommended_action="MAINTAIN AS INTERIM: Use while transitioning workforce to FIDO2 / Passkeys.",
            ),
            AuthMethodType.FIDO2_SECURITY_KEY: AuthMethodProfile(
                method_type=AuthMethodType.FIDO2_SECURITY_KEY,
                display_name="FIDO2 / WebAuthn Hardware Security Key (e.g. YubiKey)",
                resistance_rating=AuthResistanceRating.PHISHING_RESISTANT,
                nist_aal_level="NIST AAL3",
                mechanism_summary="Dedicated hardware cryptographic token communicating via USB, NFC, or BLE (CTAP2/WebAuthn).",
                aitm_failure_mechanism=None,  # Immune to AiTM reverse proxy relay
                aitm_resistance_explanation=(
                    "IMMUNE TO AiTM PHISHING. The browser kernel injects the verified TLS origin (e.g. evil-proxy.com) "
                    "into clientDataJSON and signs it with the key pair registered only for the genuine domain (e.g. login.microsoft.com). "
                    "Signature validation fails at the IdP, or the browser aborts before signing due to rpId mismatch."
                ),
                origin_bound=True,
                requires_user_presence=True,
                requires_user_verification=True,
                recommended_action="TARGET STATE: Deploy for all privileged users, administrators, and high-risk personnel.",
            ),
            AuthMethodType.PASSKEY_DEVICE_BOUND: AuthMethodProfile(
                method_type=AuthMethodType.PASSKEY_DEVICE_BOUND,
                display_name="Device-Bound Passkey (Windows Hello / Touch ID / TPM)",
                resistance_rating=AuthResistanceRating.PHISHING_RESISTANT,
                nist_aal_level="NIST AAL3",
                mechanism_summary="Platform authenticator integrated into OS hardware security module (TPM / Secure Enclave).",
                aitm_failure_mechanism=None,
                aitm_resistance_explanation=(
                    "IMMUNE TO AiTM PHISHING. Cryptographic private keys are non-exportable from device hardware and "
                    "strictly origin-bound via the WebAuthn standard."
                ),
                origin_bound=True,
                requires_user_presence=True,
                requires_user_verification=True,
                recommended_action="TARGET STATE: Enable as primary sign-in mechanism across managed enterprise endpoints.",
            ),
            AuthMethodType.PASSKEY_SYNCED: AuthMethodProfile(
                method_type=AuthMethodType.PASSKEY_SYNCED,
                display_name="Synced Passkey (iCloud Keychain / Google Password Manager)",
                resistance_rating=AuthResistanceRating.PHISHING_RESISTANT,
                nist_aal_level="NIST AAL2 / AAL3",
                mechanism_summary="WebAuthn credential backed by end-to-end encrypted cloud keychain synchronized across user devices.",
                aitm_failure_mechanism=None,
                aitm_resistance_explanation=(
                    "IMMUNE TO AiTM PHISHING. Full WebAuthn origin-binding protection applies regardless of keychain synchronization. "
                    "An attacker proxy cannot solicit or replay the cryptographic assertion."
                ),
                origin_bound=True,
                requires_user_presence=True,
                requires_user_verification=True,
                recommended_action="RECOMMENDED: Excellent balance of phishing resistance and end-user recovery convenience.",
            ),
            AuthMethodType.TOKEN_BINDING_DPOP: AuthMethodProfile(
                method_type=AuthMethodType.TOKEN_BINDING_DPOP,
                display_name="OAuth 2.0 DPoP (Demonstrating Proof-of-Possession, RFC 9449)",
                resistance_rating=AuthResistanceRating.PHISHING_RESISTANT,
                nist_aal_level="AAL3 Token Security",
                mechanism_summary="Application-layer cryptographic binding tying access/refresh tokens to a client-held private key.",
                aitm_failure_mechanism=None,
                aitm_resistance_explanation=(
                    "IMMUNE TO TOKEN THEFT REPLAY. Even if an AiTM proxy steals the access token string from HTTP traffic, "
                    "the attacker cannot use it from their command-and-control server because every API call requires "
                    "a newly signed DPoP proof from the genuine client's non-exportable private key."
                ),
                origin_bound=True,
                requires_user_presence=False,
                requires_user_verification=False,
                recommended_action="STRONGLY RECOMMENDED: Implement on all single-page apps and sensitive API endpoints.",
            ),
            AuthMethodType.CERTIFICATE_BASED_MTLS: AuthMethodProfile(
                method_type=AuthMethodType.CERTIFICATE_BASED_MTLS,
                display_name="Certificate-Based Authentication / Smart Card (PIV / CAC)",
                resistance_rating=AuthResistanceRating.PHISHING_RESISTANT,
                nist_aal_level="NIST AAL3",
                mechanism_summary="X.509 client certificate authentication during TLS handshake backed by smart card or PKI.",
                aitm_failure_mechanism=None,
                aitm_resistance_explanation=(
                    "IMMUNE TO AiTM PHISHING. The TLS handshake requires mutual proof of client private key possession. "
                    "The reverse proxy terminates the user TLS connection and cannot impersonate the client's mTLS certificate "
                    "against the upstream IdP."
                ),
                origin_bound=True,
                requires_user_presence=True,
                requires_user_verification=True,
                recommended_action="ENFORCE: Mandatory for defense, government, and zero-trust high-assurance tiers.",
            ),
        }
