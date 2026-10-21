"""
Machine-readable hardening checklist and compliance reference engine (Module 3).
Provides structured, prioritized security controls based on CISA Phishing-Resistant MFA
guidelines and NIST SP 800-63B.
"""

import json
from typing import Any, Optional
from module3_hardening.models import (
    ChecklistCategory,
    ChecklistPriority,
    HardeningChecklistItem,
)


class HardeningChecklist:
    """
    Standardized machine-readable hardening checklist for organizational defense
    against Adversary-in-the-Middle (AiTM) reverse-proxy phishing attacks.
    """

    def __init__(self) -> None:
        self._items: list[HardeningChecklistItem] = self._build_items()

    def get_all_items(self) -> list[HardeningChecklistItem]:
        """Return all checklist items."""
        return list(self._items)

    def get_items_by_priority(self, priority: ChecklistPriority) -> list[HardeningChecklistItem]:
        """Filter checklist items by priority."""
        return [item for item in self._items if item.priority == priority]

    def get_items_by_category(self, category: ChecklistCategory) -> list[HardeningChecklistItem]:
        """Filter checklist items by architectural category."""
        return [item for item in self._items if item.category == category]

    def get_critical_recommendations(self) -> list[str]:
        """Returns standard list of critical recommendations for quick alerts."""
        return [
            item.title for item in self._items
            if item.priority == ChecklistPriority.CRITICAL
        ]

    def get_default_recommendations(self) -> list[str]:
        """
        Returns the core machine-readable recommendations specified in Module 3 requirements.
        """
        return [
            "Enable FIDO2/passkeys",
            "Prefer phishing-resistant MFA",
            "Monitor unusual authentication sessions",
            "Monitor suspicious redirect behavior",
            "Re-authenticate suspicious sessions",
            "Implement cryptographic token binding (DPoP/mTLS)",
            "Enforce strict Relying Party ID origin validation",
        ]

    def to_dict(self) -> dict[str, Any]:
        """Export the entire checklist to a JSON-compatible dictionary."""
        return {
            "version": "1.0.0",
            "standard_references": [
                "CISA: Implementing Phishing-Resistant MFA Fact Sheet",
                "NIST SP 800-63B: Digital Identity Guidelines (Authentication and Lifecycle Management)",
                "W3C Web Authentication (WebAuthn) Level 3 Recommendation",
                "IETF RFC 9449: OAuth 2.0 Demonstrating Proof-of-Possession (DPoP)",
            ],
            "recommendations": self.get_default_recommendations(),
            "checklist": [item.to_dict() for item in self._items],
        }

    def to_json(self, indent: int = 2) -> str:
        """Export checklist as formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def _build_items(self) -> list[HardeningChecklistItem]:
        """Constructs curated hardening items."""
        return [
            HardeningChecklistItem(
                id="CHK-IDP-01",
                category=ChecklistCategory.IDP_POLICY,
                title="Enforce FIDO2 / Passkeys for All Privileged Accounts",
                priority=ChecklistPriority.CRITICAL,
                summary="Require hardware security keys (FIDO2) or platform passkeys for global admins and sensitive roles.",
                implementation_steps=[
                    "Navigate to Identity Provider (Entra ID / Okta / Google Workspace) Authentication Methods.",
                    "Enable FIDO2 Security Key and Passkeys method.",
                    "Create a Conditional Access policy requiring Phishing-Resistant MFA for administrators.",
                    "Phase out password + SMS/TOTP fallback for privileged groups.",
                ],
                verification_method="Verify that sign-in logs for administrator accounts show 'FIDO2' or 'Passkey' authentication method.",
                nist_reference="NIST SP 800-63B Section 5.1.7 (AAL3 Requirement)",
                cisa_guidance="CISA Advisory: Transition to Phishing-Resistant MFA Immediately",
                default_enabled=True,
            ),
            HardeningChecklistItem(
                id="CHK-IDP-02",
                category=ChecklistCategory.IDP_POLICY,
                title="Disable Legacy and Phishable MFA Methods",
                priority=ChecklistPriority.HIGH,
                summary="Deprecate SMS, voice telephony, and email OTP as primary or secondary authentication factors.",
                implementation_steps=[
                    "Review active authentication policies and audit legacy protocol sign-in attempts.",
                    "Disable SMS and Voice OTP in tenant authentication method policies.",
                    "Disable Legacy Authentication (Basic Auth, POP3, IMAP, SMTP AUTH).",
                ],
                verification_method="Audit user authentication methods report to ensure zero accounts rely solely on SMS/Voice.",
                nist_reference="NIST SP 800-63B Section 5.1.3 (Out-of-Band Verifiers Restricted)",
                cisa_guidance="CISA: Eliminating Phishable Factors across Federal & Enterprise Infrastructure",
                default_enabled=True,
            ),
            HardeningChecklistItem(
                id="CHK-WEBAUTHN-01",
                category=ChecklistCategory.WEBAUTHN_CONFIG,
                title="Enforce Strict Relying Party ID Origin Verification",
                priority=ChecklistPriority.CRITICAL,
                summary="Ensure Relying Party backends strictly match clientDataJSON.origin against configured rpId.",
                implementation_steps=[
                    "In WebAuthn verification server, configure exact FQDN allowlist for Relying Party ID.",
                    "Ensure clientDataJSON parser checks origin string byte-for-byte against https://<rpId>.",
                    "Reject any authentication assertion where origin does not match canonical service URL.",
                ],
                verification_method="Run unit and integration tests verifying assertions from proxy subdomains are rejected.",
                nist_reference="W3C WebAuthn Section 7.2 (Verifying an Authentication Assertion)",
                cisa_guidance="CISA Technical Guidelines on FIDO2 Origin-Binding Assurance",
                default_enabled=True,
            ),
            HardeningChecklistItem(
                id="CHK-TOKEN-01",
                category=ChecklistCategory.TOKEN_BINDING,
                title="Deploy OAuth 2.0 DPoP (Demonstrating Proof-of-Possession)",
                priority=ChecklistPriority.CRITICAL,
                summary="Bind session tokens cryptographically to client browser asymmetric key pairs via RFC 9449.",
                implementation_steps=[
                    "Enable DPoP support on authorization server / IdP token endpoint.",
                    "Configure frontend client SDKs to generate ephemeral WebCrypto key pairs.",
                    "Attach signed DPoP proof headers to all API requests.",
                    "Reject any API request where the presented access token does not match the DPoP public key thumbprint.",
                ],
                verification_method="Attempt to replay stolen bearer token without DPoP private key and verify HTTP 401 Unauthorized.",
                nist_reference="IETF RFC 9449 OAuth 2.0 DPoP",
                cisa_guidance="CISA: Cryptographic Proof-of-Possession Defenses Against Token Hijacking",
                default_enabled=False,
            ),
            HardeningChecklistItem(
                id="CHK-TOKEN-02",
                category=ChecklistCategory.TOKEN_BINDING,
                title="Implement Continuous Access Evaluation (CAE) & Short Token Lifetimes",
                priority=ChecklistPriority.HIGH,
                summary="Configure real-time token revocation upon critical security events and shorten token lifespans.",
                implementation_steps=[
                    "Enable Continuous Access Evaluation (CAE / OpenID Shared Signals and Events).",
                    "Set Access Token maximum lifetime to 15-60 minutes.",
                    "Enable refresh token revocation upon password change, account lock, or elevated risk detection.",
                ],
                verification_method="Trigger an elevated risk event and verify existing session tokens are revoked within seconds.",
                nist_reference="NIST SP 800-63B Section 7 (Session Management)",
                cisa_guidance="CISA: Zero Trust Architecture Session Lifetime Recommendations",
                default_enabled=True,
            ),
            HardeningChecklistItem(
                id="CHK-COND-01",
                category=ChecklistCategory.CONDITIONAL_ACCESS,
                title="Enforce Managed Device Compliance and Device Certificate Binding",
                priority=ChecklistPriority.HIGH,
                summary="Require device trust (MDM compliant or Hybrid Azure AD Joined) to satisfy Conditional Access.",
                implementation_steps=[
                    "Deploy enterprise MDM (Intune, Workspace ONE, Jamf) client certificates.",
                    "Require compliant device state in Conditional Access policies for corporate applications.",
                    "Block unmanaged browser logins from accessing internal resources.",
                ],
                verification_method="Attempt login from non-enrolled personal browser and confirm access is denied.",
                nist_reference="NIST SP 800-63B Section 5.1.7",
                cisa_guidance="CISA: Zero Trust Endpoint Security Pillar",
                default_enabled=False,
            ),
            HardeningChecklistItem(
                id="CHK-SOC-01",
                category=ChecklistCategory.MONITORING_SOC,
                title="Monitor Unusual Authentication Sessions & Redirect Anomalies",
                priority=ChecklistPriority.HIGH,
                summary="Ingest authentication telemetry into SIEM/SOC pipeline to detect AiTM proxy signatures.",
                implementation_steps=[
                    "Stream IdP sign-in logs and user-agent metadata into SIEM.",
                    "Configure alert rules for rapid IP alternation (<60s) on identical session IDs.",
                    "Alert on authentication events traversing unauthorized redirect intermediary hosts.",
                    "Integrate automated response playbook to trigger immediate user re-authentication.",
                ],
                verification_method="Simulate Module 1 suspicious event and confirm SOC SIEM receives high-severity alert.",
                nist_reference="NIST SP 800-137 (Information Security Continuous Monitoring)",
                cisa_guidance="CISA Alert: Detecting Adversary-in-the-Middle Activity",
                default_enabled=True,
            ),
            HardeningChecklistItem(
                id="CHK-EDGE-01",
                category=ChecklistCategory.EDGE_TRANSPORT,
                title="Implement HSTS Preloading and DNS CAA Records",
                priority=ChecklistPriority.MEDIUM,
                summary="Enforce strict HTTPS transport across all domains and restrict certificate issuance authorities.",
                implementation_steps=[
                    "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload header.",
                    "Submit domain to browser HSTS Preload list (hstspreload.org).",
                    "Configure DNS CAA (Certification Authority Authorization) records restricting allowed CAs.",
                ],
                verification_method="Inspect domain headers via curl -I to ensure HSTS header is present with max-age >= 1 year.",
                nist_reference="NIST SP 800-52 Rev. 2 (Guidelines for TLS Implementations)",
                cisa_guidance="CISA Binding Operational Directive 18-01",
                default_enabled=True,
            ),
        ]
