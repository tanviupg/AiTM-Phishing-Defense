"""
Risk-Based Defensive Recommendation Engine (Module 3).
Consumes detection verdicts and signals from Module 2 (Multi-Signal AiTM Detection Engine)
and generates prioritized, actionable defensive recommendations, SOC incident response playbooks,
and FIDO2/Passkey hardening strategies.
"""

from typing import Any, Optional, Union
from module3_hardening.models import (
    RiskLevel,
    ChecklistPriority,
    DefenseRecommendation,
    HardeningChecklistItem,
    HardeningPlan,
)
from module3_hardening.auth_defense import AuthDefenseKnowledgeBase
from module3_hardening.hardening_checklist import HardeningChecklist


class HardeningEngine:
    """
    Evaluates detection signals from Module 2 and produces targeted defensive recommendations.
    Supports both legacy dictionary event summaries and composite detection result objects.
    """

    def __init__(
        self,
        checklist: Optional[HardeningChecklist] = None,
        knowledge_base: Optional[AuthDefenseKnowledgeBase] = None,
    ) -> None:
        self.checklist = checklist or HardeningChecklist()
        self.kb = knowledge_base or AuthDefenseKnowledgeBase()

    def evaluate_detection(
        self,
        detection_input: Union[dict[str, Any], Any],
        override_session_id: Optional[str] = None,
    ) -> HardeningPlan:
        """
        Primary engine interface. Consumes detection output from Module 2 and returns a HardeningPlan.

        Accepts:
        - Module 2 CompositeDetectionResult dict (with 'composite_risk_score', 'composite_verdict', 'all_triggered_indicators')
        - Module 2 DetectionResult dict (with 'risk_score', 'verdict', 'triggered_rules')
        - Standard problem-statement dictionary:
          {
            "session_id": "LAB-001",
            "risk_score": 85,
            "risk_level": "HIGH",
            "signals": { "tls_anomaly": True, "redirect_anomaly": True, "replay_indicator": False }
          }
        """
        parsed = self._normalize_detection_input(detection_input, override_session_id)
        session_id = parsed["session_id"]
        risk_level = parsed["risk_level"]
        risk_score = parsed["risk_score"]
        risk_score_percent = parsed["risk_score_percent"]
        signals = parsed["signals"]
        indicators = parsed["indicators"]

        # 1. Generate Primary Human-Readable Recommendations according to risk tier
        primary_recommendations = self._generate_primary_recommendations(risk_level)

        # 2. Build Structured Detailed Action Items
        detailed_actions = self._build_detailed_actions(session_id, risk_level, risk_score_percent)

        # 3. Build Signal-Specific Targeted Remediations
        signal_remediations = self._build_signal_remediations(signals, indicators)

        # 4. Extract Relevant Checklist Highlights
        checklist_highlights = self._select_checklist_highlights(risk_level, signals, indicators)

        # 5. Phishing-Resistant Authentication Strategy Brief
        strategy = self._build_phishing_resistant_strategy(risk_level)

        # 6. Construct Summary Banner
        summary_banner = self._build_summary_banner(session_id, risk_level, risk_score_percent, signals)

        return HardeningPlan(
            session_id=session_id,
            input_risk_level=risk_level,
            input_risk_score=risk_score,
            risk_score_percent=risk_score_percent,
            primary_recommendations=primary_recommendations,
            detailed_actions=detailed_actions,
            signal_specific_remediations=signal_remediations,
            checklist_highlights=checklist_highlights,
            phishing_resistant_strategy=strategy,
            summary_banner=summary_banner,
        )

    def evaluate_risk_level(self, risk_level_str: str, session_id: str = "MANUAL-EVAL") -> HardeningPlan:
        """Convenience method to evaluate by risk level string directly ('LOW', 'MEDIUM', 'HIGH')."""
        norm = risk_level_str.strip().upper()
        if norm == "HIGH":
            score = 0.85
        elif norm == "MEDIUM":
            score = 0.40
        else:
            score = 0.10
        return self.evaluate_detection({
            "session_id": session_id,
            "risk_level": norm,
            "risk_score": score,
            "signals": {},
        })

    def _normalize_detection_input(
        self,
        detection_input: Union[dict[str, Any], Any],
        override_session_id: Optional[str],
    ) -> dict[str, Any]:
        """Normalizes heterogeneous input formats into a standardized evaluation context."""
        if not isinstance(detection_input, dict):
            # Attempt to convert dataclass or object
            if hasattr(detection_input, "__dict__"):
                detection_input = detection_input.__dict__
            else:
                raise ValueError("detection_input must be a dictionary or dataclass")

        session_id = (
            override_session_id
            or detection_input.get("session_id")
            or "UNKNOWN-SESSION"
        )

        # Extract score
        raw_score = 0.0
        if "composite_risk_score" in detection_input:
            raw_score = float(detection_input["composite_risk_score"])
        elif "risk_score" in detection_input:
            raw_score = float(detection_input["risk_score"])
        elif "score" in detection_input:
            raw_score = float(detection_input["score"])

        # Determine normalized float [0.0, 1.0] and percent [0, 100]
        if raw_score > 1.0:
            # Supplied as 0-100 percentage
            risk_score_percent = int(round(raw_score))
            risk_score = round(raw_score / 100.0, 2)
        else:
            # Supplied as 0.0-1.0 float
            risk_score = round(raw_score, 2)
            risk_score_percent = int(round(raw_score * 100))

        # Extract risk level or infer from score / verdict
        explicit_level = detection_input.get("risk_level")
        verdict = (
            detection_input.get("composite_verdict")
            or detection_input.get("verdict")
            or ""
        ).lower()

        if explicit_level and isinstance(explicit_level, str):
            norm_level = explicit_level.strip().upper()
            if norm_level in ("LOW", "MEDIUM", "HIGH"):
                risk_level = RiskLevel(norm_level)
            elif norm_level == "SUSPICIOUS":
                risk_level = RiskLevel.HIGH
            elif norm_level == "BENIGN":
                risk_level = RiskLevel.LOW
            else:
                risk_level = self._infer_risk_level(risk_score, verdict)
        else:
            risk_level = self._infer_risk_level(risk_score, verdict)

        # Extract signals dictionary and raw indicators
        signals: dict[str, bool] = {}
        if isinstance(detection_input.get("signals"), dict):
            signals = {str(k): bool(v) for k, v in detection_input["signals"].items()}

        indicators: list[str] = []
        if isinstance(detection_input.get("all_triggered_indicators"), list):
            indicators = [str(i) for i in detection_input["all_triggered_indicators"]]
        elif isinstance(detection_input.get("triggered_rules"), list):
            indicators = [str(i) for i in detection_input["triggered_rules"]]

        # Infer signals from indicators if not explicitly provided
        if "tls_anomaly" not in signals:
            tls_anomaly_indicators = {
                "tls:CERT_HOSTNAME_MISMATCH",
                "tls:SNI_HOST_MISMATCH",
                "tls:CERT_EXPIRED",
                "tls:CERT_NOT_YET_VALID",
                "tls:UNTRUSTED_SELF_SIGNED_CERT",
                "tls:UNTRUSTED_AUTH_HOST",
                "tls:LEGACY_TLS_ANOMALY_FLAG",
                "base:TLS_ANOMALY",
            }
            signals["tls_anomaly"] = bool(
                tls_anomaly_indicators.intersection(indicators)
                or detection_input.get("tls_anomaly")
                or (isinstance(detection_input.get("tls_analysis"), dict) and detection_input["tls_analysis"].get("is_anomaly"))
            )

        if "redirect_anomaly" not in signals:
            redirect_anomaly_indicators = {
                "base:SUSPICIOUS_REDIRECT_CYCLE",
                "base:REPEATED_REDIRECT_HOST",
                "base:EXCESSIVE_REDIRECT_COUNT",
                "base:ELEVATED_REDIRECT_COUNT",
                "base:HIGH_TRANSITION_COMPLEXITY",
                "base:REDIRECT_TELEMETRY_DIVERGENCE",
            }
            signals["redirect_anomaly"] = bool(
                redirect_anomaly_indicators.intersection(indicators)
                or (detection_input.get("redirect_count", 0) > 3)
            )

        if "replay_indicator" not in signals:
            replay_anomaly_indicators = {
                "session:CONCURRENT_SESSION_BIFURCATION",
                "session:CLIENT_PLATFORM_DIVERGENCE",
                "session:DATACENTER_SOURCE_TRANSITION",
                "session:SUSPICIOUS_CONTEXT_MISMATCH",
                "session:DEVICE_CONTEXT_CHANGED",
                "session:RAPID_SOURCE_IP_CHANGE",
                "session:TOKEN_BINDING_FAILURE",
            }
            signals["replay_indicator"] = bool(
                replay_anomaly_indicators.intersection(indicators)
                or detection_input.get("replay_indicator")
                or (isinstance(detection_input.get("session_correlation"), dict) and detection_input["session_correlation"].get("is_correlated"))
            )

        return {
            "session_id": session_id,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "risk_score_percent": risk_score_percent,
            "signals": signals,
            "indicators": indicators,
        }

    @staticmethod
    def _infer_risk_level(score: float, verdict: str) -> RiskLevel:
        """Infers RiskLevel from numeric score and verdict strings."""
        if verdict == "suspicious" or score >= 0.50:
            return RiskLevel.HIGH
        elif score >= 0.30:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def _generate_primary_recommendations(self, risk_level: RiskLevel) -> list[str]:
        """
        Generates the core machine-readable list of recommendations
        specifically mapped to the prompt specification:
        LOW -> Continue monitoring
        MEDIUM -> Investigate authentication activity
        HIGH -> Investigate session, Re-authenticate user, Prefer FIDO2/passkey
        """
        if risk_level == RiskLevel.LOW:
            return [
                "Continue monitoring",
                "Maintain baseline authentication logging",
                "Ensure standard session timeout policies apply",
            ]
        elif risk_level == RiskLevel.MEDIUM:
            return [
                "Investigate authentication activity",
                "Monitor unusual authentication sessions",
                "Monitor suspicious redirect behavior",
                "Evaluate device context and IP transition telemetry",
                "Prepare conditional step-up challenge for sensitive operations",
            ]
        else:  # HIGH
            return [
                "Investigate session",
                "Re-authenticate user",
                "Prefer FIDO2/passkey",
                "Enable FIDO2/passkeys",
                "Prefer phishing-resistant MFA",
                "Revoke active session tokens and refresh tokens",
                "Isolate suspicious session from sensitive services",
            ]

    def _build_detailed_actions(
        self,
        session_id: str,
        risk_level: RiskLevel,
        score_percent: int,
    ) -> list[DefenseRecommendation]:
        """Builds structured, prioritized SOC actions."""
        actions: list[DefenseRecommendation] = []

        if risk_level == RiskLevel.HIGH:
            actions.append(
                DefenseRecommendation(
                    action_id=f"ACT-{session_id}-01",
                    risk_level=RiskLevel.HIGH,
                    title="Immediate Session Invalidation & Token Revocation",
                    action="Invoke IdP session termination API (e.g. revokeSignInSessions) to immediately destroy issued session cookies and OAuth refresh tokens.",
                    rationale="In an AiTM attack, session cookies have likely been captured by the reverse proxy. Immediate token invalidation closes the window of attacker reuse.",
                    urgency="IMMEDIATE",
                    operator_guidance="Verify in the IdP admin center that all active tokens for this user identity are revoked and session caches cleared.",
                    automated_remediation_suggested=True,
                )
            )
            actions.append(
                DefenseRecommendation(
                    action_id=f"ACT-{session_id}-02",
                    risk_level=RiskLevel.HIGH,
                    title="Enforce Phishing-Resistant Step-Up Re-Authentication",
                    action="Require the affected user to re-authenticate strictly using a FIDO2 hardware key or platform passkey (Windows Hello / Touch ID).",
                    rationale="Conventional passwords and SMS/TOTP codes will be relayed again if the user remains on the phishing proxy. Only FIDO2 origin-binding breaks the attack cycle.",
                    urgency="IMMEDIATE",
                    operator_guidance="Do not allow SMS, email, or standard mobile push fallback during this re-authentication challenge.",
                    automated_remediation_suggested=True,
                )
            )
            actions.append(
                DefenseRecommendation(
                    action_id=f"ACT-{session_id}-03",
                    risk_level=RiskLevel.HIGH,
                    title="Perimeter Domain & IP Threat Containment",
                    action="Extract intermediate hostnames from the redirect chain and block them across the secure web gateway (SWG), perimeter firewall, and DNS sinkhole.",
                    rationale="Prevents other organizational users from reaching the same AiTM reverse-proxy infrastructure.",
                    urgency="WITHIN_1_HOUR",
                    operator_guidance="Check URLhaus, VirusTotal, and internal DNS queries for broader campaign indicators.",
                    automated_remediation_suggested=False,
                )
            )
        elif risk_level == RiskLevel.MEDIUM:
            actions.append(
                DefenseRecommendation(
                    action_id=f"ACT-{session_id}-11",
                    risk_level=RiskLevel.MEDIUM,
                    title="Investigate Authentication Activity & Context Drift",
                    action="Correlate the session ID across SIEM logs to verify whether the source IP, device fingerprint, or ASN matches the user's historical profile.",
                    rationale="Medium risk indicates anomalous redirect traversal or certificate characteristics that warrant analyst triage before punitive session termination.",
                    urgency="WITHIN_1_HOUR",
                    operator_guidance="Reach out to user via out-of-band channel (voice/chat) if device context shows an unrecognized browser or country.",
                    automated_remediation_suggested=False,
                )
            )
            actions.append(
                DefenseRecommendation(
                    action_id=f"ACT-{session_id}-12",
                    risk_level=RiskLevel.MEDIUM,
                    title="Apply Conditional Access Risk Step-Up",
                    action="Attach a high-risk session tag in the IdP policy engine to enforce re-authentication before accessing high-impact resources (e.g., Azure Portal, HR databases).",
                    rationale="Restricts blast radius while preventing disruption to legitimate users who experienced a transient network glitch.",
                    urgency="WITHIN_1_HOUR",
                    operator_guidance="Ensure the step-up prompt mandates phishing-resistant MFA.",
                    automated_remediation_suggested=True,
                )
            )
        else:  # LOW
            actions.append(
                DefenseRecommendation(
                    action_id=f"ACT-{session_id}-21",
                    risk_level=RiskLevel.LOW,
                    title="Continue Continuous Monitoring",
                    action="Maintain standard session telemetry logging and retain authentication telemetry in the data pipeline.",
                    rationale="Authentication flow exhibited expected single sign-on or direct login characteristics with unanomalous transport parameters.",
                    urgency="ROUTINE",
                    operator_guidance="No analyst intervention required. Telemetry remains indexed for temporal session continuity tracking.",
                    automated_remediation_suggested=False,
                )
            )

        return actions

    def _build_signal_remediations(
        self,
        signals: dict[str, bool],
        indicators: list[str],
    ) -> list[str]:
        """Builds signal-specific tactical hardening instructions."""
        remediations: list[str] = []

        if signals.get("tls_anomaly"):
            remediations.append(
                "TLS Certificate Anomaly Detected: Inspect client TLS certificate parameters. "
                "Verify whether an untrusted self-signed certificate, SNI mismatch, or non-matching SAN "
                "was presented. Verify corporate TLS inspection certificates if enterprise middlebox is in path; "
                "otherwise treat as an active AiTM proxy insertion attempt. Enforce HSTS Preloading."
            )

        if signals.get("redirect_anomaly"):
            remediations.append(
                "Suspicious Redirect Chain Detected: Cyclic redirect loop or excessive intermediate hops observed. "
                "Inspect intermediary hostnames in the authentication path. Verify whether intermediate hosts are "
                "registered in your enterprise proxy/CASB allowlist. Add unknown intermediary domains to your "
                "Secure Web Gateway (SWG) and DNS sinkhole blocklist."
            )

        if signals.get("replay_indicator"):
            remediations.append(
                "Session Replay & Context Bifurcation Detected: Stolen token replay signature identified "
                "(rapid source IP alternation, client platform mismatch, or simultaneous disparate user agents). "
                "Revoke active session tokens immediately via IdP session management APIs, isolate the host, "
                "and deploy cryptographic token binding (OAuth 2.0 DPoP or mTLS)."
            )

        if any("TOKEN_BINDING_FAILURE" in i for i in indicators):
            remediations.append(
                "Cryptographic Token Binding Failure: Proof-of-possession validation failed or key signature mismatch. "
                "Ensure client application attaches a valid DPoP proof header (RFC 9449) and reject unauthenticated requests."
            )

        if not remediations:
            remediations.append(
                "Standard Authentication Telemetry: No anomalous redirect, transport, or session transitions detected. "
                "Continue standard identity monitoring."
            )

        return remediations

    def _select_checklist_highlights(
        self,
        risk_level: RiskLevel,
        signals: dict[str, bool],
        indicators: list[str],
    ) -> list[HardeningChecklistItem]:
        """Selects the most relevant checklist items for the observed scenario."""
        all_items = self.checklist.get_all_items()
        selected: list[HardeningChecklistItem] = []

        # Always include Critical FIDO2/Passkey item
        fido2_item = next((i for i in all_items if i.id == "CHK-IDP-01"), None)
        if fido2_item:
            selected.append(fido2_item)

        webauthn_item = next((i for i in all_items if i.id == "CHK-WEBAUTHN-01"), None)
        if webauthn_item:
            selected.append(webauthn_item)

        # Signal-specific additions
        if signals.get("replay_indicator") or any("TOKEN" in i for i in indicators):
            dpop_item = next((i for i in all_items if i.id == "CHK-TOKEN-01"), None)
            if dpop_item and dpop_item not in selected:
                selected.append(dpop_item)

        if signals.get("redirect_anomaly") or risk_level == RiskLevel.HIGH:
            soc_item = next((i for i in all_items if i.id == "CHK-SOC-01"), None)
            if soc_item and soc_item not in selected:
                selected.append(soc_item)

        if signals.get("tls_anomaly"):
            edge_item = next((i for i in all_items if i.id == "CHK-EDGE-01"), None)
            if edge_item and edge_item not in selected:
                selected.append(edge_item)

        return selected

    def _build_phishing_resistant_strategy(self, risk_level: RiskLevel) -> dict[str, Any]:
        """Builds a succinct, executive-ready explanation of why FIDO2 resolves this vulnerability."""
        origin_doc = self.kb.explain_origin_binding()
        token_doc = self.kb.explain_token_binding()

        recommended_auth = "FIDO2 Hardware Security Key (e.g. YubiKey) or Platform Passkey (Windows Hello / Touch ID)"
        if risk_level == RiskLevel.LOW:
            posture = "Maintain and accelerate migration from phishable factors (SMS/Voice/TOTP) to Passkeys."
        elif risk_level == RiskLevel.MEDIUM:
            posture = "Prioritize FIDO2 enrollment for accounts exhibiting anomalous redirect or session telemetry."
        else:
            posture = "IMMEDIATE MANDATE: Require FIDO2/Passkey authentication to remediate this active session compromise."

        return {
            "recommended_authentication_standard": recommended_auth,
            "nist_assurance_level": "NIST SP 800-63B AAL3",
            "strategic_posture": posture,
            "core_immunity_mechanism": (
                "FIDO2 WebAuthn authentication assertions are cryptographically bound to the browser's verified "
                "TLS domain (origin) in clientDataJSON. An AiTM reverse proxy cannot spoof the domain or relay the "
                "signature to the genuine IdP, rendering reverse-proxy phishing ineffective."
            ),
            "origin_binding_summary": origin_doc["executive_summary"],
            "token_binding_summary": token_doc["executive_summary"],
        }

    @staticmethod
    def _build_summary_banner(
        session_id: str,
        risk_level: RiskLevel,
        score_percent: int,
        signals: dict[str, bool],
    ) -> str:
        """Constructs concise status banner for SOC headers."""
        active_signals = [k for k, v in signals.items() if v]
        signal_str = f" [Signals: {', '.join(active_signals)}]" if active_signals else ""

        if risk_level == RiskLevel.HIGH:
            return (
                f"[HIGH RISK] ({score_percent}/100) - Session '{session_id}' exhibits high-confidence AiTM proxy or session replay signatures.{signal_str} "
                f"Action: Invalidate session immediately, require FIDO2/passkey re-authentication, and contain attacker infrastructure."
            )
        elif risk_level == RiskLevel.MEDIUM:
            return (
                f"[MEDIUM RISK] ({score_percent}/100) - Session '{session_id}' exhibited anomalous redirect or transport telemetry.{signal_str} "
                f"Action: Triage authentication activity, verify device context, and apply conditional step-up MFA."
            )
        else:
            return (
                f"[LOW RISK] ({score_percent}/100) - Session '{session_id}' conforms to normal single sign-on and direct authentication baselines. "
                f"Action: Continue continuous monitoring."
            )
