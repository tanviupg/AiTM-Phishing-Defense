"""
Benchmark v2: Comprehensive Multi-Signal AiTM Detection Evaluation (Module 2, Stage 3).

Evaluates the Base Redirect Detector against the Composite Multi-Signal Detector
(Redirects + Temporal Context + TLS/Certificate Telemetry) on a structured,
reproducible 24-case synthetic benchmark (12 benign, 12 suspicious).

Indicators are namespaced by source (base:*, tls:*, session:*) to ensure complete
clarity regarding which subsystem emitted each observation.

Ground-truth labels are stored exclusively in TestCase metadata and are NEVER
passed to detection models.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional
import sys
from pathlib import Path

MODULE2_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(MODULE2_DIR))

from detector import AiTMDetector
from session_tracker import SessionTracker
from tls_analyzer import TLSAnalyzer, CertificateTelemetry


@dataclass
class TestCaseV2:
    case_id: str
    scenario_category: str
    description: str
    ground_truth: str  # "benign" or "suspicious"
    setup_event: Optional[dict[str, Any]]  # Prior event for establishing session history (if applicable)
    event: dict[str, Any]


# Fixed reference time for deterministic certificate validity checks
BENCHMARK_REF_TIME = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)


BENCHMARK_V2_DATASET: list[TestCaseV2] = [
    # =========================================================================
    # BENIGN CASES (12 Cases: V2-BEN-01 to V2-BEN-12)
    # =========================================================================
    TestCaseV2(
        case_id="V2-BEN-01",
        scenario_category="Direct Login / Uninstrumented TLS",
        description="Direct login to internal portal with missing TLS telemetry",
        ground_truth="benign",
        setup_event=None,
        event={
            "session_id": "V2-BEN-01",
            "redirect_count": 0,
            "redirect_chain": ["portal.internal.corp"],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-CORP-01",
        },
    ),
    TestCaseV2(
        case_id="V2-BEN-02",
        scenario_category="Canonical SSO Bounce",
        description="Standard 3-hop SAML SSO bounce (SP -> IdP -> SP)",
        ground_truth="benign",
        setup_event=None,
        event={
            "session_id": "V2-BEN-02",
            "redirect_count": 2,
            "redirect_chain": [
                "app.corp.local",
                "login.microsoftonline.com",
                "app.corp.local",
            ],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-CORP-01",
            "certificate_telemetry": {
                "observed_hostname": "login.microsoftonline.com",
                "subject_cn": "login.microsoftonline.com",
                "subject_alt_names": ["login.microsoftonline.com", "*.microsoft.com"],
                "issuer_org": "DigiCert Inc",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
                "validation_status": "valid",
            },
        },
    ),
    TestCaseV2(
        case_id="V2-BEN-03",
        scenario_category="Canonical SSO (Count 3 Variance)",
        description="Legitimate federated SSO bounce reporting redirect_count=3",
        ground_truth="benign",
        setup_event=None,
        event={
            "session_id": "V2-BEN-03",
            "redirect_count": 3,
            "redirect_chain": [
                "jira.internal.net",
                "okta.internal.net",
                "jira.internal.net",
            ],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-CORP-01",
        },
    ),
    TestCaseV2(
        case_id="V2-BEN-04",
        scenario_category="Enterprise SSL Inspection (Unmanaged / BYOD Client)",
        description="Unmanaged BYOD client observing corporate SSL inspection middlebox re-signing; score 0.20 represents investigative triage and remains benign",
        ground_truth="benign",
        setup_event=None,
        event={
            "session_id": "V2-BEN-04",
            "redirect_count": 1,
            "redirect_chain": ["login.idp.company.com"],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "10.0.50.20",
            "device_id": "DEV-WORKSTATION-05",
            "certificate_telemetry": {
                "observed_hostname": "login.idp.company.com",
                "subject_cn": "login.idp.company.com",
                "issuer_org": "Corporate Proxy CA (Zscaler Inspection)",
                "is_self_signed": True,
                "validation_status": "untrusted_root",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
            },
        },
    ),
    TestCaseV2(
        case_id="V2-BEN-05",
        scenario_category="Legitimate Mobile Network Roaming",
        description="Employee switches from Wi-Fi to cellular hotspot after 600s on same device",
        ground_truth="benign",
        setup_event={
            "session_id": "V2-BEN-05",
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-MOBILE-01",
        },
        event={
            "session_id": "V2-BEN-05",
            "redirect_count": 1,
            "redirect_chain": ["mail.company.com"],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:10:00Z",
            "source_ip": "198.51.100.88",
            "device_id": "DEV-MOBILE-01",
        },
    ),
    TestCaseV2(
        case_id="V2-BEN-06",
        scenario_category="CDN Wildcard Certificate",
        description="Cloudflare edge presenting valid wildcard *.corp.net certificate",
        ground_truth="benign",
        setup_event=None,
        event={
            "session_id": "V2-BEN-06",
            "redirect_count": 1,
            "redirect_chain": ["auth.corp.net"],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-CORP-01",
            "certificate_telemetry": {
                "observed_hostname": "auth.corp.net",
                "subject_cn": "*.corp.net",
                "subject_alt_names": ["*.corp.net", "corp.net"],
                "issuer_org": "Cloudflare Inc ECC CA-3",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
                "validation_status": "valid",
            },
        },
    ),
    TestCaseV2(
        case_id="V2-BEN-07",
        scenario_category="Subdomain Handoff",
        description="Benign intra-domain subdomain handoff (mail -> auth)",
        ground_truth="benign",
        setup_event=None,
        event={
            "session_id": "V2-BEN-07",
            "redirect_count": 1,
            "redirect_chain": ["mail.corp.com", "auth.corp.com"],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-CORP-01",
        },
    ),
    TestCaseV2(
        case_id="V2-BEN-08",
        scenario_category="Multi-Tenant SaaS Federation",
        description="Enterprise CRM to Azure AD federation bounce",
        ground_truth="benign",
        setup_event=None,
        event={
            "session_id": "V2-BEN-08",
            "redirect_count": 2,
            "redirect_chain": [
                "crm.salesforce.com",
                "login.microsoftonline.com",
                "crm.salesforce.com",
            ],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-CORP-01",
        },
    ),
    TestCaseV2(
        case_id="V2-BEN-09",
        scenario_category="Incomplete TLS Telemetry",
        description="Sensor recorded TLS version but cert payload was unparsed",
        ground_truth="benign",
        setup_event=None,
        event={
            "session_id": "V2-BEN-09",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.org"],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-CORP-01",
            "certificate_telemetry": {
                "tls_version": "TLSv1.3",
            },
        },
    ),
    TestCaseV2(
        case_id="V2-BEN-10",
        scenario_category="Intranet 2-Hop Navigation",
        description="Intranet portal 2-hop navigation to auth service",
        ground_truth="benign",
        setup_event=None,
        event={
            "session_id": "V2-BEN-10",
            "redirect_count": 2,
            "redirect_chain": ["intranet.local", "sso.internal.local"],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-CORP-01",
        },
    ),
    TestCaseV2(
        case_id="V2-BEN-11",
        scenario_category="Standard OAuth Code Callback",
        description="OAuth authorization code callback bounce",
        ground_truth="benign",
        setup_event=None,
        event={
            "session_id": "V2-BEN-11",
            "redirect_count": 2,
            "redirect_chain": [
                "client-app.com",
                "auth-service.com",
                "client-app.com",
            ],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-CORP-01",
        },
    ),
    TestCaseV2(
        case_id="V2-BEN-12",
        scenario_category="Normal Session Continuation",
        description="Normal session event continuation on identical IP and device",
        ground_truth="benign",
        setup_event={
            "session_id": "V2-BEN-12",
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-USER-01",
        },
        event={
            "session_id": "V2-BEN-12",
            "redirect_count": 1,
            "redirect_chain": ["portal.internal.net"],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:05:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-USER-01",
        },
    ),

    # =========================================================================
    # SUSPICIOUS CASES (12 Cases: V2-SUSP-01 to V2-SUSP-12)
    # =========================================================================
    TestCaseV2(
        case_id="V2-SUSP-01",
        scenario_category="Classic AiTM Proxy Sandwich",
        description="AiTM reverse proxy sandwich with legacy TLS anomaly flag (LAB-002 style)",
        ground_truth="suspicious",
        setup_event=None,
        event={
            "session_id": "V2-SUSP-01",
            "redirect_count": 4,
            "redirect_chain": [
                "lab-login.local",
                "proxy-simulation.local",
                "lab-idp.local",
                "lab-login.local",
            ],
            "tls_anomaly": True,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "198.51.100.20",
            "device_id": "DEV-SIM-02",
        },
    ),
    TestCaseV2(
        case_id="V2-SUSP-02",
        scenario_category="Stealth AiTM with Valid Cert on Proxy Domain",
        description="AiTM reverse proxy where attacker holds a valid Let's Encrypt cert on phishing domain",
        ground_truth="suspicious",
        setup_event=None,
        event={
            "session_id": "V2-SUSP-02",
            "redirect_count": 4,
            "redirect_chain": [
                "login.target.com",
                "evil-aitm-proxy.net",
                "idp.target.com",
                "login.target.com",
            ],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "198.51.100.20",
            "device_id": "DEV-SIM-02",
            "certificate_telemetry": {
                "observed_hostname": "evil-aitm-proxy.net",
                "subject_cn": "evil-aitm-proxy.net",
                "subject_alt_names": ["evil-aitm-proxy.net"],
                "issuer_org": "Let's Encrypt",
                "not_before": "2026-09-01T00:00:00Z",
                "not_after": "2026-11-30T23:59:59Z",
                "validation_status": "valid",
            },
        },
    ),
    TestCaseV2(
        case_id="V2-SUSP-03",
        scenario_category="Presented Certificate Hostname Mismatch",
        description="Target host is login.bank.com, but presented cert is for phish-proxy.local (score 0.30 investigative triage)",
        ground_truth="suspicious",
        setup_event=None,
        event={
            "session_id": "V2-SUSP-03",
            "redirect_count": 1,
            "redirect_chain": ["login.bank.com"],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "198.51.100.20",
            "device_id": "DEV-SIM-02",
            "certificate_telemetry": {
                "observed_hostname": "login.bank.com",
                "subject_cn": "phish-proxy.local",
                "subject_alt_names": ["phish-proxy.local"],
                "issuer_org": "Untrusted Cert Authority",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
            },
        },
    ),
    TestCaseV2(
        case_id="V2-SUSP-04",
        scenario_category="Expired Staging Proxy Certificate",
        description="AiTM lab proxy operating with an expired certificate",
        ground_truth="suspicious",
        setup_event=None,
        event={
            "session_id": "V2-SUSP-04",
            "redirect_count": 3,
            "redirect_chain": [
                "portal.org",
                "expired-proxy.org",
                "idp.org",
                "portal.org",
            ],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "198.51.100.20",
            "device_id": "DEV-SIM-02",
            "certificate_telemetry": {
                "observed_hostname": "expired-proxy.org",
                "subject_cn": "expired-proxy.org",
                "not_before": "2025-01-01T00:00:00Z",
                "not_after": "2026-01-01T00:00:00Z",
            },
        },
    ),
    TestCaseV2(
        case_id="V2-SUSP-05",
        scenario_category="Suspicious Rapid Context Transition (Device & IP Mismatch)",
        description="Active session observed with rapid simultaneous device change and source IP transition in 15 seconds; investigative anomaly, token theft not proven",
        ground_truth="suspicious",
        setup_event={
            "session_id": "V2-SUSP-05",
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-VICTIM-01",
        },
        event={
            "session_id": "V2-SUSP-05",
            "redirect_count": 1,
            "redirect_chain": ["idp.company.com"],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:15Z",
            "source_ip": "198.51.100.99",
            "device_id": "DEV-ATTACKER-99",
        },
    ),
    TestCaseV2(
        case_id="V2-SUSP-06",
        scenario_category="Telemetry Inconsistency / Obfuscated Proxy",
        description="AiTM proxy chain reporting low redirect_count=1 despite 4 observed hosts",
        ground_truth="suspicious",
        setup_event=None,
        event={
            "session_id": "V2-SUSP-06",
            "redirect_count": 1,
            "redirect_chain": [
                "login.target.net",
                "proxy.stealth.io",
                "idp.target.net",
                "login.target.net",
            ],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "198.51.100.20",
            "device_id": "DEV-SIM-02",
        },
    ),
    TestCaseV2(
        case_id="V2-SUSP-07",
        scenario_category="SNI Transport Discrepancy",
        description="Client SNI header mismatches target HTTP host during authentication",
        ground_truth="suspicious",
        setup_event=None,
        event={
            "session_id": "V2-SUSP-07",
            "redirect_count": 3,
            "redirect_chain": ["login.company.com", "proxy.front.com", "idp.company.com"],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "198.51.100.20",
            "device_id": "DEV-SIM-02",
            "certificate_telemetry": {
                "observed_hostname": "login.company.com",
                "sni_hostname": "fronting.attacker.net",
                "subject_cn": "login.company.com",
            },
        },
    ),
    TestCaseV2(
        case_id="V2-SUSP-08",
        scenario_category="High Transition Complexity (Multi-Domain Proxy)",
        description="AiTM chain hopping across 5 distinct domains",
        ground_truth="suspicious",
        setup_event=None,
        event={
            "session_id": "V2-SUSP-08",
            "redirect_count": 4,
            "redirect_chain": [
                "spoof.com",
                "gate.net",
                "aitm-node.org",
                "idp.target.com",
                "spoof.com",
            ],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "198.51.100.20",
            "device_id": "DEV-SIM-02",
        },
    ),
    TestCaseV2(
        case_id="V2-SUSP-09",
        scenario_category="Cyclic Proxy Bouncing",
        description="Repetitive cyclic bouncing between proxy and target host",
        ground_truth="suspicious",
        setup_event=None,
        event={
            "session_id": "V2-SUSP-09",
            "redirect_count": 4,
            "redirect_chain": [
                "target.com",
                "proxy.evil.org",
                "target.com",
                "proxy.evil.org",
            ],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "198.51.100.20",
            "device_id": "DEV-SIM-02",
        },
    ),
    TestCaseV2(
        case_id="V2-SUSP-10",
        scenario_category="Stealth Credential Harvest Loop",
        description="Intermediate harvester domain traversed before returning to portal",
        ground_truth="suspicious",
        setup_event=None,
        event={
            "session_id": "V2-SUSP-10",
            "redirect_count": 3,
            "redirect_chain": [
                "portal.org",
                "aitm-harvest.biz",
                "idp.org",
                "portal.org",
            ],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "198.51.100.20",
            "device_id": "DEV-SIM-02",
        },
    ),
    TestCaseV2(
        case_id="V2-SUSP-11",
        scenario_category="Excessive Multi-Hop Chain",
        description="Excessive redirect sequence traversing 6 hops",
        ground_truth="suspicious",
        setup_event=None,
        event={
            "session_id": "V2-SUSP-11",
            "redirect_count": 6,
            "redirect_chain": ["h1.com", "h2.com", "h3.com", "h4.com", "h5.com", "h6.com"],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "198.51.100.20",
            "device_id": "DEV-SIM-02",
        },
    ),
    TestCaseV2(
        case_id="V2-SUSP-12",
        scenario_category="Untrusted Root with Intermediary Proxy",
        description="Untrusted self-signed root certificate coupled with intermediary injection",
        ground_truth="suspicious",
        setup_event=None,
        event={
            "session_id": "V2-SUSP-12",
            "redirect_count": 3,
            "redirect_chain": ["login.site.com", "proxy.site.com", "auth.site.com"],
            "tls_anomaly": False,
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "198.51.100.20",
            "device_id": "DEV-SIM-02",
            "certificate_telemetry": {
                "observed_hostname": "proxy.site.com",
                "subject_cn": "proxy.site.com",
                "is_self_signed": True,
                "validation_status": "untrusted_root",
            },
        },
    ),
]


def calculate_metrics_v2(y_true: list[str], y_pred: list[str]) -> dict[str, Any]:
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == "suspicious" and yp == "suspicious")
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == "benign" and yp == "suspicious")
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == "benign" and yp == "benign")
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == "suspicious" and yp == "benign")

    # Safe handling for zero denominators
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
    }


def main():
    detector = AiTMDetector()
    session_tracker = SessionTracker()
    tls_analyzer = TLSAnalyzer()

    y_true: list[str] = []
    y_pred_base: list[str] = []
    y_pred_composite: list[str] = []
    detailed_rows: list[dict[str, Any]] = []

    for case in BENCHMARK_V2_DATASET:
        # Ground truth is isolated from detection models
        truth = case.ground_truth
        y_true.append(truth)

        # Reset session tracker before each test case
        session_tracker.reset()
        if case.setup_event is not None:
            session_tracker.correlate_event(case.setup_event)

        # 1. Base detector prediction (redirect & legacy TLS only)
        base_res = detector.analyze_event(case.event)
        base_verdict = base_res["verdict"]
        y_pred_base.append(base_verdict)

        # 2. Composite multi-signal prediction
        comp_res = detector.analyze_event_composite(
            case.event,
            session_tracker=session_tracker,
            tls_analyzer=tls_analyzer,
            reference_time=BENCHMARK_REF_TIME,
        )
        comp_verdict = comp_res["composite_verdict"]
        y_pred_composite.append(comp_verdict)

        detailed_rows.append(
            {
                "case_id": case.case_id,
                "category": case.scenario_category,
                "truth": truth,
                "base_pred": base_verdict,
                "base_score": base_res["risk_score"],
                "comp_pred": comp_verdict,
                "comp_score": comp_res["composite_risk_score"],
                "indicators": ", ".join(comp_res["all_triggered_indicators"]) if comp_res["all_triggered_indicators"] else "NONE",
            }
        )

    metrics_base = calculate_metrics_v2(y_true, y_pred_base)
    metrics_composite = calculate_metrics_v2(y_true, y_pred_composite)

    print("=" * 135)
    print("BENCHMARK V2 PER-CASE RESULTS (24 Labelled Synthetic Multi-Signal Cases)")
    print("=" * 135)
    header = f"{'Case ID':<10} | {'Truth':<10} | {'Base':<10} | {'Composite':<10} | {'B-Score':<7} | {'C-Score':<7} | {'Namespaced Triggered Indicators'}"
    print(header)
    print("-" * 135)
    for row in detailed_rows:
        mark = " "
        if row["base_pred"] != row["comp_pred"]:
            mark = "*"  # Mark divergence
        print(
            f"{mark}{row['case_id']:<9} | {row['truth']:<10} | {row['base_pred']:<10} | {row['comp_pred']:<10} | {row['base_score']:<7.2f} | {row['comp_score']:<7.2f} | {row['indicators']}"
        )
    print("-" * 135)
    print("(* denotes cases where Base Detector and Composite Detector verdicts differ)\n")

    print("=" * 75)
    print("BENCHMARK V2 SUMMARY PERFORMANCE METRICS")
    print("=" * 75)
    print(f"{'Metric':<32} | {'Base Detector':<16} | {'Composite Detector'}")
    print("-" * 75)
    print(f"{'Total Cases':<32} | {len(y_true):<16} | {len(y_true)}")
    print(f"{'Positive Cases (Suspicious)':<32} | {y_true.count('suspicious'):<16} | {y_true.count('suspicious')}")
    print(f"{'Negative Cases (Benign)':<32} | {y_true.count('benign'):<16} | {y_true.count('benign')}")
    print(f"{'True Positives (TP)':<32} | {metrics_base['TP']:<16} | {metrics_composite['TP']}")
    print(f"{'False Positives (FP)':<32} | {metrics_base['FP']:<16} | {metrics_composite['FP']}")
    print(f"{'True Negatives (TN)':<32} | {metrics_base['TN']:<16} | {metrics_composite['TN']}")
    print(f"{'False Negatives (FN)':<32} | {metrics_base['FN']:<16} | {metrics_composite['FN']}")
    print("-" * 75)
    print(f"{'Precision [TP / (TP+FP)]':<32} | {metrics_base['precision']:<16.4f} | {metrics_composite['precision']:.4f}")
    print(f"{'Recall [TP / (TP+FN)]':<32} | {metrics_base['recall']:<16.4f} | {metrics_composite['recall']:.4f}")
    print(f"{'F1-Score':<32} | {metrics_base['f1']:<16.4f} | {metrics_composite['f1']:.4f}")
    print(f"{'False Positive Rate (FPR)':<32} | {metrics_base['fpr']:<16.4f} | {metrics_composite['fpr']:.4f}")
    print("=" * 75)
    print("\nSCIENTIFIC EVALUATION NOTE:")
    print("Benchmark v2 evaluates 24 handcrafted synthetic scenarios. These metrics reflect")
    print("the deterministic rules on specified test fixtures and do NOT prove real-world accuracy.")


if __name__ == "__main__":
    main()
