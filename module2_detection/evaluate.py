"""
Reproducible evaluation script comparing the Simple Baseline Detector
and the Sequence-Aware Enhanced Detector (AiTMDetector) on a synthetic
benchmark of 16 labelled authentication events (8 benign, 8 suspicious).
"""

from dataclasses import dataclass
from typing import Any
import sys
from pathlib import Path

# Add module2_detection parent to path so detector can be imported cleanly
MODULE2_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(MODULE2_DIR))

from detector import AiTMDetector


@dataclass
class TestCase:
    case_id: str
    description: str
    ground_truth: str  # "benign" or "suspicious"
    event: dict[str, Any]


# ----------------------------------------------------------------------
# Synthetic Evaluation Dataset (16 Cases: 8 Benign, 8 Suspicious)
# Note: Ground-truth labels are stored separately and NEVER passed
# to the detection models.
# ----------------------------------------------------------------------
EVALUATION_DATASET: list[TestCase] = [
    # ------------------ Benign Cases (8) ------------------
    TestCase(
        case_id="BENIGN-01",
        description="Direct authentication without redirects",
        ground_truth="benign",
        event={
            "session_id": "BENIGN-01",
            "redirect_count": 0,
            "redirect_chain": ["portal.internal.company.com"],
            "tls_anomaly": False,
        },
    ),
    TestCase(
        case_id="BENIGN-02",
        description="Single redirect to central identity provider",
        ground_truth="benign",
        event={
            "session_id": "BENIGN-02",
            "redirect_count": 1,
            "redirect_chain": ["login.idp.company.com"],
            "tls_anomaly": False,
        },
    ),
    TestCase(
        case_id="BENIGN-03",
        description="Canonical 3-hop SAML SSO bounce (SP -> IdP -> SP)",
        ground_truth="benign",
        event={
            "session_id": "BENIGN-03",
            "redirect_count": 2,
            "redirect_chain": [
                "app.corp.local",
                "login.microsoftonline.com",
                "app.corp.local",
            ],
            "tls_anomaly": False,
        },
    ),
    TestCase(
        case_id="BENIGN-04",
        description="Canonical SAML SSO bounce with redirect_count=3 variance",
        ground_truth="benign",
        event={
            "session_id": "BENIGN-04",
            "redirect_count": 3,
            "redirect_chain": [
                "jira.internal.net",
                "okta.internal.net",
                "jira.internal.net",
            ],
            "tls_anomaly": False,
        },
    ),
    TestCase(
        case_id="BENIGN-05",
        description="Benign intra-domain subdomain handoff",
        ground_truth="benign",
        event={
            "session_id": "BENIGN-05",
            "redirect_count": 1,
            "redirect_chain": ["mail.corp.com", "auth.corp.com"],
            "tls_anomaly": False,
        },
    ),
    TestCase(
        case_id="BENIGN-06",
        description="Multi-tenant enterprise SaaS federation (CRM -> AzureAD -> CRM)",
        ground_truth="benign",
        event={
            "session_id": "BENIGN-06",
            "redirect_count": 2,
            "redirect_chain": [
                "crm.salesforce.com",
                "login.microsoftonline.com",
                "crm.salesforce.com",
            ],
            "tls_anomaly": False,
        },
    ),
    TestCase(
        case_id="BENIGN-07",
        description="Intranet portal 2-hop navigation to auth service",
        ground_truth="benign",
        event={
            "session_id": "BENIGN-07",
            "redirect_count": 2,
            "redirect_chain": ["intranet.local", "sso.internal.local"],
            "tls_anomaly": False,
        },
    ),
    TestCase(
        case_id="BENIGN-08",
        description="Standard OAuth authorization code callback bounce",
        ground_truth="benign",
        event={
            "session_id": "BENIGN-08",
            "redirect_count": 2,
            "redirect_chain": [
                "client-app.com",
                "auth-service.com",
                "client-app.com",
            ],
            "tls_anomaly": False,
        },
    ),
    # ------------------ Suspicious Cases (8) ------------------
    TestCase(
        case_id="SUSP-01",
        description="AiTM proxy sandwich with TLS anomaly (LAB-002 simulation)",
        ground_truth="suspicious",
        event={
            "session_id": "SUSP-01",
            "redirect_count": 4,
            "redirect_chain": [
                "lab-login.local",
                "proxy-simulation.local",
                "lab-idp.local",
                "lab-login.local",
            ],
            "tls_anomaly": True,
        },
    ),
    TestCase(
        case_id="SUSP-02",
        description="Stealth AiTM reverse proxy sandwich without TLS anomaly",
        ground_truth="suspicious",
        event={
            "session_id": "SUSP-02",
            "redirect_count": 4,
            "redirect_chain": [
                "login.target.com",
                "evil-aitm-proxy.net",
                "idp.target.com",
                "login.target.com",
            ],
            "tls_anomaly": False,
        },
    ),
    TestCase(
        case_id="SUSP-03",
        description="Stealth credential harvester loop without TLS anomaly",
        ground_truth="suspicious",
        event={
            "session_id": "SUSP-03",
            "redirect_count": 3,
            "redirect_chain": [
                "portal.org",
                "aitm-harvest.biz",
                "idp.org",
                "portal.org",
            ],
            "tls_anomaly": False,
        },
    ),
    TestCase(
        case_id="SUSP-04",
        description="Cyclic proxy bouncing without TLS anomaly",
        ground_truth="suspicious",
        event={
            "session_id": "SUSP-04",
            "redirect_count": 4,
            "redirect_chain": [
                "target.com",
                "proxy.evil",
                "target.com",
                "proxy.evil",
            ],
            "tls_anomaly": False,
        },
    ),
    TestCase(
        case_id="SUSP-05",
        description="Excessive multi-hop redirection chain (6 hops)",
        ground_truth="suspicious",
        event={
            "session_id": "SUSP-05",
            "redirect_count": 6,
            "redirect_chain": [
                "h1.com",
                "h2.com",
                "h3.com",
                "h4.com",
                "h5.com",
                "h6.com",
            ],
            "tls_anomaly": False,
        },
    ),
    TestCase(
        case_id="SUSP-06",
        description="Intermediary proxy injection with TLS anomaly",
        ground_truth="suspicious",
        event={
            "session_id": "SUSP-06",
            "redirect_count": 3,
            "redirect_chain": [
                "login.site.com",
                "proxy.site.com",
                "auth.site.com",
            ],
            "tls_anomaly": True,
        },
    ),
    TestCase(
        case_id="SUSP-07",
        description="Evasive AiTM proxy loop reporting low redirect_count (telemetry divergence)",
        ground_truth="suspicious",
        event={
            "session_id": "SUSP-07",
            "redirect_count": 1,
            "redirect_chain": [
                "login.target.net",
                "proxy.stealth.io",
                "idp.target.net",
                "login.target.net",
            ],
            "tls_anomaly": False,
        },
    ),
    TestCase(
        case_id="SUSP-08",
        description="Multi-domain intermediary traversal without TLS anomaly",
        ground_truth="suspicious",
        event={
            "session_id": "SUSP-08",
            "redirect_count": 4,
            "redirect_chain": [
                "spoof.com",
                "gate.net",
                "aitm-node.org",
                "idp.target.com",
                "spoof.com",
            ],
            "tls_anomaly": False,
        },
    ),
]


def baseline_predict(event: dict[str, Any]) -> str:
    """
    Simple Baseline Detector:
    Predicts 'suspicious' if redirect_count > 2 OR tls_anomaly is True.
    Otherwise predicts 'benign'.
    """
    if event["redirect_count"] > 2 or event["tls_anomaly"] is True:
        return "suspicious"
    return "benign"


def calculate_metrics(y_true: list[str], y_pred: list[str]) -> dict[str, Any]:
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == "suspicious" and yp == "suspicious")
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == "benign" and yp == "suspicious")
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == "benign" and yp == "benign")
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == "suspicious" and yp == "benign")

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
    enhanced_detector = AiTMDetector()

    y_true: list[str] = []
    y_pred_baseline: list[str] = []
    y_pred_enhanced: list[str] = []
    detailed_rows: list[dict[str, Any]] = []

    for case in EVALUATION_DATASET:
        truth = case.ground_truth
        y_true.append(truth)

        # Baseline prediction
        base_verdict = baseline_predict(case.event)
        y_pred_baseline.append(base_verdict)

        # Enhanced detector prediction
        enhanced_result = enhanced_detector.analyze_event(case.event)
        enh_verdict = enhanced_result["verdict"]
        y_pred_enhanced.append(enh_verdict)

        detailed_rows.append(
            {
                "case_id": case.case_id,
                "description": case.description,
                "truth": truth,
                "baseline_pred": base_verdict,
                "enhanced_pred": enh_verdict,
                "enhanced_score": enhanced_result["risk_score"],
                "rules": ", ".join(enhanced_result["triggered_rules"]) if enhanced_result["triggered_rules"] else "NONE",
            }
        )

    metrics_baseline = calculate_metrics(y_true, y_pred_baseline)
    metrics_enhanced = calculate_metrics(y_true, y_pred_enhanced)

    print("=" * 105)
    print("PER-CASE COMPARISON TABLE (16 Labelled Synthetic Cases)")
    print("=" * 105)
    header = f"{'Case ID':<10} | {'Truth':<10} | {'Baseline':<10} | {'Enhanced':<10} | {'Score':<6} | {'Triggered Rules (Enhanced)'}"
    print(header)
    print("-" * 105)
    for row in detailed_rows:
        mark = " "
        if row["baseline_pred"] != row["enhanced_pred"]:
            mark = "*"  # Mark cases where predictions differ
        print(
            f"{mark}{row['case_id']:<9} | {row['truth']:<10} | {row['baseline_pred']:<10} | {row['enhanced_pred']:<10} | {row['enhanced_score']:<6.2f} | {row['rules']}"
        )
    print("-" * 105)
    print("(* denotes cases where Baseline and Enhanced detector verdicts differ)\n")

    print("=" * 70)
    print("SUMMARY PERFORMANCE METRICS")
    print("=" * 70)
    print(f"{'Metric':<30} | {'Simple Baseline':<16} | {'Enhanced Detector'}")
    print("-" * 70)
    print(f"{'Total Cases':<30} | {len(y_true):<16} | {len(y_true)}")
    print(f"{'Positive Cases (Suspicious)':<30} | {y_true.count('suspicious'):<16} | {y_true.count('suspicious')}")
    print(f"{'Negative Cases (Benign)':<30} | {y_true.count('benign'):<16} | {y_true.count('benign')}")
    print(f"{'True Positives (TP)':<30} | {metrics_baseline['TP']:<16} | {metrics_enhanced['TP']}")
    print(f"{'False Positives (FP)':<30} | {metrics_baseline['FP']:<16} | {metrics_enhanced['FP']}")
    print(f"{'True Negatives (TN)':<30} | {metrics_baseline['TN']:<16} | {metrics_enhanced['TN']}")
    print(f"{'False Negatives (FN)':<30} | {metrics_baseline['FN']:<16} | {metrics_enhanced['FN']}")
    print("-" * 70)
    print(f"{'Precision [TP / (TP+FP)]':<30} | {metrics_baseline['precision']:<16.4f} | {metrics_enhanced['precision']:.4f}")
    print(f"{'Recall [TP / (TP+FN)]':<30} | {metrics_baseline['recall']:<16.4f} | {metrics_enhanced['recall']:.4f}")
    print(f"{'F1-Score':<30} | {metrics_baseline['f1']:<16.4f} | {metrics_enhanced['f1']:.4f}")
    print(f"{'False Positive Rate (FPR)':<30} | {metrics_baseline['fpr']:<16.4f} | {metrics_enhanced['fpr']:.4f}")
    print("=" * 70)
    print("\nNOTE ON EVALUATION:")
    print("This evaluation was conducted on a small, synthetic lab benchmark of 16 handcrafted")
    print("scenarios. These results demonstrate comparative behavior on specified test cases")
    print("and do NOT constitute empirical proof of general or real-world AiTM detection efficacy.")


if __name__ == "__main__":
    main()
