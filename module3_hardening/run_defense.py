"""
End-to-End Pipeline Demonstration: Module 1 -> Module 2 -> Module 3.
Loads synthetic events from Module 1, runs detection through Module 2,
and generates defensive recommendations and FIDO2/passkey hardening plans via Module 3.
"""

import json
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from module2_detection.detector import AiTMDetector
from module2_detection.session_tracker import SessionTracker
from module2_detection.tls_analyzer import TLSAnalyzer
from module3_hardening.recommendation_engine import HardeningEngine
from module3_hardening.hardening_checklist import HardeningChecklist
from module3_hardening.auth_defense import AuthDefenseKnowledgeBase


def print_separator(char: str = "=", length: int = 100) -> None:
    print(char * length)


def run_pipeline() -> None:
    events_path = ROOT_DIR / "module1_aitm_poc" / "events" / "sample_events.json"

    if not events_path.exists():
        print(f"Error: Events file not found at {events_path}")
        print("Please run 'python module1_aitm_poc/event_generator.py' first.")
        sys.exit(1)

    with open(events_path, "r", encoding="utf-8") as f:
        events = json.load(f)

    print_separator("=")
    print("AiTM PHISHING DEFENSE - END-TO-END DEMONSTRATION")
    print("Module 1 (Event Gen) -> Module 2 (Detection) -> Module 3 (Hardening & Defense)")
    print_separator("=")
    print(f"Loaded {len(events)} synthetic events from Module 1.\n")

    detector = AiTMDetector()
    session_tracker = SessionTracker()
    tls_analyzer = TLSAnalyzer()
    hardening_engine = HardeningEngine()

    for idx, event in enumerate(events, 1):
        session_id = event.get("session_id", f"EVENT-{idx}")
        scenario = event.get("scenario", "unknown")

        print_separator("-")
        print(f"STEP 1: INGESTION (Module 1) - Session: {session_id} [{scenario}]")
        print_separator("-")
        print(f"  Timestamp:       {event.get('timestamp')}")
        print(f"  Redirect Count:  {event.get('redirect_count')}")
        print(f"  Redirect Chain:  {' -> '.join(event.get('redirect_chain', []))}")
        print(f"  TLS Anomaly:     {event.get('tls_anomaly')}")
        print(f"  Replay Indic.:   {event.get('replay_indicator')}")
        print(f"  Source IP:       {event.get('source_ip')} ({event.get('device_id')})")

        # Step 2: Detection via Module 2
        detection_res = detector.analyze_event_composite(
            event,
            session_tracker=session_tracker,
            tls_analyzer=tls_analyzer,
        )

        print("\nSTEP 2: DETECTION & SCORING (Module 2)")
        score_val = detection_res["composite_risk_score"]
        verdict = detection_res["composite_verdict"]
        print(f"  Verdict:         {verdict.upper()}")
        print(f"  Risk Score:      {score_val:.2f} / 1.00 ({int(round(score_val * 100))}/100)")
        print(f"  Explanation:     {detection_res['composite_explanation']}")
        print(f"  Indicators:      {', '.join(detection_res['all_triggered_indicators']) or 'None'}")

        # Step 3: Defense & Hardening via Module 3
        plan = hardening_engine.evaluate_detection(detection_res)

        print("\nSTEP 3: HARDENING & DEFENSE ENGINE (Module 3 - Vaishnavi)")
        print(f"  Assigned Tier:   {plan.input_risk_level.value}")
        print(f"  Status Banner:   {plan.summary_banner}")
        print("\n  Primary Recommendations (for SOC / Dashboard):")
        for rec in plan.primary_recommendations:
            print(f"    [>] {rec}")

        print("\n  Detailed SOC Action Items:")
        for act in plan.detailed_actions:
            print(f"    * [{act.urgency}] {act.title}")
            print(f"      Action:    {act.action}")
            print(f"      Rationale: {act.rationale}")

        print("\n  Signal-Specific Remediations:")
        for rem in plan.signal_specific_remediations:
            print(f"    - {rem}")

        print("\n  Phishing-Resistant Strategy Brief:")
        strat = plan.phishing_resistant_strategy
        print(f"    Standard:  {strat['recommended_authentication_standard']}")
        print(f"    Assurance: {strat['nist_assurance_level']}")
        print(f"    Mechanism: {strat['core_immunity_mechanism']}")
        print()

    print_separator("=")
    print("DEMONSTRATION COMPLETED SUCCESSFULLY")
    print_separator("=")


if __name__ == "__main__":
    run_pipeline()
