"""
End-to-End Live Lab Test & Industrial Workflow Demonstration.
Demonstrates:
Generate events (Live Proxy) -> Detect suspicious activity (M2) -> Explain risk ->
Recommend defenses (M3) -> Display alerts -> Verify simulated containment.
"""

import http.client
import json
import threading
import time
import unittest
import urllib.parse
import urllib.request
from pathlib import Path

from module1_aitm_poc.mock_idp import run_idp, revoke_session, is_valid_session
from module1_aitm_poc.lab_proxy import run_proxy, INTERCEPTED_LOOT
from module2_detection.detector import AiTMDetector
from module3_hardening.recommendation_engine import HardeningEngine
from module3_hardening.models import RiskLevel


class TestLiveLabPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Start Mock IdP on port 5001 in daemon thread
        cls.idp_thread = threading.Thread(target=run_idp, kwargs={"port": 5001}, daemon=True)
        cls.idp_thread.start()

        # Start Lab Proxy on port 5002 in daemon thread
        cls.proxy_thread = threading.Thread(target=run_proxy, kwargs={"port": 5002}, daemon=True)
        cls.proxy_thread.start()

        time.sleep(1.0)  # Allow sockets to bind

    def test_complete_aitm_workflow_and_containment(self) -> None:
        print("\n" + "=" * 80)
        print("STAGE 1: SIMULATE VICTIM LOGIN THROUGH PROXY (Port 5002)")
        print("=" * 80)

        # 1. Step 1: User visits login page via proxy
        login_url = "http://127.0.0.1:5002/login"
        req = urllib.request.Request(login_url)
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode("utf-8")
            self.assertIn("AiTM REVERSE PROXY SIMULATION ACTIVE", content)
            self.assertIn("Lab Identity Provider", content)
            print("[+] Victim accessed login page through reverse proxy.")

        # 2. Step 2: User submits credentials to proxy
        login_data = urllib.parse.urlencode({
            "username": "alice@lab.local",
            "password": "Password123!",
        }).encode("utf-8")

        post_req = urllib.request.Request(login_url, data=login_data, method="POST")
        with urllib.request.urlopen(post_req) as resp:
            mfa_page = resp.read().decode("utf-8")
            self.assertIn("Two-Factor Authentication", mfa_page)
            print("[+] Credentials relayed to IdP. Proxy intercepted credentials and received MFA challenge.")

        # Extract MFA state token from form
        state_marker = 'name="state" value="'
        state_idx = mfa_page.find(state_marker) + len(state_marker)
        mfa_state = mfa_page[state_idx:mfa_page.find('"', state_idx)]

        # 3. Step 3: User submits MFA OTP to proxy
        mfa_data = urllib.parse.urlencode({
            "state": mfa_state,
            "otp": "123456",
        }).encode("utf-8")

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(NoRedirect)
        mfa_req = urllib.request.Request("http://127.0.0.1:5002/mfa", data=mfa_data, method="POST")

        try:
            mfa_resp = opener.open(mfa_req)
        except urllib.error.HTTPError as e:
            mfa_resp = e

        # Check that proxy intercepted the Set-Cookie
        self.assertGreaterEqual(len(INTERCEPTED_LOOT), 1)
        latest_loot = INTERCEPTED_LOOT[-1]
        stolen_token = latest_loot["stolen_token_value"]
        self.assertTrue(stolen_token.startswith("LAB_AUTH_SESSION_"))
        print(f"[+] PROXY STOLE TOKEN: {stolen_token}")

        # Verify stolen token works against genuine IdP on port 5001
        portal_req = urllib.request.Request("http://127.0.0.1:5001/portal")
        portal_req.add_header("Cookie", f"session_token={stolen_token}")
        with urllib.request.urlopen(portal_req) as portal_resp:
            portal_html = portal_resp.read().decode("utf-8")
            self.assertIn("ACTIVE SESSION", portal_html)
            self.assertIn("Enterprise Cloud Portal", portal_html)
            print("[+] Token Replay Verified: Attacker successfully accessed portal using stolen cookie!")

        # 4. Step 4: DETECTION (Module 2 - Devyani)
        print("\n" + "=" * 80)
        print("STAGE 2: RUN DETECTION ENGINE (Module 2)")
        print("=" * 80)

        live_event_path = Path(__file__).parent / "events" / "live_intercepted_event.json"
        self.assertTrue(live_event_path.exists())
        with open(live_event_path, "r", encoding="utf-8") as f:
            live_event = json.load(f)

        detector = AiTMDetector()
        detection_result = detector.analyze_event_composite(live_event)
        self.assertEqual(detection_result["composite_verdict"], "suspicious")
        self.assertGreaterEqual(detection_result["composite_risk_score"], 0.50)
        print(f"[+] Detection Verdict: {detection_result['composite_verdict'].upper()}")
        print(f"[+] Composite Risk Score: {detection_result['composite_risk_score']} / 1.00")
        print(f"[+] Indicators: {detection_result['all_triggered_indicators']}")

        # 5. Step 5: HARDENING & DEFENSE (Module 3 - Vaishnavi)
        print("\n" + "=" * 80)
        print("STAGE 3: GENERATE HARDENING & CONTAINMENT PLAYBOOK (Module 3)")
        print("=" * 80)

        engine = HardeningEngine()
        hardening_plan = engine.evaluate_detection(detection_result)
        self.assertEqual(hardening_plan.input_risk_level, RiskLevel.HIGH)
        print(f"[+] Hardening Tier: {hardening_plan.input_risk_level.value}")
        print(f"[+] Recommendations: {hardening_plan.primary_recommendations}")

        # 6. Step 6: SIMULATED CONTAINMENT VERIFICATION
        print("\n" + "=" * 80)
        print("STAGE 4: EXECUTE & VERIFY SIMULATED CONTAINMENT")
        print("=" * 80)

        # Simulate SOC executing containment: Revoke session token in IdP
        revoke_data = urllib.parse.urlencode({"token": stolen_token}).encode("utf-8")
        revoke_req = urllib.request.Request("http://127.0.0.1:5001/api/revoke_session", data=revoke_data, method="POST")
        with urllib.request.urlopen(revoke_req) as rev_resp:
            rev_data = json.loads(rev_resp.read().decode("utf-8"))
            self.assertTrue(rev_data["revoked"])
            print(f"[+] Containment Action Executed: Session token '{stolen_token}' revoked in IdP.")

        # Test replay again with the revoked token: MUST BE 401 UNAUTHORIZED
        try:
            with urllib.request.urlopen(portal_req) as portal_resp2:
                self.fail("Expected 401 Unauthorized after session revocation")
        except urllib.error.HTTPError as err:
            self.assertEqual(err.code, 401)
            print("[+] CONTAINMENT VERIFIED: Attacker replayed token rejected with HTTP 401 Unauthorized!")

        print("\n" + "=" * 80)
        print("COMPLETE INDUSTRIAL WORKFLOW VERIFIED SUCCESSFULLY!")
        print("=" * 80 + "\n")


if __name__ == "__main__":
    unittest.main()
