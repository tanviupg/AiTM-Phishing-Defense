"""
Unit tests for Module 3: Authentication Defense Knowledge Base.
Validates authentication method profiles, ratings, and technical origin-binding explanations.
"""

import unittest
from module3_hardening.models import (
    AuthMethodType,
    AuthResistanceRating,
    AuthMethodProfile,
)
from module3_hardening.auth_defense import AuthDefenseKnowledgeBase


class TestAuthDefenseKnowledgeBase(unittest.TestCase):
    def setUp(self) -> None:
        self.kb = AuthDefenseKnowledgeBase()

    def test_all_expected_methods_profiled(self) -> None:
        profiles = self.kb.get_all_profiles()
        self.assertGreaterEqual(len(profiles), 8)
        method_types = {p.method_type for p in profiles}

        expected = {
            AuthMethodType.PASSWORD_ONLY,
            AuthMethodType.PASSWORD_SMS_OTP,
            AuthMethodType.PASSWORD_EMAIL_OTP,
            AuthMethodType.PASSWORD_TOTP_APP,
            AuthMethodType.CONVENTIONAL_PUSH,
            AuthMethodType.FIDO2_SECURITY_KEY,
            AuthMethodType.PASSKEY_DEVICE_BOUND,
            AuthMethodType.PASSKEY_SYNCED,
            AuthMethodType.TOKEN_BINDING_DPOP,
        }
        self.assertTrue(expected.issubset(method_types))

    def test_phishing_resistant_methods_classification(self) -> None:
        resistant = self.kb.get_phishing_resistant_methods()
        resistant_types = {p.method_type for p in resistant}

        self.assertIn(AuthMethodType.FIDO2_SECURITY_KEY, resistant_types)
        self.assertIn(AuthMethodType.PASSKEY_DEVICE_BOUND, resistant_types)
        self.assertIn(AuthMethodType.PASSKEY_SYNCED, resistant_types)
        self.assertIn(AuthMethodType.TOKEN_BINDING_DPOP, resistant_types)

        for p in resistant:
            self.assertEqual(p.resistance_rating, AuthResistanceRating.PHISHING_RESISTANT)
            self.assertTrue(p.origin_bound)

    def test_vulnerable_methods_classification(self) -> None:
        vulnerable = self.kb.get_vulnerable_methods()
        vulnerable_types = {p.method_type for p in vulnerable}

        self.assertIn(AuthMethodType.PASSWORD_ONLY, vulnerable_types)
        self.assertIn(AuthMethodType.PASSWORD_SMS_OTP, vulnerable_types)
        self.assertIn(AuthMethodType.PASSWORD_EMAIL_OTP, vulnerable_types)
        self.assertIn(AuthMethodType.PASSWORD_TOTP_APP, vulnerable_types)
        self.assertIn(AuthMethodType.CONVENTIONAL_PUSH, vulnerable_types)

        for p in vulnerable:
            self.assertEqual(p.resistance_rating, AuthResistanceRating.VULNERABLE)
            self.assertFalse(p.origin_bound)
            self.assertIsNotNone(p.aitm_failure_mechanism)

    def test_origin_binding_technical_explanation(self) -> None:
        doc = self.kb.explain_origin_binding()
        self.assertIn("title", doc)
        self.assertIn("protocol_breakdown", doc)
        self.assertGreaterEqual(len(doc["protocol_breakdown"]), 4)

        # Check for critical keywords in the explanation
        doc_str = str(doc)
        self.assertIn("clientDataJSON", doc_str)
        self.assertIn("origin", doc_str)
        self.assertIn("rpId", doc_str)
        self.assertIn("SecurityError", doc_str)

    def test_token_binding_technical_explanation(self) -> None:
        doc = self.kb.explain_token_binding()
        self.assertIn("title", doc)
        self.assertIn("mechanisms", doc)
        doc_str = str(doc)
        self.assertIn("DPoP", doc_str)
        self.assertIn("RFC 9449", doc_str)

    def test_profile_to_dict_serialization(self) -> None:
        profile = self.kb.get_profile(AuthMethodType.FIDO2_SECURITY_KEY)
        p_dict = profile.to_dict()
        self.assertEqual(p_dict["method_type"], "FIDO2_SECURITY_KEY")
        self.assertEqual(p_dict["resistance_rating"], "PHISHING_RESISTANT")
        self.assertTrue(p_dict["origin_bound"])


if __name__ == "__main__":
    unittest.main()
