"""
Unit tests for Module 3: Hardening Checklist.
Validates machine-readable recommendations, JSON serialization, and filtering.
"""

import json
import unittest
from module3_hardening.models import (
    ChecklistCategory,
    ChecklistPriority,
    HardeningChecklistItem,
)
from module3_hardening.hardening_checklist import HardeningChecklist


class TestHardeningChecklist(unittest.TestCase):
    def setUp(self) -> None:
        self.checklist = HardeningChecklist()

    def test_default_recommendations_match_requirements(self) -> None:
        recs = self.checklist.get_default_recommendations()
        self.assertIsInstance(recs, list)
        self.assertGreaterEqual(len(recs), 5)

        # Check required strings from problem statement
        self.assertIn("Enable FIDO2/passkeys", recs)
        self.assertIn("Prefer phishing-resistant MFA", recs)
        self.assertIn("Monitor unusual authentication sessions", recs)
        self.assertIn("Monitor suspicious redirect behavior", recs)
        self.assertIn("Re-authenticate suspicious sessions", recs)

    def test_filter_by_priority(self) -> None:
        critical_items = self.checklist.get_items_by_priority(ChecklistPriority.CRITICAL)
        self.assertGreater(len(critical_items), 0)
        for item in critical_items:
            self.assertEqual(item.priority, ChecklistPriority.CRITICAL)

    def test_filter_by_category(self) -> None:
        idp_items = self.checklist.get_items_by_category(ChecklistCategory.IDP_POLICY)
        self.assertGreater(len(idp_items), 0)
        for item in idp_items:
            self.assertEqual(item.category, ChecklistCategory.IDP_POLICY)

    def test_json_serialization(self) -> None:
        json_str = self.checklist.to_json()
        parsed = json.loads(json_str)

        self.assertIn("recommendations", parsed)
        self.assertIn("checklist", parsed)
        self.assertIn("standard_references", parsed)
        self.assertGreater(len(parsed["checklist"]), 0)

        first_item = parsed["checklist"][0]
        self.assertIn("id", first_item)
        self.assertIn("title", first_item)
        self.assertIn("priority", first_item)
        self.assertIn("nist_reference", first_item)
        self.assertIn("cisa_guidance", first_item)


if __name__ == "__main__":
    unittest.main()
