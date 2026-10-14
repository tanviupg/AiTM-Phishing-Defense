import json
import sys
import unittest
from pathlib import Path

MODULE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MODULE_DIR))

from event_generator import generate_events, OUTPUT_DIR


class TestEventGenerator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        generate_events()
        file_path = OUTPUT_DIR / "sample_events.json"
        cls.events = json.loads(file_path.read_text(encoding="utf-8"))

    def test_two_events_generated(self):
        self.assertEqual(len(self.events), 2)

    def test_required_fields_exist(self):
        required = {
            "session_id", "timestamp", "auth_result",
            "redirect_count", "tls_anomaly",
            "replay_indicator", "scenario"
        }
        for event in self.events:
            self.assertTrue(required.issubset(event.keys()))

    def test_session_ids_are_unique(self):
        ids = [event["session_id"] for event in self.events]
        self.assertEqual(len(ids), len(set(ids)))

    def test_normal_and_suspicious_scenarios_exist(self):
        scenarios = {event["scenario"] for event in self.events}
        self.assertIn("normal", scenarios)
        self.assertIn("suspicious_simulation", scenarios)
    
    def test_events_match_shared_schema(self):
        schema_path = (
            Path(__file__).resolve().parents[2]
            / "integration"
            / "event_schema.json"
        )

        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        required_fields = set(schema["required_fields"])

        for event in self.events:
            self.assertTrue(
                required_fields.issubset(event.keys()),
                f"Event {event.get('session_id')} is missing required fields"
            )
    
    
    def test_invalid_event_is_rejected(self):
        from event_generator import validate_event

        invalid_event = {"session_id": "LAB-003"}

        with self.assertRaises(ValueError):
            validate_event(invalid_event)


if __name__ == "__main__":
    unittest.main()