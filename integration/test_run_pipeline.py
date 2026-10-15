import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
PIPELINE_FILE = ROOT_DIR / "integration" / "run_pipeline.py"
EVENTS_FILE = (
    ROOT_DIR / "module1_aitm_poc" / "events" / "sample_events.json"
)


class TestIntegrationPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        subprocess.run(
            [
                sys.executable,
                str(ROOT_DIR / "module1_aitm_poc" / "event_generator.py"),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_pipeline_accepts_valid_events(self):
        result = subprocess.run(
            [sys.executable, str(PIPELINE_FILE)],
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VALID | LAB-001", result.stdout)
        self.assertIn("VALID | LAB-002", result.stdout)
        self.assertIn(
            "Pipeline input validation completed successfully.",
            result.stdout,
        )

    def test_pipeline_rejects_unknown_scenario(self):
        original_content = EVENTS_FILE.read_text(encoding="utf-8")

        try:
            events = json.loads(original_content)
            events[0]["scenario"] = "unknown_scenario"
            EVENTS_FILE.write_text(json.dumps(events, indent=2), encoding="utf-8")

            result = subprocess.run(
                [sys.executable, str(PIPELINE_FILE)],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Unknown scenario", result.stderr)

        finally:
            EVENTS_FILE.write_text(original_content, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()

