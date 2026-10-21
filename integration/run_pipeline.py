import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
EVENTS_FILE = ROOT_DIR / "module1_aitm_poc" / "events" / "sample_events.json"
SCHEMA_FILE = ROOT_DIR / "integration" / "event_schema.json"

sys.path.insert(0, str(ROOT_DIR / "module1_aitm_poc"))
from event_generator import validate_event


def validate_against_schema(event, schema):
    validate_event(event)

    for field in schema["required_fields"]:
        if field not in event:
            raise ValueError(f"Missing required field: {field}")

    if not isinstance(event["session_id"], str):
        raise ValueError("session_id must be a string")

    if not isinstance(event["redirect_chain"], list):
        raise ValueError("redirect_chain must be a list")

    if not all(isinstance(host, str) for host in event["redirect_chain"]):
        raise ValueError("redirect_chain must contain only strings")

    if event["scenario"] not in schema["scenarios"]:
        raise ValueError(f"Unknown scenario: {event['scenario']}")

    return True


def main():
    if not EVENTS_FILE.exists():
        raise FileNotFoundError(
            f"Events file not found: {EVENTS_FILE}\n"
            "Run event_generator.py first."
        )

    with SCHEMA_FILE.open(encoding="utf-8") as file:
        schema = json.load(file)

    with EVENTS_FILE.open(encoding="utf-8") as file:
        events = json.load(file)

    if not isinstance(events, list):
        raise ValueError("The events file must contain a JSON list")

    print(f"Loaded {len(events)} synthetic events.")

    for event in events:
        validate_against_schema(event, schema)
        print(
            f"VALID | {event['session_id']} | "
            f"scenario={event['scenario']}"
        )

    print("Pipeline input validation completed successfully.")
    print("Events are ready for the detection module.")


if __name__ == "__main__":
    main()
