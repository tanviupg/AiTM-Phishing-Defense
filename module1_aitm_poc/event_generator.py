import json
from datetime import datetime, timezone
from pathlib import Path



OUTPUT_DIR = Path(__file__).parent / "events"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def validate_event(event):
    required_fields = [
        "session_id",
        "timestamp",
        "auth_result",
        "redirect_count",
        "redirect_chain",
        "tls_anomaly",
        "replay_indicator",
        "source_ip",
        "device_id",
        "scenario",
    ]

    for field in required_fields:
        if field not in event:
            raise ValueError(f"Missing required field: {field}")

    if not isinstance(event["redirect_count"], int) or event["redirect_count"] < 0:
        raise ValueError("redirect_count must be a non-negative integer")

    if not isinstance(event["redirect_chain"], list):
        raise ValueError("redirect_chain must be a list")

    if not isinstance(event["tls_anomaly"], bool):
        raise ValueError("tls_anomaly must be true or false")

    if not isinstance(event["replay_indicator"], bool):
        raise ValueError("replay_indicator must be true or false")

    return True


def generate_events():
    timestamp = datetime.now(timezone.utc).isoformat()

    events = [
        {
            "session_id": "LAB-001",
            "timestamp": timestamp,
            "auth_result": "success",
            "redirect_count": 1,
            "redirect_chain": ["lab-idp.local"],
            "tls_anomaly": False,
            "replay_indicator": False,
            "source_ip": "192.0.2.10",
            "device_id": "DEVICE-A",
            "scenario": "normal"
        },
        {
            "session_id": "LAB-002",
            "timestamp": timestamp,
            "auth_result": "success",
            "redirect_count": 4,
            "redirect_chain": [
                "lab-login.local",
                "proxy-simulation.local",
                "lab-idp.local",
                "lab-login.local"
            ],
            "tls_anomaly": True,
            "replay_indicator": True,
            "source_ip": "198.51.100.20",
            "device_id": "DEVICE-B",
            "scenario": "suspicious_simulation"
        }
    ]

    for event in events:
            validate_event(event)

    output_file = OUTPUT_DIR / "sample_events.json"
    output_file.write_text(json.dumps(events, indent=2), encoding="utf-8")



    print(f"Generated {len(events)} synthetic events.")
    print(f"Saved to: {output_file}")


if __name__ == "__main__":
    generate_events()