"""
Standalone launcher for Module 4 SOC Dashboard & User-Training Module.
Runs on http://127.0.0.1:8004 by default.
"""

import argparse
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Module 4 SOC Dashboard & Training Platform")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8004, help="Bind port (default: 8004)")
    args = parser.parse_args()

    try:
        import uvicorn
    except ImportError:
        print("Error: uvicorn is required. Run: pip install fastapi uvicorn pytest")
        sys.exit(1)

    print(f"Starting Module 4 SOC Dashboard at http://{args.host}:{args.port}")
    uvicorn.run("module4_soc_dashboard.backend.app:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
