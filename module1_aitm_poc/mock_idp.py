"""
Safe Local Test Identity Provider (IdP) for AiTM Lab Simulation.
Runs on http://127.0.0.1:5001.

Simulates an enterprise Single Sign-On (SSO) login flow:
- Authenticates test user (alice@lab.local / Password123!)
- Challenges for MFA OTP (123456)
- Issues genuine HTTP session cookie (session_token=...)
- Supports administrative session revocation (simulated containment).
"""

import http.server
import json
import secrets
import sys
import urllib.parse
from http.cookies import SimpleCookie
from typing import Any, Optional

IDP_PORT = 5001
TEST_USER = "alice@lab.local"
TEST_PASS = "Password123!"
TEST_OTP = "123456"

# In-memory session store: session_id -> { username, created_at, active }
ACTIVE_SESSIONS: dict[str, dict[str, Any]] = {}
PENDING_MFA: dict[str, str] = {}  # mfa_state -> username


def create_session(username: str) -> str:
    token = f"LAB_AUTH_SESSION_{secrets.token_hex(16)}"
    ACTIVE_SESSIONS[token] = {
        "username": username,
        "active": True,
        "token": token,
    }
    return token


def is_valid_session(token: str) -> bool:
    sess = ACTIVE_SESSIONS.get(token)
    return bool(sess and sess.get("active", False))


def revoke_session(token: str) -> bool:
    if token in ACTIVE_SESSIONS:
        ACTIVE_SESSIONS[token]["active"] = False
        return True
    return False


HTML_LOGIN = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Corporate Identity Provider - Sign In</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0B0F19; color: #F3F4F6; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { background: #111827; border: 1px solid #1F2937; border-radius: 10px; padding: 2rem; width: 360px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
    h2 { margin-top: 0; font-size: 1.25rem; color: #06B6D4; display: flex; align-items: center; gap: 0.5rem; }
    .badge { font-size: 0.65rem; background: #1E293B; border: 1px solid #334155; padding: 0.15rem 0.4rem; border-radius: 4px; color: #94A3B8; text-transform: uppercase; }
    input { width: 100%; box-sizing: border-box; background: #030712; border: 1px solid #374151; color: #fff; padding: 0.65rem; border-radius: 6px; margin: 0.5rem 0 1rem; }
    button { width: 100%; background: #0284C7; color: #fff; border: none; padding: 0.75rem; border-radius: 6px; font-weight: 600; cursor: pointer; }
    button:hover { background: #0369A1; }
    .note { font-size: 0.75rem; color: #9CA3AF; margin-top: 1rem; border-top: 1px solid #1F2937; padding-top: 0.75rem; }
    .error { color: #EF4444; font-size: 0.8rem; margin-bottom: 0.5rem; }
  </style>
</head>
<body>
  <div class="card">
    <h2><span>🛡️</span> Lab Identity Provider <span class="badge">Port 5001</span></h2>
    <p style="font-size: 0.85rem; color: #9CA3AF;">Authorized Enterprise Test Environment</p>
    __ERROR__
    <form method="POST" action="/login">
      <label style="font-size: 0.8rem;">Email address</label>
      <input type="email" name="username" value="alice@lab.local" required>
      <label style="font-size: 0.8rem;">Password</label>
      <input type="password" name="password" value="Password123!" required>
      <button type="submit">Sign In</button>
    </form>
    <div class="note">
      <strong>Lab Test Account:</strong> alice@lab.local / Password123!<br>
      Notice: This is a safe local authentication endpoint for AiTM demonstration.
    </div>
  </div>
</body>
</html>
"""

HTML_MFA = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Identity Provider - MFA Verification</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0B0F19; color: #F3F4F6; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { background: #111827; border: 1px solid #1F2937; border-radius: 10px; padding: 2rem; width: 360px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
    h2 { margin-top: 0; font-size: 1.25rem; color: #F59E0B; }
    input { width: 100%; box-sizing: border-box; background: #030712; border: 1px solid #374151; color: #fff; padding: 0.65rem; border-radius: 6px; margin: 0.5rem 0 1rem; text-align: center; letter-spacing: 0.2em; font-size: 1.25rem; font-family: monospace; }
    button { width: 100%; background: #D97706; color: #fff; border: none; padding: 0.75rem; border-radius: 6px; font-weight: 600; cursor: pointer; }
    .note { font-size: 0.75rem; color: #9CA3AF; margin-top: 1rem; }
    .error { color: #EF4444; font-size: 0.8rem; margin-bottom: 0.5rem; }
  </style>
</head>
<body>
  <div class="card">
    <h2>🔐 Two-Factor Authentication</h2>
    <p style="font-size: 0.85rem; color: #9CA3AF;">Enter the 6-digit verification code from your authenticator app.</p>
    __ERROR__
    <form method="POST" action="/mfa">
      <input type="hidden" name="state" value="__STATE__">
      <input type="text" name="otp" placeholder="123456" maxlength="6" value="123456" required autofocus>
      <button type="submit">Verify Code</button>
    </form>
    <div class="note">Lab OTP code is: <strong>123456</strong></div>
  </div>
</body>
</html>
"""

HTML_PORTAL = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Enterprise Portal - Authenticated Session</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0B0F19; color: #F3F4F6; margin: 0; padding: 2rem; }
    .container { max-width: 800px; margin: 0 auto; background: #111827; border: 1px solid #1F2937; border-radius: 12px; padding: 2rem; }
    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1F2937; padding-bottom: 1rem; margin-bottom: 1.5rem; }
    .badge { background: rgba(16, 185, 129, 0.2); border: 1px solid #10B981; color: #10B981; padding: 0.3rem 0.8rem; border-radius: 9999px; font-size: 0.8rem; font-weight: 700; }
    .token-box { background: #030712; border: 1px solid #374151; padding: 1rem; border-radius: 8px; font-family: monospace; font-size: 0.85rem; word-break: break-all; color: #06B6D4; margin: 1rem 0; }
    button { background: #EF4444; color: #fff; border: none; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; font-weight: 600; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h2 style="margin: 0; color: #F3F4F6;">🏢 Enterprise Cloud Portal</h2>
        <span style="font-size: 0.8rem; color: #9CA3AF;">Authenticated User: __USER__</span>
      </div>
      <span class="badge">ACTIVE SESSION</span>
    </div>
    <p>You have successfully authenticated through Single Sign-On.</p>
    <div style="font-size: 0.85rem; color: #9CA3AF;">Active Session Cookie (Bearer Token):</div>
    <div class="token-box">__TOKEN__</div>
    <p style="font-size: 0.8rem; color: #9CA3AF;">
      ⚠️ In an Adversary-in-the-Middle attack, if this login traversed an unauthorized reverse proxy,
      the proxy server has captured this exact token and can now access this portal without knowing your password!
    </p>
    <form method="POST" action="/logout">
      <button type="submit">Sign Out</button>
    </form>
  </div>
</body>
</html>
"""


class MockIdPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/login"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_LOGIN.replace("__ERROR__", "").encode("utf-8"))

        elif path == "/portal":
            token = self._extract_session_cookie()
            if not token or not is_valid_session(token):
                self.send_response(401)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                content = "<h2>401 Unauthorized</h2><p>Invalid or revoked session token. Authentication required.</p><a href='/login'>Return to Login</a>"
                self.wfile.write(content.encode("utf-8"))
                return

            sess = ACTIVE_SESSIONS[token]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            html = HTML_PORTAL.replace("__USER__", sess["username"]).replace("__TOKEN__", token)
            self.wfile.write(html.encode("utf-8"))

        elif path == "/api/active_sessions":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(ACTIVE_SESSIONS).encode("utf-8"))

        elif path == "/api/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "running", "idp_port": IDP_PORT}).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        params = urllib.parse.parse_qs(body)

        if path == "/login":
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]

            if username == TEST_USER and password == TEST_PASS:
                state = secrets.token_hex(8)
                PENDING_MFA[state] = username
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                html = HTML_MFA.replace("__STATE__", state).replace("__ERROR__", "")
                self.wfile.write(html.encode("utf-8"))
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                err = "<div class='error'>Invalid credentials. Use alice@lab.local / Password123!</div>"
                self.wfile.write(HTML_LOGIN.replace("__ERROR__", err).encode("utf-8"))

        elif path == "/mfa":
            state = params.get("state", [""])[0]
            otp = params.get("otp", [""])[0]

            if state in PENDING_MFA and otp == TEST_OTP:
                username = PENDING_MFA.pop(state)
                session_token = create_session(username)

                # Set session cookie on IdP domain
                self.send_response(303)
                self.send_header("Location", "/portal")
                self.send_header(
                    "Set-Cookie",
                    f"session_token={session_token}; Path=/; HttpOnly; SameSite=Lax",
                )
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                err = "<div class='error'>Invalid OTP code. Use 123456</div>"
                self.wfile.write(HTML_MFA.replace("__STATE__", state).replace("__ERROR__", err).encode("utf-8"))

        elif path == "/logout":
            token = self._extract_session_cookie()
            if token:
                revoke_session(token)
            self.send_response(303)
            self.send_header("Location", "/login")
            self.send_header("Set-Cookie", "session_token=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
            self.end_headers()

        elif path == "/api/revoke_session":
            # Administrative API for simulated containment
            token = params.get("token", [""])[0]
            if not token:
                # Try JSON body
                try:
                    data = json.loads(body)
                    token = data.get("token", "")
                except Exception:
                    pass

            success = revoke_session(token)
            self.send_response(200 if success else 404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"revoked": success, "token": token}).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def _extract_session_cookie(self) -> Optional[str]:
        raw_cookie = self.headers.get("Cookie")
        if not raw_cookie:
            return None
        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookie)
            if "session_token" in cookie:
                return cookie["session_token"].value
        except Exception:
            pass
        return None

    def log_message(self, format: str, *args: Any) -> None:
        # Clean custom logging
        sys.stderr.write(f"[Mock IdP:5001] {self.address_string()} - {format % args}\n")


def run_idp(host: str = "127.0.0.1", port: int = IDP_PORT) -> None:
    server = http.server.ThreadingHTTPServer((host, port), MockIdPHandler)
    print(f"[*] Safe Test Identity Provider running at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down Test IdP...")
        server.server_close()


if __name__ == "__main__":
    run_idp()
