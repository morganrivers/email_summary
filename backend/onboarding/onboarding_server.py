"""Sign-in-with-Google onboarding web flow (Track C1).

A minimal HTTP server, same shape as gmail_hook_server.py / billing_webhook.py:
a loopback listener that Caddy terminates TLS for and reverse-proxies. It is the
"webapp = auth, not a wizard" surface from the plan -- one button, one Google
consent, then hand off to Polar checkout.

Flow:
  GET /onboard          landing page, single "Connect your Gmail" button.
  GET /oauth/start      mint a CSRF state token (set as a cookie), ask
                        oauth_helper.mjs for the Google consent URL, 302 there.
  GET /oauth/callback   verify the returned state against the cookie, exchange
                        the one-time code via oauth_helper.mjs (writes the
                        per-user creds dir), register the account
                        (account.register_account -> inactive until paid),
                        register its Gmail watch (watch_renew.renew_account),
                        then 302 to Polar checkout.
  GET /onboard/success  post-checkout "you're connected" stub.

All Google/OAuth concerns live in Node (oauth_helper.mjs / gmail_lib.mjs); all
account + state writes live in Python (account.py / state.py). This server only
orchestrates and never constructs a token/creds path itself beyond the
per-user creds dir it hands to the helper.

Token-custody note (plan "token-custody subtlety at code exchange"): the refresh
token is written to the per-user creds dir in the clear here, exactly as the
pre-TEE single-tenant box already stores it. Sealing that write to the enclave
key is Track F, not C.
"""

import http.cookies
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
from hmac import compare_digest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from dotenv import load_dotenv

from backend import paths
from backend.accounts import account
from backend.onboarding import watch_renew

load_dotenv(paths.ENV_FILE)

OAUTH_HELPER = paths.node_script("oauth_helper.mjs")

HOST = os.environ.get("ONBOARD_HOST", "127.0.0.1")
PORT = int(os.environ.get("ONBOARD_PORT", "8789"))
REDIRECT_URI = os.environ.get(
    "GMAIL_OAUTH_REDIRECT_URI", "https://hezner.morganrivers.com/oauth/callback"
)
POLAR_CHECKOUT_URL = os.environ.get("POLAR_CHECKOUT_URL", "")
STATE_COOKIE = "onboard_state"
STATE_TTL = 600

LANDING_HTML = b"""<!doctype html>
<html><head><meta charset="utf-8"><title>Connect your Gmail</title></head>
<body style="font-family:sans-serif;max-width:32rem;margin:6rem auto;text-align:center">
<h1>Private email assistant</h1>
<p>Drafts replies without your raw email ever reaching the model.</p>
<p><a href="/oauth/start"
   style="display:inline-block;padding:.75rem 1.5rem;background:#1a73e8;color:#fff;
          border-radius:.375rem;text-decoration:none">Connect your Gmail</a></p>
</body></html>
"""

SUCCESS_HTML = b"""<!doctype html>
<html><head><meta charset="utf-8"><title>You're connected</title></head>
<body style="font-family:sans-serif;max-width:32rem;margin:6rem auto;text-align:center">
<h1>You're connected</h1>
<p>We'll email you in your own inbox to learn your writing voice.</p>
</body></html>
"""


def log(msg):
    sys.stderr.write(f"onboarding {msg}\n")
    sys.stderr.flush()


class OnboardError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code
        self.msg = msg


def _run_helper(args):
    """Run oauth_helper.mjs, returning its stdout. Raises OnboardError(502) on a
    non-zero exit so a Google/helper failure surfaces as a bad-gateway, not a 500."""
    result = subprocess.run(
        ["node", str(OAUTH_HELPER), *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
    )
    if result.returncode != 0:
        raise OnboardError(502, f"oauth_helper {args[0]} failed: {result.stderr.decode().strip()}")
    return result.stdout.decode()


def build_auth_url(state):
    out = _run_helper(["auth-url", "--state", state, "--redirect", REDIRECT_URI])
    return out.strip()


def exchange_code(code, creds_dir):
    out = _run_helper([
        "exchange", "--code", code, "--redirect", REDIRECT_URI,
        "--creds-dir", str(creds_dir),
    ])
    return json.loads(out)


def checkout_redirect(email):
    """Where to send the user after a successful connect. Polar hosted checkout
    when configured (carrying customer_email so the order.paid webhook resolves
    to this account), else the local success stub."""
    if not POLAR_CHECKOUT_URL:
        return "/onboard/success"
    sep = "&" if "?" in POLAR_CHECKOUT_URL else "?"
    return f"{POLAR_CHECKOUT_URL}{sep}customer_email={urllib.parse.quote(email)}"


def provision(code):
    """Exchange the code and stand up the account: write the per-user creds dir,
    register the account (inactive), and register its Gmail watch. Returns the
    account. The creds land in a staging dir first because the owning email is
    only known after the exchange; they are then moved under the final per-user
    path recorded in the manifest."""
    account.ACCOUNTS_DIR.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(dir=account.ACCOUNTS_DIR, prefix=".staging-"))
    try:
        profile = exchange_code(code, staging)
        email = profile["email"]
        creds_abs = account.ACCOUNTS_DIR / email / ".gmail-mcp"
        creds_rel = creds_abs.relative_to(paths.REPO_ROOT)
        creds_abs.mkdir(parents=True, exist_ok=True)
        for name in ("gcp-oauth.keys.json", "credentials.json"):
            shutil.move(str(staging / name), str(creds_abs / name))
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    acct = account.register_account(email, profile["first"], profile["last"], str(creds_rel))
    watch_renew.renew_account(acct, log=lambda m: log(m))
    log(f"provisioned account {acct.id}")
    return acct


def handle_callback(query, cookie_state):
    """Pure decision path for /oauth/callback, shared by do_GET and the tests.
    Returns the redirect location. Raises OnboardError on any failure."""
    err = query.get("error")
    if err:
        raise OnboardError(400, f"consent denied: {err}")
    code = query.get("code")
    state = query.get("state")
    if not code or not state:
        raise OnboardError(400, "missing code or state")
    if not cookie_state or not compare_digest(state, cookie_state):
        raise OnboardError(403, "state mismatch (possible CSRF)")
    acct = provision(code)
    return checkout_redirect(acct.id)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body=b"", ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _redirect(self, location, extra=None):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()

    def _cookie_state(self):
        raw = self.headers.get("Cookie", "")
        if not raw:
            return None
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(raw)
        except http.cookies.CookieError:
            return None
        morsel = jar.get(STATE_COOKIE)
        return morsel.value if morsel else None

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path in ("/", "/onboard"):
            return self._send(200, LANDING_HTML)
        if path == "/onboard/success":
            return self._send(200, SUCCESS_HTML)
        if path == "/oauth/start":
            state = secrets.token_urlsafe(24)
            try:
                url = build_auth_url(state)
            except OnboardError as e:
                log(f"start failed: {e.msg}")
                return self._send(e.code, b"onboarding unavailable")
            cookie = (f"{STATE_COOKIE}={state}; HttpOnly; Path=/; Max-Age={STATE_TTL}; "
                      f"SameSite=Lax; Secure")
            return self._redirect(url, extra=[("Set-Cookie", cookie)])
        if path == "/oauth/callback":
            query = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
            try:
                location = handle_callback(query, self._cookie_state())
            except OnboardError as e:
                log(f"callback rejected {e.code}: {e.msg}")
                return self._send(e.code, e.msg.encode())
            except Exception as e:
                log(f"callback error: {e}")
                return self._send(500, b"onboarding failed")
            clear = f"{STATE_COOKIE}=; Path=/; Max-Age=0"
            return self._redirect(location, extra=[("Set-Cookie", clear)])
        return self._send(404, b"not found")

    def log_message(self, *args):
        pass


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    log(f"listening on {HOST}:{PORT}, redirect_uri={REDIRECT_URI}")
    server.serve_forever()


if __name__ == "__main__":
    main()
