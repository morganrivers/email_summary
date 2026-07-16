#!/usr/bin/env python3
"""HTTPS webhook receiver for Gmail push notifications.

Port of the former gmail-hook.php. Caddy terminates TLS for the public
hostname and reverse-proxies to this listener on 127.0.0.1:WEBHOOK_PORT.

Google Pub/Sub attaches an OIDC bearer JWT to every push. We verify it via
Google's tokeninfo endpoint (no local crypto), enforcing issuer, audience,
the pushing service account, and expiry, then wake the daemon by writing one
byte to the FIFO. The Pub/Sub message body is irrelevant to processing:
daemon_loop pulls the history delta itself from state.lastHistoryId.
"""

import json
import os
import sys
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).parent
load_dotenv(SCRIPT_DIR / ".env")

FIFO_PATH = SCRIPT_DIR / "wake.fifo"
HOST = os.environ.get("WEBHOOK_HOST", "127.0.0.1")
PORT = int(os.environ.get("WEBHOOK_PORT", "8787"))

EXPECTED_AUD = os.environ.get("WEBHOOK_AUD", "https://hezner.morganrivers.com/")
EXPECTED_ISSUERS = frozenset({"https://accounts.google.com", "accounts.google.com"})
PUBSUB_SERVICE_ACCOUNT = os.environ.get(
    "PUBSUB_SERVICE_ACCOUNT",
    "pubsub-pusher-coastal-mender-4@coastal-mender-462719-q3.iam.gserviceaccount.com",
)
TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo?id_token="


def log(msg):
    sys.stderr.write(f"gmail-hook {msg}\n")
    sys.stderr.flush()


class HookError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code
        self.msg = msg


def verify_jwt(jwt):
    url = TOKENINFO_URL + urllib.parse.quote(jwt, safe="")
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            claims = json.loads(resp.read().decode())
    except urllib.error.HTTPError as err:
        raise HookError(401, f"tokeninfo rejected JWT: {err.code}")
    except Exception as err:
        raise HookError(503, f"tokeninfo network failure: {err}")
    if not isinstance(claims, dict) or "error" in claims:
        raise HookError(401, "tokeninfo rejected JWT")
    if claims.get("iss") not in EXPECTED_ISSUERS:
        raise HookError(401, f"bad iss: {claims.get('iss')}")
    if claims.get("aud") != EXPECTED_AUD:
        raise HookError(401, f"bad aud: {claims.get('aud')}")
    if claims.get("email") != PUBSUB_SERVICE_ACCOUNT:
        raise HookError(401, f"bad email: {claims.get('email')}")
    if str(claims.get("email_verified")).lower() != "true":
        raise HookError(401, "email not verified")
    if int(claims.get("exp", 0)) < time.time():
        raise HookError(401, "token expired")
    return claims


def signal_daemon():
    """Non-blocking FIFO write. If no reader (daemon down), fail soft."""
    try:
        fd = os.open(str(FIFO_PATH), os.O_WRONLY | os.O_NONBLOCK)
    except OSError as err:
        log(f"FIFO open failed (daemon may not be running): {err}")
        return
    try:
        os.write(fd, b"x")
    except OSError as err:
        log(f"FIFO write failed: {err}")
    finally:
        os.close(fd)


class Handler(BaseHTTPRequestHandler):
    def _reject(self, code, msg):
        log(f"reject {code}: {msg}")
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        remote = self.client_address[0]
        log(f"HIT method=POST remote={remote} path={self.path}")
        hdr = self.headers.get("Authorization", "")
        if not hdr.lower().startswith("bearer "):
            return self._reject(401, "Missing Bearer token")
        jwt = hdr[7:].strip()
        try:
            verify_jwt(jwt)
        except HookError as err:
            return self._reject(err.code, err.msg)
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(length)
        log("OK verified, signaling daemon")
        signal_daemon()
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._reject(405, "POST only")

    def log_message(self, *args):
        pass


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    log(f"listening on {HOST}:{PORT}, aud={EXPECTED_AUD}, fifo={FIFO_PATH}")
    server.serve_forever()


if __name__ == "__main__":
    main()
