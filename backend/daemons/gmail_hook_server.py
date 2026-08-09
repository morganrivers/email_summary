#!/usr/bin/env python3
"""HTTPS webhook receiver for Gmail push notifications.

Port of the former gmail-hook.php. Caddy terminates TLS for the public
hostname and reverse-proxies to this listener on 127.0.0.1:WEBHOOK_PORT.

Google Pub/Sub attaches an OIDC bearer JWT to every push. We verify it via
Google's tokeninfo endpoint (no local crypto), enforcing issuer, audience,
the pushing service account, and expiry.

The endpoint is public, so the claims are screened locally before that network
call: anything whose payload does not already carry the right issuer, audience,
service account, and an unexpired exp is rejected without touching Google. Only
a token that could plausibly be genuine costs a request, which is what stops an
anonymous flood from turning into an outbound flood and getting us throttled
(and the real pushes rejected with it). Verified tokens are cached until they
expire so Pub/Sub's own retries cost nothing either. We then decode the message body
({emailAddress, historyId}), enqueue that address on the wake spool, and poke the
FIFO so the daemon processes only that user's mailbox. The historyId is not
used: the daemon pulls the delta from that account's stored lastHistoryId
cursor (single source of truth). emailAddress is trusted only because the JWT
proves the push came from Google.

This process does not resolve the address, and that is deliberate rather than
an omission. Resolving it means reading `database/accounts.json`, which is
every user's address and whether they are paid up, and this is a program that
verifies a signature and appends a line. It runs under its own account with no
read access to the store (deploy/hetzner/email-webhook.service.d), so an
unregistered address is dropped by the daemon on the next drain instead of
here. The cost is one wake for an address nobody registered, which the daemon
already handles: it logs and moves on.
"""

import base64
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from backend import paths, secrets, site
from backend.daemons import wake_queue

secrets.load()

FIFO_PATH = paths.RUN_DIR / "wake.fifo"
HOST = os.environ.get("WEBHOOK_HOST", "127.0.0.1")
PORT = int(os.environ.get("WEBHOOK_PORT", str(site.GMAIL_PUSH_PORT)))

EXPECTED_AUD = os.environ.get("WEBHOOK_AUD", site.pubsub_audience())
EXPECTED_ISSUERS = frozenset({"https://accounts.google.com", "accounts.google.com"})
PUBSUB_SERVICE_ACCOUNT = os.environ.get(
    "PUBSUB_SERVICE_ACCOUNT",
    "pubsub-pusher-coastal-mender-4@coastal-mender-462719-q3.iam.gserviceaccount.com",
)
TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo?id_token="

# A Pub/Sub push envelope is a few kilobytes. Reading an attacker-declared
# Content-Length unbounded is a free way to make us allocate.
MAX_BODY = 256 * 1024


def log(msg):
    sys.stderr.write(f"gmail-hook {msg}\n")
    sys.stderr.flush()


class HookError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code
        self.msg = msg


# jwt -> exp, for tokens tokeninfo has already vouched for. Pub/Sub retries the
# same token on any non-2xx, and a token is good for an hour.
_VERIFIED = {}
_VERIFIED_MAX = 512


def check_claims(claims):
    """Every claim rule, in one place, so the local screen and the verified
    response are judged identically. Returns None or the reason to reject."""
    if not isinstance(claims, dict) or "error" in claims:
        return "malformed claims"
    if claims.get("iss") not in EXPECTED_ISSUERS:
        return f"bad iss: {claims.get('iss')}"
    if claims.get("aud") != EXPECTED_AUD:
        return f"bad aud: {claims.get('aud')}"
    if claims.get("email") != PUBSUB_SERVICE_ACCOUNT:
        return f"bad email: {claims.get('email')}"
    if str(claims.get("email_verified")).lower() != "true":
        return "email not verified"
    try:
        exp = int(claims.get("exp", 0))
    except (TypeError, ValueError):
        return "bad exp"
    if exp < time.time():
        return "token expired"
    return None


def peek_claims(jwt):
    """The JWT's payload without verifying its signature. Only ever used to
    reject early: a forged payload still has to survive tokeninfo afterwards."""
    parts = jwt.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload).decode())
    except Exception:
        return None


def _cache_verified(jwt, claims):
    if len(_VERIFIED) >= _VERIFIED_MAX:
        now = time.time()
        for token, exp in list(_VERIFIED.items()):
            if exp < now:
                del _VERIFIED[token]
        if len(_VERIFIED) >= _VERIFIED_MAX:
            _VERIFIED.clear()
    _VERIFIED[jwt] = int(claims.get("exp", 0))


def verify_jwt(jwt):
    cached_exp = _VERIFIED.get(jwt)
    if cached_exp is not None:
        if cached_exp > time.time():
            return {"cached": True}
        del _VERIFIED[jwt]

    # Cheap screen first: no network for anything that cannot be genuine.
    reason = check_claims(peek_claims(jwt))
    if reason is not None:
        raise HookError(401, f"rejected before tokeninfo ({reason})")

    url = TOKENINFO_URL + urllib.parse.quote(jwt, safe="")
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            claims = json.loads(resp.read().decode())
    except urllib.error.HTTPError as err:
        raise HookError(401, f"tokeninfo rejected JWT: {err.code}")
    except Exception as err:
        raise HookError(503, f"tokeninfo network failure: {err}")
    reason = check_claims(claims)
    if reason is not None:
        raise HookError(401, reason)
    _cache_verified(jwt, claims)
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


def route_push(body):
    """Spool the address a verified push names and wake the daemon for it.

    Whether that address belongs to anyone is the daemon's question, not this
    process's: see the module docstring. An unparseable body falls back to a
    full sweep so no mail is silently lost."""
    try:
        envelope = json.loads(body)
        data = base64.b64decode(envelope["message"]["data"])
        email = json.loads(data)["emailAddress"]
    except Exception as err:
        log(f"unparseable push body ({err}); waking full sweep as fallback")
        signal_daemon()
        return
    assert email, "verified push carried no emailAddress"
    wake_queue.enqueue(email)
    log("queued push and signaling daemon")
    signal_daemon()


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
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            return self._reject(400, "bad Content-Length")
        if length < 0 or length > MAX_BODY:
            return self._reject(413, f"body too large ({length} bytes)")
        body = self.rfile.read(length) if length else b""
        log("OK verified, routing push")
        route_push(body)
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
