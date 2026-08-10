#!/usr/bin/env python3
"""HTTPS webhook receiver for Gmail push notifications.

Port of the former gmail-hook.php. Caddy terminates TLS for the public
hostname and reverse-proxies to this listener on 127.0.0.1:WEBHOOK_PORT.

Google Pub/Sub attaches an OIDC bearer JWT to every push. We verify its RS256
signature locally against Google's published certificates
(``google.auth.jwt.decode``, which also enforces ``iat``/``exp`` and rejects any
algorithm but RS256/ES256, so neither ``none`` nor an HMAC substitution is
reachable), then apply ``check_claims`` -- issuer, audience, the pushing service
account, and that the address on the token is a verified one.

This used to be a call to Google's ``tokeninfo`` endpoint, which is a debugging
aid rather than a validator, and it made verifying a token a network round trip:
one outbound request per distinct token, so an anonymous flood at a public
endpoint turned into an outbound flood. Two mitigations existed only because of
that -- an unverified pre-screen of the JWT payload, and a cache of tokens
tokeninfo had vouched for -- and both are gone with it. The one thing fetched
now is the certificate set, cached for the lifetime the certs endpoint states,
so a forged token costs a signature check and no network at all.

The pre-screen also made ``check_claims`` judge two different wire formats,
since tokeninfo returns every claim as a string where the JWT payload carries
JSON types, and the coercions that straddled them (``str(...).lower() ==
"true"``, ``int(claims.get("exp", 0))``) were weaker than either format needed.
It now sees signature-verified JSON and compares exactly.

We then decode the message body
({emailAddress, historyId}), enqueue that address on the wake spool, and poke the
FIFO so the daemon processes only that user's mailbox. The historyId is not
used: the daemon pulls the delta from that account's stored lastHistoryId
cursor (single source of truth). emailAddress is trusted only because the JWT
proves the push came from Google.

The token is a bearer credential and there is deliberately no replay cache. It
carries no ``jti``, it lives about an hour, and Pub/Sub mints one and reuses it
across many pushes inside that window -- so refusing a second use of the same
token would refuse nearly every push after the first. Anything that captures one
can therefore drive wakes for the rest of that hour, and the only place to close
that is where TLS is terminated. On the box that is Caddy on loopback. In the
enclave the compose file publishes this port in plaintext and something outside
the containers terminates it, which has to be settled before the hook role is
published: either a TLS listener in this container holding a certificate the
enclave derives, or a written acknowledgement that the push address list is
visible to the gateway operator. What a captured token buys is bounded by
`route_push` refusing a body it cannot parse rather than escalating to a sweep.

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
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from google.auth import exceptions as google_auth_exceptions
from google.auth import jwt as google_jwt

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
CERTS_URL = "https://www.googleapis.com/oauth2/v1/certs"
CLOCK_SKEW_SECONDS = 30
CERTS_TTL_MIN = 300
CERTS_TTL_MAX = 6 * 3600
CERTS_REFETCH_FLOOR = 60

assert EXPECTED_AUD.startswith("https://"), f"aud is not a URL: {EXPECTED_AUD!r}"
assert PUBSUB_SERVICE_ACCOUNT.endswith(
    ".gserviceaccount.com"
), f"pusher is not a service account: {PUBSUB_SERVICE_ACCOUNT!r}"

# A Pub/Sub push envelope is a few kilobytes. Reading an attacker-declared
# Content-Length unbounded is a free way to make us allocate.
MAX_BODY = 256 * 1024

# An unauthenticated caller decides the request path and the bytes of a parse
# error, and both reach the journal. One line in means one line out.
MAX_LOG = 500


def log(msg):
    line = str(msg).replace("\r", " ").replace("\n", " ")[:MAX_LOG]
    sys.stderr.write(f"gmail-hook {line}\n")
    sys.stderr.flush()


class HookError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code
        self.msg = msg


def check_claims(claims):
    """Every identity rule for a push token, in one place. Returns None or the
    reason to reject.

    What it does *not* cover is what `google.auth.jwt.decode` owns and owns
    better: the signature, the algorithm, and the `iat`/`exp` window. This
    function only ever sees a payload that has already survived those, which is
    why each comparison here can be exact rather than coercing. `aud` is stated
    here as well as passed to `decode`; both read the one constant, and an
    audience rule written in only one of them is one a refactor can drop.

    `email_verified` must be the JSON boolean. A string "true" would mean the
    payload is not the shape a Google ID token has, and accepting both spellings
    is how the old tokeninfo-era check came to accept `str(None).lower()`
    reasoning about a claim that was absent."""
    if not isinstance(claims, dict):
        return f"claims are {type(claims).__name__}, not an object"
    if claims.get("iss") not in EXPECTED_ISSUERS:
        return f"bad iss: {claims.get('iss')!r}"
    if claims.get("aud") != EXPECTED_AUD:
        return f"bad aud: {claims.get('aud')!r}"
    if claims.get("email") != PUBSUB_SERVICE_ACCOUNT:
        return f"bad email: {claims.get('email')!r}"
    if claims.get("email_verified") is not True:
        return f"email not verified: {claims.get('email_verified')!r}"
    return None


class SigningCerts:
    """Google's OIDC signing certificates, cached for the lifetime the certs
    endpoint states.

    The cache is what keeps verification off the network: without it a forged
    token costs an outbound request, which is the amplification the old
    unverified pre-screen existed to blunt.

    A key id the cached set does not name is the one case worth a refetch, since
    it is what a rotation looks like from here. That is also the one case an
    anonymous caller can trigger at will, so it is rate limited to one fetch per
    CERTS_REFETCH_FLOOR and a failed refetch leaves the unexpired set in place;
    an *expired* set that cannot be refreshed is an error, because serving stale
    keys forever is how a revoked key stays trusted."""

    def __init__(self):
        self._lock = threading.Lock()
        self._certs = {}
        self._fetched = 0.0
        self._expires = 0.0

    def for_kid(self, kid):
        with self._lock:
            now = time.time()
            if now >= self._expires:
                self._refresh(now)
            elif self._may_refetch(kid, now):
                try:
                    self._refresh(now)
                except Exception as err:
                    log(f"signing-cert refetch for unknown kid failed: {err}")
            assert self._certs, "no signing certificates after refresh"
            return self._certs

    def _may_refetch(self, kid, now):
        if kid is None or kid in self._certs:
            return False
        return now - self._fetched >= CERTS_REFETCH_FLOOR

    def _refresh(self, now):
        certs, ttl = download_certs()
        self._certs = certs
        self._fetched = now
        self._expires = now + ttl


def download_certs():
    """The certificate set and how long Google says it is good for."""
    with urllib.request.urlopen(CERTS_URL, timeout=5) as resp:  # nosec B310  # constant https URL
        body = resp.read()
        ttl = cache_lifetime(resp.headers.get("Cache-Control", ""))
    certs = json.loads(body.decode())
    assert isinstance(certs, dict) and certs, f"certs endpoint returned {certs!r}"
    return certs, ttl


def cache_lifetime(header):
    """Google's stated max-age, clamped. The floor stops a max-age of zero from
    making every verification a fetch; the ceiling stops a long one from
    outliving a revocation by more than a few hours."""
    for part in header.split(","):
        name, _, value = part.strip().partition("=")
        if name.lower() == "max-age" and value.isdigit():
            return min(max(int(value), CERTS_TTL_MIN), CERTS_TTL_MAX)
    return CERTS_TTL_MIN


_CERTS = SigningCerts()


def verify_jwt(token):
    """Verify a push token and return its claims, or raise HookError.

    401 is the verdict on the token, 503 is our own inability to reach a
    verdict, and the split matters: Pub/Sub retries a 503 and drops a 401."""
    assert isinstance(token, str), f"token is {type(token).__name__}"
    try:
        kid = google_jwt.decode_header(token).get("kid")
    except Exception as err:
        raise HookError(401, f"unparseable JWT header: {err}")
    try:
        certs = _CERTS.for_kid(kid)
    except Exception as err:
        raise HookError(503, f"signing certificates unavailable: {err}")
    try:
        claims = google_jwt.decode(
            token,
            certs=certs,
            audience=EXPECTED_AUD,
            clock_skew_in_seconds=CLOCK_SKEW_SECONDS,
        )
    except (google_auth_exceptions.GoogleAuthError, ValueError, TypeError) as err:
        raise HookError(401, f"JWT rejected: {err}")
    reason = check_claims(claims)
    if reason is not None:
        raise HookError(401, reason)
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
    process's: see the module docstring. An unparseable body is refused and
    nothing is woken.

    That used to fall back to an address-less wake, which the daemon reads as
    "process every account". A genuine Google push is never unparseable, so the
    branch was reachable only by something already holding a valid Pub/Sub OIDC
    token -- but that token is a bearer credential with no `jti`, no replay
    cache and roughly an hour of life, so anything that captures one can drive
    repeated full sweeps. A sweep spends one co-signer unwrap-and-sign per
    account, which is precisely what `cosigner.policy._sweep_refusal` exists to
    refuse, and its refusal stops mail for everyone until an operator clears it.
    A fallback that exists so one mail is not lost could stop all mail."""
    try:
        envelope = json.loads(body)
        data = base64.b64decode(envelope["message"]["data"])
        email = json.loads(data)["emailAddress"]
    except Exception as err:
        raise HookError(400, f"verified push body does not parse: {err}")
    if not email:
        raise HookError(400, "verified push carried no emailAddress")
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
        token = hdr[7:].strip()
        try:
            verify_jwt(token)
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
        try:
            route_push(body)
        except HookError as err:
            # A verified push that names no mailbox we can route: the body did
            # not parse, or parsed and carried no address. Answered rather than
            # left to escape the handler, so Pub/Sub gets a status instead of a
            # closed connection and retries a body that will never improve.
            return self._reject(err.code, err.msg)
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
