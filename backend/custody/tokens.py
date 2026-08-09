"""Access tokens obtained one co-signer round trip per refresh.

Nothing on this box can
produce an access token by itself. Every refresh is:

    read database/<uid>/dek.bin          outer ciphertext, unopenable here
    co-signer unwrap-and-sign            -> inner ciphertext + a DPoP proof
    wrapping.open_dek                    -> the account's data key, briefly
    read database/<uid>/token.bin        the refresh token under that key
    POST oauth2.googleapis.com/token     refresh_token grant + the proof
    zeroize                              and cache only the access token

The data key comes from `keyring.release_for_refresh`, which does not use the
cache the document path uses: a refresh has to cost a round trip, because that
round trip is what puts mail access inside the co-signer's rate limit and its
log.

Google binds a refresh token to a DPoP key at the authorization-code exchange,
and the key is the co-signer's. That is what makes the second barrier permanent
rather than one-shot: a refresh token lifted out of enclave RAM during a
legitimate use is inert without a proof only the co-signer can sign. Issued
access tokens stay Bearer and are not bound, so they are cached for their hour
and no longer.

The nonce round trip is mandatory, not an optimization. Google answers the first
proof with `use_dpop_nonce` and a `DPoP-Nonce` header; the retry with that nonce
in the proof is the request that actually succeeds.
"""

from __future__ import annotations

import datetime
import html
import sys
import threading

import requests

from backend import site
from backend.custody import client as cosigner
from backend.custody import keyring, wrapping
from backend.integrations import telegram
from backend.integrations.gmail_gcal import oauth_app

TOKEN_FILE = "token.bin"

HTTP_TIMEOUT = 30
# Refresh a little before Google would stop accepting it, so a long request
# started on a nearly-expired token does not fail mid-flight.
EXPIRY_MARGIN = datetime.timedelta(seconds=120)

_lock = threading.Lock()
_access_cache = {}
_dpop_nonce = None


# A mailbox with no grant is a standing condition, not an event: the daemon
# wakes on every Gmail push and every 300s besides, and each wake asks again.
# Once a day is enough to be a reminder without becoming noise.
REAUTH_NOTICE_COOLDOWN = 24 * 3600


class ReauthRequired(wrapping.CustodyError):
    """Google refused the refresh grant, or there is no readable token record.
    The user has to consent again; no amount of retrying on this box changes
    that."""

    def __init__(self, uid, detail=""):
        super().__init__(
            f"Gmail access for {uid} is no longer valid; the account must "
            f"re-consent{': ' + detail if detail else ''}"
        )
        self.uid = uid


def log(msg):
    sys.stderr.write(f"tokens {msg}\n")
    sys.stderr.flush()


# --- the record on disk ---------------------------------------------------

def token_path(acct):
    """Where one account's encrypted refresh token lives. Inside the account's
    own directory in the store -- the same root account._owned_paths() reasons
    about, so account.delete_account() removes the token with the rest of what
    that account owns rather than leaving it behind."""
    return keyring.path_for(acct, TOKEN_FILE)


def take_custody(acct, refresh_token):
    """Onboarding: encrypt the refresh token under this account's data key and
    store it. The plaintext token exists only as the argument to this call and is
    never written anywhere.

    The data key is minted on the first consent and reused on every later one.
    That is what makes a re-consent work at all: the co-signer refuses a second
    wrap for an account it has already wrapped, so a design that asked it to wrap
    something new on every sign-in refused every returning user -- and Google
    issues a fresh refresh token on each one, because the consent URL sends
    `prompt=consent`.

    Order matters and is the whole design: ours inside, theirs outside. It is the
    data key that goes through both layers; the token is encrypted under the key,
    the same as every other file this account owns. See
    backend/custody/keyring.py."""
    assert refresh_token, "take_custody needs a refresh token"
    uid, handle = keyring.identify(acct)
    if not keyring.has_key(uid):
        keyring.create(uid, handle)
    return keyring.write_encrypted(acct, TOKEN_FILE, refresh_token, shared=False)


def has_custody(acct):
    return token_path(acct).exists()


def notify_reauth_required(account, log=None):
    """Tell this account, in words, that Letterlock cannot reach their mailbox
    and what to do about it at most once a day."""
    target = getattr(account, "telegram", None)
    sent = telegram.notify_once(
        f"reauth:{account.id}",
        "🔐 <b>Letterlock is not connected to your Gmail</b>\n"
        f"{html.escape(account.id)} "
        "has no active Google grant, so drafting is paused.\n\n"
        f"Sign in to reconnect: {site.app_url('/auth/login')}",
        REAUTH_NOTICE_COOLDOWN,
        target,
    )
    if log is not None:
        log(f"{account.id}: not signed in to Gmail; drafting paused"
            f"{' (notified)' if sent else ''}")
    return sent


def discard(acct):
    """Drop an account's token record. Used when a provision is refused after
    the exchange, so a token we cannot use does not stay on disk.

    The data key stays. It belongs to the account rather than to the token, and
    the documents that account wrote are encrypted under it -- destroying it
    here would make a refused signup take a user's own writing with it."""
    return keyring.clear_encrypted(acct, TOKEN_FILE)


# --- the refresh itself ---------------------------------------------------

def _post_token(form, proof):
    return requests.post(
        oauth_app.TOKEN_ENDPOINT, data=form,
        headers={"DPoP": proof}, timeout=HTTP_TIMEOUT,
    )


def _needs_nonce(resp):
    """Is this the token endpoint asking for a nonce rather than refusing?

    RFC 9449 says `use_dpop_nonce`, and that is what is required here. A server
    that answers some other error while attaching a `DPoP-Nonce` is not asking
    politely for a retry -- it is refusing, and retrying the same request with a
    nonce would hide the refusal behind a second identical failure. The header
    is still captured for the next request either way."""
    if resp.status_code not in (400, 401):
        return False
    try:
        return resp.json().get("error") == "use_dpop_nonce"
    except ValueError:
        return False


def _refusal_detail(resp):
    """What the token endpoint said, including the headers that carry half the
    answer. Google's body for a refused exchange is often `invalid_request` and
    the word "Bad Request", which names nothing; `WWW-Authenticate` and
    `DPoP-Nonce` are what distinguish a rejected proof from a rejected grant,
    and without them a failure like this is diagnosed by guesswork."""
    hints = {name: resp.headers.get(name) for name in
             ("WWW-Authenticate", "DPoP-Nonce", "X-Debug-Tracking-Id")
             if resp.headers.get(name)}
    detail = resp.text[:300]
    return f"{detail} {hints}" if hints else detail


def exchange_with_dpop(form, uid=None, proof=None, sign=None):
    """POST the token endpoint with a DPoP proof, honouring the nonce round trip.

    `sign(nonce)` produces a fresh proof; it is the co-signer either way, but the
    first proof of a refresh arrives bundled with the unwrap and only the retry
    needs a standalone signature. Shared by the refresh grant and the
    authorization-code exchange so the nonce dance is written once."""
    global _dpop_nonce
    assert proof or sign, "exchange_with_dpop needs a proof or a way to sign one"
    if proof is None:
        proof = sign(_dpop_nonce)
    resp = _post_token(form, proof)
    nonce = resp.headers.get("DPoP-Nonce")
    if nonce:
        _dpop_nonce = nonce
    if _needs_nonce(resp):
        assert sign is not None, (
            "Google asked for a DPoP nonce and there is no way to sign a second "
            "proof for this request"
        )
        assert nonce, "Google demanded a DPoP nonce without supplying one"
        resp = _post_token(form, sign(nonce))
        if resp.headers.get("DPoP-Nonce"):
            _dpop_nonce = resp.headers["DPoP-Nonce"]
    if resp.status_code != 200:
        detail = _refusal_detail(resp)
        if "invalid_grant" in detail:
            raise ReauthRequired(uid or form.get("client_id", ""), detail)
        raise wrapping.CustodyError(
            f"token endpoint returned HTTP {resp.status_code} for "
            f"{form.get('grant_type')} with fields {sorted(form)}: {detail}"
        )
    return resp.json()


def _refresh(acct):
    """One full refresh for one account. Returns (access_token, expiry_utc).

    Always goes to the co-signer, never to the data-key cache, and that is
    deliberate. The cache exists so rendering a settings page does not cost a
    round trip; a refresh is the operation the per-account rate limit is
    calibrated on, and serving one from a warm cache would take the co-signer's
    view of how often a mailbox is read and quietly make it a view of how often
    a process restarts."""
    uid, handle = keyring.identify(acct)
    path = token_path(acct)
    if not path.exists():
        raise ReauthRequired(uid, f"no token record at {path}")
    htu, htm = oauth_app.TOKEN_ENDPOINT, "POST"
    try:
        dek, proof = keyring.release_for_refresh(uid, handle, htm, htu, nonce=_dpop_nonce)
    except keyring.NoDataKey as err:
        raise ReauthRequired(uid, str(err)) from err
    try:
        refresh_token = bytearray(
            keyring.decrypt(dek, handle, TOKEN_FILE, path.read_bytes()))
    finally:
        wrapping.zeroize(dek)
    client_id, client_secret = oauth_app.load_keys()
    try:
        payload = exchange_with_dpop(
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token.decode(),
                "client_id": client_id,
                "client_secret": client_secret,
            },
            uid=uid,
            proof=proof,
            sign=lambda nonce: cosigner.sign_dpop(htm, htu, nonce),
        )
    finally:
        wrapping.zeroize(refresh_token)
    access = payload.get("access_token")
    assert access, f"token endpoint returned no access_token for {uid}"
    expires_in = int(payload.get("expires_in", 3600))
    expiry = (datetime.datetime.now(datetime.timezone.utc)
              + datetime.timedelta(seconds=expires_in) - EXPIRY_MARGIN)
    return access, expiry


def access_token_for(account):
    """A usable access token for this account, refreshing only when the cached
    one is spent. Tokens last about an hour and every refresh costs a co-signer
    round trip that the co-signer counts against a rate limit, so caching is
    part of the design rather than a shortcut.

    The lock is held across the refresh, not just around the cache read: two
    threads waking on the same mailbox would otherwise spend two of that
    account's rate-limit budget to end up with the same token.

    Takes an Account and not an id. It used to accept either, and once an
    account is named on this box by its address and off it by an opaque handle,
    a function that accepts a bare string accepts the wrong one of the two --
    which would not fail, it would derive a different key and read as a
    corrupted record."""
    uid = account.id
    now = datetime.datetime.now(datetime.timezone.utc)
    with _lock:
        cached = _access_cache.get(uid)
        if cached and cached[1] > now:
            return cached[0]
        access, expiry = _refresh(account)
        _access_cache[uid] = (access, expiry)
        log(f"{uid}: refreshed access token, valid until {expiry.isoformat()}")
        return access


def refresh_handler_for(account):
    """A google-auth `refresh_handler`: (request, scopes) -> (token, expiry).

    google.oauth2.credentials.Credentials takes this callable and, when it holds
    no refresh token of its own, routes every acquisition through it -- the case
    its own docstring describes as "tokens are obtained by calling some external
    process on demand". That is exactly this design, so the Google client
    library stays stock and split custody sits behind its supported extension
    point rather than beside it.

    google-auth compares expiry against a naive UTC clock, so the aware value
    used everywhere else is stripped here and nowhere else."""
    def handler(request, scopes=None):
        token = access_token_for(account)
        expiry = _access_cache[account.id][1].replace(tzinfo=None)
        return token, expiry
    return handler


def forget(acct=None):
    """Drop what this process cached about an account's custody: the access
    token here and the data key in `keyring`. Called when an account's custody
    changes and by tests; either one would otherwise outlive a re-consent."""
    with _lock:
        if acct is None:
            _access_cache.clear()
        else:
            _access_cache.pop(acct.id, None)
    keyring.forget(None if acct is None else acct.id)
