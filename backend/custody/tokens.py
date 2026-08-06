"""Access tokens, obtained the hard way: one co-signer round trip per refresh.

This is the replacement for what google-auth-library used to do internally with
a plaintext refresh token sitting in credentials.json. Nothing on this box can
produce an access token by itself. Every refresh is:

    read database/<uid>/token.bin        outer ciphertext, unopenable here
    co-signer unwrap-and-sign            -> inner ciphertext + a DPoP proof
    wrapping.open_inner                  -> the refresh token, in RAM, briefly
    POST oauth2.googleapis.com/token     refresh_token grant + the proof
    zeroize                              and cache only the access token

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
import sys
import threading

import requests

from backend.accounts import account as account_store
from backend.custody import client as cosigner
from backend.custody import wrapping
from backend.integrations.gmail_gcal import oauth_app

TOKEN_FILE = "token.bin"
RECORD_MAGIC = b"LLTK"
RECORD_VERSION = 1
# magic | record version | key version, and then the ciphertext.
HEADER_LEN = len(RECORD_MAGIC) + 2

HTTP_TIMEOUT = 30
# Refresh a little before Google would stop accepting it, so a long request
# started on a nearly-expired token does not fail mid-flight.
EXPIRY_MARGIN = datetime.timedelta(seconds=120)

_lock = threading.Lock()
_access_cache = {}
_dpop_nonce = None


class BadRecord(wrapping.CustodyError):
    """A stored token record does not decode. Raised by `decode_record` and
    turned into `ReauthRequired` by `load_record`, which is the only caller that
    knows whose record it was."""


class ReauthRequired(wrapping.CustodyError):
    """Google refused the refresh grant. The user has to consent again; no
    amount of retrying on this box changes that."""

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

def check_uid(uid):
    """Refuse a uid that would name a path outside the account's own directory.

    Exported because onboarding has to make the same judgement before it wraps
    anything, and the check was written out twice: once here and once in
    `provisioning.provision`. Two copies of a path-traversal guard is one that
    can be relaxed on its own."""
    assert uid and "/" not in uid and "\\" not in uid and ".." not in uid, (
        f"refusing to build a token path from {uid!r}"
    )
    return uid


def token_path(uid):
    """Where one account's wrapped refresh token lives. Inside the account's own
    directory in the store -- the same root account._owned_paths() reasons
    about, so account.delete_account() removes the token with the rest of what
    that account owns rather than leaving it behind."""
    return account_store.ACCOUNTS_DIR / check_uid(uid) / TOKEN_FILE


def encode_record(key_version, outer):
    """magic | record version | key version | outer ciphertext.

    The key version is outside the ciphertext because it is needed to derive the
    key that opens it. Keeping it here rather than in the manifest means the
    token and the version it was sealed at cannot drift apart."""
    assert 0 <= key_version <= 255, f"key_version {key_version} does not fit a byte"
    assert outer, "encode_record needs an outer ciphertext"
    return RECORD_MAGIC + bytes([RECORD_VERSION, key_version]) + bytes(outer)


def decode_record(blob):
    """The header and the ciphertext, or `BadRecord`.

    A record that does not decode is a fact about a file on disk, not a broken
    invariant: a truncated write, a restored backup, a record from a schema this
    build predates. It is raised rather than asserted so `load_record` can turn
    it into the ReauthRequired it actually means, instead of an IndexError
    surfacing from the middle of a mailbox wake."""
    if len(blob) <= HEADER_LEN:
        raise BadRecord(f"token record is {len(blob)} bytes, too short to hold a header")
    if blob[:4] != RECORD_MAGIC:
        raise BadRecord("not a Letterlock token record")
    record_version, key_version = blob[4], blob[5]
    if record_version != RECORD_VERSION:
        raise BadRecord(f"token record version {record_version} is not {RECORD_VERSION}")
    return key_version, blob[HEADER_LEN:]


def store_record(uid, outer, key_version=wrapping.KEY_VERSION):
    """Write one account's wrapped token. 0600 inside a 0700 directory, same as
    everything else in the store -- though what lands here is useless to anyone
    who reads it without the co-signer."""
    path = token_path(uid)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(encode_record(key_version, outer))
    tmp.chmod(0o600)
    tmp.replace(path)
    return path


def load_record(uid):
    path = token_path(uid)
    if not path.exists():
        raise ReauthRequired(uid, f"no token record at {path}")
    try:
        return decode_record(path.read_bytes())
    except BadRecord as err:
        # Unreadable and unrecoverable are the same thing here: there is no
        # second copy of a refresh token anywhere, so the only way forward is
        # for the user to consent again.
        raise ReauthRequired(uid, f"{path}: {err}") from err


def take_custody(uid, refresh_token):
    """Onboarding: seal under the enclave's key, have the co-signer wrap that,
    and store the result. The plaintext token exists only as the argument to
    this call and is never written anywhere.

    Order matters and is the whole design: ours inside, theirs outside."""
    assert uid and refresh_token, "take_custody needs a uid and a refresh token"
    inner = wrapping.seal_inner(uid, refresh_token)
    outer = cosigner.wrap(uid, inner)
    return store_record(uid, outer)


def has_custody(uid):
    return token_path(uid).exists()


def discard(uid):
    """Drop an account's token record. Used when a provision is refused after
    the exchange, so a token we cannot use does not stay on disk."""
    path = token_path(uid)
    if path.exists():
        path.unlink()


# --- the refresh itself ---------------------------------------------------

def _post_token(form, proof):
    return requests.post(
        oauth_app.TOKEN_ENDPOINT, data=form,
        headers={"DPoP": proof}, timeout=HTTP_TIMEOUT,
    )


def _needs_nonce(resp):
    if resp.status_code not in (400, 401):
        return False
    try:
        return resp.json().get("error") == "use_dpop_nonce"
    except ValueError:
        return False


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
        detail = resp.text[:300]
        if "invalid_grant" in detail:
            raise ReauthRequired(uid or form.get("client_id", ""), detail)
        raise wrapping.CustodyError(
            f"token endpoint returned HTTP {resp.status_code}: {detail}"
        )
    return resp.json()


def _refresh(uid):
    """One full refresh for one account. Returns (access_token, expiry_utc)."""
    key_version, outer = load_record(uid)
    htu, htm = oauth_app.TOKEN_ENDPOINT, "POST"
    inner, proof = cosigner.unwrap_and_sign(uid, outer, htm, htu, nonce=_dpop_nonce)
    refresh_token = wrapping.open_inner(uid, inner, key_version)
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
    account's rate-limit budget to end up with the same token."""
    uid = account.id if hasattr(account, "id") else account
    now = datetime.datetime.now(datetime.timezone.utc)
    with _lock:
        cached = _access_cache.get(uid)
        if cached and cached[1] > now:
            return cached[0]
        access, expiry = _refresh(uid)
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


def forget(uid=None):
    """Drop cached access tokens. Called when an account's custody changes and
    by tests; a stale cached token would otherwise outlive a re-consent."""
    with _lock:
        if uid is None:
            _access_cache.clear()
        else:
            _access_cache.pop(uid, None)
