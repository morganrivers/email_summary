"""HMAC-signed cookies: the session, and the OAuth state (Track U3).

Both are `{kid}:{value}:{iat}:{signature}`, where the signature is
HMAC-SHA256(key, "{purpose}:{kid}:{value}:{iat}"). The purpose is inside the
signed string, so a value minted for one cookie cannot be presented as the
other even though one key signs both.

The `kid` names which key signed it, so more than one key can be live at once
and verification still has exactly one key to try. That is what makes
SESSION_SECRET rotatable: the outgoing value moves to
SESSION_SECRET_PREVIOUS, the new one mints from then on, and nobody is signed
out at the moment of the restart. Without it, rotation logs every user out
simultaneously, which is why it would never be done.

The session stores the account email. Everything else is looked up via
account.py on each request.

The state is here rather than in web_server because it is the same question --
did this box mint this, and how long ago -- and the answer should not be
written twice. Unlike the session, the cookie holds several at once: a browser
with two sign-in tabs open has two pending consents, and a single slot meant
the second tab silently invalidated the first.
"""

import hashlib
import hmac
import http.cookies
import itertools
import secrets as secrets_mod
import time

from backend import secrets

SESSION_COOKIE = "letterlock_session"
SESSION_TTL = 86400 * 30

SESSION_PURPOSE = "session"
STATE_PURPOSE = "oauth-state"

# A consent round trip: account chooser, scope screen, possibly a password and
# a second factor. Ten minutes was short enough that a slow sign-in came back
# to "state mismatch (possible CSRF)", which reads as an attack and is not one.
STATE_TTL = 1800

# The current key first, then the outgoing one. Verification accepts both;
# only the first ever signs. Both names are owned by backend/secrets.py, so
# this module still has no opinion about where a secret comes from: whether it
# was injected into an attested CVM or read from .env is one question, answered
# in one place, and the boot gate and the deploy preflight ask it about the
# current key too.
KEY_ENVS = (secrets.SESSION_SECRET_ENV, secrets.SESSION_SECRET_PREVIOUS_ENV)

_keys = None


def _kid(key):
    """A key's short label, cut from `secrets.fingerprint` so the kid in a
    cookie and the fingerprint in the startup line name the same key: read one
    off a browser and the other out of the journal and you can say which key
    signed a session without either place holding the key.

    The algorithm prefix is dropped because `:` separates the cookie's fields.
    Publishing a digest of the key is not a new exposure: every cookie already
    carries an HMAC over plaintext the holder can see, so an offline guess at a
    weak key was already checkable."""
    algo, _, digest = secrets.fingerprint(key).partition(":")
    assert digest and ":" not in digest, f"{algo} label is unusable as a kid"
    return digest


def _keyring():
    """Every key a cookie may be signed under, current first, each with its kid.

    Read once per process, like every other secret here. A previous key is
    accepted only if it is actually a different value, so a copy-paste that
    leaves both variables equal is one key rather than two."""
    global _keys
    if _keys is None:
        current = secrets.require(secrets.SESSION_SECRET_ENV).encode()
        previous = (secrets.get(secrets.SESSION_SECRET_PREVIOUS_ENV) or "").encode()
        live = [current] + ([previous] if previous and previous != current else [])
        _keys = tuple((_kid(key), key) for key in live)
        assert len({kid for kid, _ in _keys}) == len(_keys), \
            "two signing keys share a key id"
    return _keys


def _key_for(kid):
    """The key a cookie names, or None if it names one this process does not
    hold -- an unknown kid is the ordinary shape of a session signed under a
    key that has since been retired.

    Every key is compared even after a match, so the work does not depend on
    which key was named or on whether one was."""
    found = None
    for known, key in _keyring():
        if hmac.compare_digest(known, kid):
            found = key
    return found


def _mac(key, purpose, payload):
    """HMAC over one value, for one purpose, under one key.

    The purpose is inside the signed string rather than beside it, so a value
    minted as one kind of token cannot be presented as the other: the same key
    signs both a session and an OAuth state, and both are
    `<kid>:<value>:<iat>:<sig>` on the wire. Without domain separation an
    emailless session cookie and a state would be interchangeable to the
    verifier. The kid is signed too, so which key was meant is not something a
    holder can edit."""
    if not key:
        # An empty key is a MAC anyone can compute, so every cookie this
        # process minted or verified under one would be forgeable. Raised and
        # not asserted because the key comes from the environment.
        raise RuntimeError("_mac needs a key")
    return hmac.new(key, f"{purpose}:{payload}".encode(),
                    hashlib.sha256).hexdigest()


def _signed(purpose, value, iat):
    """`value` signed under the current key. Nothing mints under a previous
    one: it exists to finish out the sessions it already signed."""
    kid, key = _keyring()[0]
    payload = f"{kid}:{value}:{iat}"
    return f"{payload}:{_mac(key, purpose, payload)}"


def _open_signed(purpose, raw, ttl):
    """The value out of a `<kid>:<value>:<iat>:<sig>` string, or None if it is
    not one we signed or is older than `ttl`.

    An unknown kid is refused by the same comparison a bad signature is, not by
    an early return, so a probe cannot learn which key ids this process holds by
    timing the answer."""
    if not raw:
        return None
    try:
        parts = raw.split(":")
        if len(parts) < 4:
            return None
        kid = parts[0]
        value = ":".join(parts[1:-2])
        iat = int(parts[-2])
        sig = parts[-1]
    except (ValueError, IndexError):
        return None
    if int(time.time()) - iat > ttl:
        return None
    key = _key_for(kid)
    signed = hmac.compare_digest(
        sig, _mac(key or _keyring()[0][1], purpose, f"{kid}:{value}:{iat}"))
    if key is None or not signed:
        return None
    return value


def describe_keys():
    """Which signing keys this process captured, for the startup line.

    A service reads its secrets once and never rereads them, so a `.env` edited
    under a running web server is invisible until something downstream breaks --
    here, that break is every user being signed out. Printing the pair says
    which keys are live, and the kid in any cookie is the digest half of one of
    these, so an unexpected sign-out is diagnosable from a log line and a
    browser."""
    captured = [key for _, key in _keyring()]
    assert len(captured) <= len(KEY_ENVS), "more keys than names for them"
    return " ".join(
        f"{name}={secrets.fingerprint(key)}"
        for name, key in itertools.zip_longest(KEY_ENVS, captured))


def make_cookie(email):
    value = _signed(SESSION_PURPOSE, email, int(time.time()))
    return (
        f"{SESSION_COOKIE}={value}; HttpOnly; Path=/; Max-Age={SESSION_TTL}; SameSite=Lax; Secure"
    )


def clear_cookie():
    return f"{SESSION_COOKIE}=; Path=/; Max-Age=0"


def _cookie_value(headers, name):
    raw = headers.get("Cookie", "")
    if not raw:
        return None
    jar = http.cookies.SimpleCookie()
    try:
        jar.load(raw)
    except http.cookies.CookieError:
        return None
    morsel = jar.get(name)
    return morsel.value if morsel else None


def get_email(headers):
    return _open_signed(SESSION_PURPOSE, _cookie_value(headers, SESSION_COOKIE),
                        SESSION_TTL)


# --- the OAuth state ------------------------------------------------------
#
# The state is signed the way the session is, with the same keyring and the
# same `<kid>:<value>:<iat>:<sig>` shape, because it answers the same question:
# did this box mint this, and how long ago. What it adds is room for more than
# one at a time. A single-slot cookie meant a second sign-in tab overwrote the
# first tab's state, so finishing the older consent failed as "state mismatch
# (possible CSRF)" -- an alarming way to say the user opened two tabs.
#
# It inherits rotation from that shape, and needs to: a restart lands in the
# middle of somebody's consent round trip, and a state minted seconds before it
# must still come back as ours rather than as the same CSRF alarm.
#
# Each state is still verified individually, so accepting several does not
# weaken the check: an attacker who cannot sign one cannot sign any of the
# three.

STATE_COOKIE = "letterlock_oauth_state"
STATE_SEPARATOR = "|"
# Enough for a couple of stray tabs, few enough that the cookie stays small and
# an old state ages out rather than lingering behind a wall of newer ones.
MAX_PENDING_STATES = 3


def new_state():
    """A fresh state value, signed and ready for both the URL and the cookie."""
    return _signed(STATE_PURPOSE, secrets_mod.token_urlsafe(24), int(time.time()))


def state_cookie(state, headers=None):
    """The Set-Cookie carrying `state` plus whatever earlier states are still
    live, newest first. Pass the request headers so a second tab adds to the
    list rather than evicting what the first tab is waiting on."""
    assert state, "state_cookie needs a state"
    pending = [state] + [s for s in _pending_states(headers) if s != state]
    value = STATE_SEPARATOR.join(pending[:MAX_PENDING_STATES])
    return (f"{STATE_COOKIE}={value}; HttpOnly; Path=/; "
            f"Max-Age={STATE_TTL}; SameSite=Lax; Secure")


def clear_state_cookie():
    return f"{STATE_COOKIE}=; Path=/; Max-Age=0"


def _pending_states(headers):
    """The still-valid states in the cookie. Anything expired or unsigned by us
    is dropped here rather than compared against, so a stale cookie cannot keep
    a value alive past its TTL."""
    if headers is None:
        return []
    raw = _cookie_value(headers, STATE_COOKIE) or ""
    live = []
    for candidate in raw.split(STATE_SEPARATOR):
        if candidate and _open_signed(STATE_PURPOSE, candidate, STATE_TTL):
            live.append(candidate)
    return live


def state_is_ours(state, headers):
    """Is this callback's state one we minted, still within its TTL, and still
    pending in this browser? All three, in that order."""
    if not state or not _open_signed(STATE_PURPOSE, state, STATE_TTL):
        return False
    return any(hmac.compare_digest(state, known)
               for known in _pending_states(headers))
