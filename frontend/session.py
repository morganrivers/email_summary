"""HMAC-signed cookies: the session, the OAuth state and the Polar checkout
(Track U3).

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


# --- the anti-CSRF token --------------------------------------------------
#
# Defence in depth behind SameSite=Lax, not a replacement for it. The cookie
# attribute is what keeps the session cookie off a cross-site POST, and it is
# the primary defence; this is the synchroniser token that still stands if that
# attribute is ever dropped, relaxed to SameSite=None, or a mutating action is
# moved onto a request shape a Lax cookie does follow.
#
# It is signed from the same keyring as the session, with its own purpose and
# bound to the signed-in account, so a token minted for one account cannot
# authorise a POST for another. Rotating the secret does not invalidate the
# tokens on pages already open, for the same reason a session survives a
# rotation, and a restart mid-form does not reject the next save.

CSRF_PURPOSE = "csrf"


def csrf_token(account_id):
    """A fresh anti-CSRF token bound to the signed-in account, for a form.

    The account id, not the address: every caller passes `acct.id`, and the two
    are not the same thing anywhere else in this tree -- an account names
    several addresses. They were consistent here because the check reads back
    whatever the mint wrote, so the name was the only thing wrong with it."""
    assert account_id, "csrf_token needs the signed-in account id"
    return _signed(CSRF_PURPOSE, account_id, int(time.time()))


def csrf_ok(token, account_id):
    """Whether `token` is one we minted for this signed-in account and is still
    within the session TTL. Bound to the account, so knowing the shape of a
    token is not enough to post as another one."""
    if not token or not account_id:
        return False
    signed = _open_signed(CSRF_PURPOSE, token, SESSION_TTL)
    return signed is not None and hmac.compare_digest(signed, account_id)


# --- cookies holding several pending values at once -----------------------
#
# Two round trips need the same thing: this browser started something, went to
# a third party, and came back naming it. The OAuth consent is one, the Polar
# checkout is the other, and both need room for more than one at a time -- a
# single slot meant a second sign-in tab overwrote the first tab's state, so
# finishing the older consent failed as "state mismatch (possible CSRF)", an
# alarming way to say the user opened two tabs.
#
# Each entry is signed the way the session is, with the same keyring and the
# same `<kid>:<value>:<iat>:<sig>` shape, because it answers the same question:
# did this box mint this, and how long ago. It inherits rotation from that
# shape, and needs to: a restart lands in the middle of somebody's consent round
# trip, and a value minted seconds before it must still come back as ours rather
# than as the same CSRF alarm. Each entry is verified individually, so accepting
# several does not weaken the check -- an attacker who cannot sign one cannot
# sign any of the three.

SEPARATOR = "|"
# Enough for a couple of stray tabs, few enough that the cookie stays small and
# an old entry ages out rather than lingering behind a wall of newer ones.
MAX_PENDING = 3


class PendingValues:
    """One cookie holding up to `MAX_PENDING` signed values, newest first.

    Parsing, expiry, the cap and the Set-Cookie rendering live here once. What
    a caller compares against an entry does not, because the two users differ:
    the OAuth state travels in the URL already signed, so it is compared as the
    whole string, while a Polar checkout id arrives raw and is compared against
    the value inside an entry."""

    def __init__(self, cookie, purpose, ttl):
        self.cookie = cookie
        self.purpose = purpose
        self.ttl = ttl

    def live(self, headers):
        """The still-valid entries. Anything expired or unsigned by us is
        dropped here rather than compared against, so a stale cookie cannot keep
        a value alive past its TTL."""
        if headers is None:
            return []
        raw = _cookie_value(headers, self.cookie) or ""
        return [c for c in raw.split(SEPARATOR)
                if c and _open_signed(self.purpose, c, self.ttl)]

    def _render(self, pending):
        value = SEPARATOR.join(pending[:MAX_PENDING])
        return (f"{self.cookie}={value}; HttpOnly; Path=/; "
                f"Max-Age={self.ttl}; SameSite=Lax; Secure")

    def sign(self, value):
        """`value` as an entry. The separator would split one entry into two, so
        a value carrying it is refused rather than mangled."""
        assert value and SEPARATOR not in str(value), \
            f"{self.purpose} value is unusable in a cookie: {value!r}"
        return _signed(self.purpose, value, int(time.time()))

    def with_entry(self, entry, headers=None):
        """The Set-Cookie carrying `entry` plus whatever earlier ones are still
        live. Pass the request headers so a second tab adds to the list rather
        than evicting what the first tab is waiting on."""
        assert entry, "with_entry needs an entry"
        return self._render([entry] + [e for e in self.live(headers) if e != entry])

    def without(self, entry, headers=None):
        """The Set-Cookie with `entry` removed and the rest left pending.

        This is what makes a value one-shot. Membership alone left it valid for
        the remainder of its TTL on every path that did not clear the whole
        cookie, so a refused callback left a reusable token behind -- and the
        PKCE verifier is a deterministic function of the state, which makes
        state reuse verifier reuse."""
        return self._render([e for e in self.live(headers) if e != entry])

    def clear(self):
        return f"{self.cookie}=; Path=/; Max-Age=0"


# --- the OAuth state ------------------------------------------------------

STATE_COOKIE = "letterlock_oauth_state"
_STATES = PendingValues(STATE_COOKIE, STATE_PURPOSE, STATE_TTL)


def new_state():
    """A fresh state value, signed and ready for both the URL and the cookie."""
    return _STATES.sign(secrets_mod.token_urlsafe(24))


def state_cookie(state, headers=None):
    return _STATES.with_entry(state, headers)


def state_cookie_without(state, headers=None):
    """The Set-Cookie that consumes `state`. Every /auth/callback response sets
    one, refusals included: a callback that failed must not leave its state
    usable for the remaining half hour."""
    return _STATES.without(state, headers)


def clear_state_cookie():
    return _STATES.clear()


def state_is_ours(state, headers):
    """Is this callback's state one we minted, still within its TTL, and still
    pending in this browser? All three, in that order."""
    if not state or not _open_signed(STATE_PURPOSE, state, STATE_TTL):
        return False
    return any(hmac.compare_digest(state, known)
               for known in _STATES.live(headers))


# --- the Polar checkout ---------------------------------------------------
#
# `/billing/return` is a GET whose `checkout_id` comes out of a query string the
# browser controls, and SameSite=Lax sends the session cookie on a cross-site
# top-level navigation, so an attacker-supplied link fires that handler with the
# victim's session. The metadata stamp answers "does this checkout belong to
# this account"; this answers the stronger question, "did this browser start
# it", which is the binding a return trip actually calls for.
#
# Longer-lived than the OAuth state because a checkout is: card details, a bank
# app, a 3-D Secure round trip. A buyer who exceeds it, or who pays in a
# different browser, is not refused anything they bought -- the reconcile and
# the webhook still settle them, and the return page already says the flip may
# still be in flight.

CHECKOUT_COOKIE = "letterlock_checkout"
CHECKOUT_PURPOSE = "checkout"
CHECKOUT_TTL = 3600
_CHECKOUTS = PendingValues(CHECKOUT_COOKIE, CHECKOUT_PURPOSE, CHECKOUT_TTL)


def checkout_cookie(checkout_id, headers=None):
    """The Set-Cookie recording that this browser minted `checkout_id`."""
    return _CHECKOUTS.with_entry(_CHECKOUTS.sign(checkout_id), headers)


def checkout_is_ours(checkout_id, headers):
    """Did this browser start this checkout? Compared against the value inside
    each pending entry, because Polar hands the id back raw."""
    if not checkout_id:
        return False
    return any(hmac.compare_digest(_open_signed(CHECKOUT_PURPOSE, e, CHECKOUT_TTL) or "",
                                   checkout_id)
               for e in _CHECKOUTS.live(headers))


def checkout_cookie_without(checkout_id, headers=None):
    """The Set-Cookie that consumes `checkout_id`, so a return trip is one-shot
    the way a consent callback is."""
    for entry in _CHECKOUTS.live(headers):
        if _open_signed(CHECKOUT_PURPOSE, entry, CHECKOUT_TTL) == checkout_id:
            return _CHECKOUTS.without(entry, headers)
    return None
