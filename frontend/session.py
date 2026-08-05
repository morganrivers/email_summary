"""HMAC-signed session cookie helpers (Track U3).

Cookie format: {email}:{iat}:{signature}
where signature = HMAC-SHA256(SESSION_SECRET, "{email}:{iat}").

The session stores the account email. Everything else is looked up via
account.py on each request.
"""

import hashlib
import hmac
import http.cookies
import time

from backend import secrets

SESSION_COOKIE = "letterlock_session"
SESSION_TTL = 86400 * 30

_secret = None


def _get_secret():
    """The signing key, read through backend.secrets so this module never has an
    opinion about where a secret comes from: whether it was injected into an
    attested CVM or read from .env is one question, answered in one place, and
    the boot gate and the deploy preflight ask it about this value too."""
    global _secret
    if _secret is None:
        _secret = secrets.require(secrets.SESSION_SECRET_ENV).encode()
    return _secret


def _sign(email, iat):
    payload = f"{email}:{iat}"
    return hmac.new(_get_secret(), payload.encode(), hashlib.sha256).hexdigest()


def make_cookie(email):
    iat = int(time.time())
    sig = _sign(email, iat)
    value = f"{email}:{iat}:{sig}"
    return (
        f"{SESSION_COOKIE}={value}; HttpOnly; Path=/; Max-Age={SESSION_TTL}; SameSite=Lax; Secure"
    )


def clear_cookie():
    return f"{SESSION_COOKIE}=; Path=/; Max-Age=0"


def get_email(headers):
    raw = headers.get("Cookie", "")
    if not raw:
        return None
    jar = http.cookies.SimpleCookie()
    try:
        jar.load(raw)
    except http.cookies.CookieError:
        return None
    morsel = jar.get(SESSION_COOKIE)
    if not morsel:
        return None
    try:
        parts = morsel.value.split(":")
        if len(parts) < 3:
            return None
        email = ":".join(parts[:-2])
        iat = int(parts[-2])
        sig = parts[-1]
    except (ValueError, IndexError):
        return None
    if int(time.time()) - iat > SESSION_TTL:
        return None
    expected = _sign(email, iat)
    if not hmac.compare_digest(sig, expected):
        return None
    return email
