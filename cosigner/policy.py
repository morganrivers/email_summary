"""What the co-signer will do, how often, and for whom.

This is the number that bounds a live enclave breach. Nothing stops an attacker
who owns the enclave from asking for one mailbox at a time -- the enclave is
what talks to Google, so a refresh token has to exist in its RAM at the moment
of use. What is available is the rate: set the aggregate ceiling low enough
that draining the user base takes longer than noticing it (plan §0).

Every decision in the service goes through `authorize()`, and it is also the
only place a row is written for one. The count-then-log pair happens under one
lock, so two concurrent unwraps cannot both read "59 used" and both proceed,
and the number the limiter enforced is the number the log shows.

`allowed_target()` is the other half. The co-signer signs DPoP proofs, and a
proof covers `htm`, `htu`, `iat`, `jti`, `nonce` -- no token material, which is
what makes "compromising this box yields a signing key that signs no secrets"
true. It stays true only while the target is fixed: an enclave-side attacker
who can name the URI has a signing oracle for any endpoint that accepts DPoP.
It applies to `/sign-dpop` exactly as it does to `/unwrap-and-sign`; that
endpoint has no uid to meter, so its ceiling and the fixed target are the whole
of what bounds it.
"""

import os
import threading
import time
from collections import namedtuple

from cosigner import alerts
from cosigner import audit
from cosigner import protocol

ACTION_WRAP = "wrap"
ACTION_UNWRAP = "unwrap-and-sign"
ACTION_SIGN = "sign-dpop"

ACTIONS = (ACTION_WRAP, ACTION_UNWRAP, ACTION_SIGN)

# Why a request was refused, in a form the HTTP layer can turn into a status
# code without pattern-matching on prose.
Refusal = namedtuple("Refusal", "kind reason")

KIND_DISABLED = "disabled"
KIND_ATTESTATION = "attestation"
KIND_REQUEST = "request"
KIND_RATE = "rate"

WINDOW_SECONDS = 3600

DEFAULT_PER_USER_HOUR = 60
DEFAULT_TOTAL_HOUR = 200

# `/sign-dpop` carries no uid, so the per-user limit cannot reach it and this
# ceiling is the only thing bounding it. Without one it is the unmetered path
# around the metered one: an enclave-side attacker skips `/unwrap-and-sign`,
# uses a refresh token they already lifted, and asks here for the proof that
# makes it work. The legitimate pattern is at most one retry proof per unwrap
# plus onboarding, so the default matches the unwrap ceiling rather than
# doubling it.
DEFAULT_SIGN_HOUR = DEFAULT_TOTAL_HOUR

# One alert per reason per interval. A breach produces the same refusal over
# and over, and a Telegram channel that gets a thousand of them is a channel
# the operator mutes.
ALERT_INTERVAL = 300

_LOCK = threading.Lock()
_LAST_ALERT = {}


def kill_switch_path():
    return audit.state_dir() / "DISABLED"


def disabled_reason():
    """The kill switch. A file rather than only an env var, so an operator who
    suspects a breach stops every unwrap on the box without a restart -- and
    stopping it is safe by construction, because the enclave fails closed."""
    if os.environ.get("COSIGNER_DISABLED", "").strip() in ("1", "true", "yes"):
        return "co-signer disabled by COSIGNER_DISABLED"
    if kill_switch_path().exists():
        return f"co-signer disabled by kill switch at {kill_switch_path()}"
    return None


def _limit(name, default):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    value = int(raw)
    assert value > 0, f"{name} must be positive, got {value}"
    return value


def per_user_limit():
    """A mailbox wake needs one unwrap; the access token it yields is good for
    about an hour and is cached in-process by the enclave."""
    return _limit("COSIGNER_RATE_PER_USER_HOUR", DEFAULT_PER_USER_HOUR)


def total_limit():
    return _limit("COSIGNER_RATE_TOTAL_HOUR", DEFAULT_TOTAL_HOUR)


def sign_limit():
    return _limit("COSIGNER_RATE_SIGN_HOUR", DEFAULT_SIGN_HOUR)


def allowed_target(htm, htu):
    """None when this is a proof the co-signer is willing to sign."""
    if htm != "POST":
        return f"refusing to sign a proof for method {htm!r}"
    if htu != protocol.TOKEN_ENDPOINT:
        return f"refusing to sign a proof for {htu!r}"
    return None


def _wrap_once_refusal(uid):
    """A second wrap for a uid that already has one is either a bug or an
    attacker asking us to re-wrap something, so it is refused rather than
    served: the enclave's stored `outer` stays the only one that exists
    (invariant 4).

    It is decided here rather than by the caller because it is a read of the
    audit log followed by a write to it, and only this module holds the lock
    that makes that pair atomic. Computed in the handler, two concurrent wraps
    for one uid could both read "not yet wrapped" and both be granted, which is
    exactly the outcome the check exists to prevent."""
    if audit.ever_granted(uid, ACTION_WRAP):
        return Refusal(KIND_REQUEST, "already wrapped for this uid")
    return None


def _rate_refusal(uid, action):
    """A wrap happens once per user at onboarding and is bounded by
    `_wrap_once_refusal` instead, so it consumes no budget.

    A bare sign is counted against its own ceiling and nothing else: the uid is
    optional there (at the code exchange none exists yet), so charging it to a
    user would meter only the callers honest enough to name one."""
    if action == ACTION_WRAP:
        return None
    since = time.time() - WINDOW_SECONDS
    if action == ACTION_SIGN:
        signed = audit.granted_since(since, action=action)
        if signed >= sign_limit():
            return Refusal(KIND_RATE,
                           f"sign ceiling reached ({signed}/{sign_limit()} per hour)")
        return None
    used = audit.granted_since(since, action=action, uid=uid)
    if used >= per_user_limit():
        return Refusal(KIND_RATE,
                       f"per-user rate limit reached ({used}/{per_user_limit()} per hour)")
    total = audit.granted_since(since, action=action)
    if total >= total_limit():
        return Refusal(KIND_RATE,
                       f"aggregate ceiling reached ({total}/{total_limit()} per hour)")
    return None


def _alert(uid, action, refusal):
    key = (action, refusal.kind, refusal.reason.split("(")[0].strip())
    now = time.time()
    if now - _LAST_ALERT.get(key, 0) < ALERT_INTERVAL:
        return
    _LAST_ALERT[key] = now
    alerts.notify_operator(
        f"⚠️ <b>co-signer refused {action}</b>\nuid: {uid or '(none)'}\n{refusal.reason}"
    )


def authorize(uid, action, verdict, precheck=None):
    """Decide one request, write its audit row, and return the `Refusal`
    (None when allowed).

    Order matters: the kill switch first, then attestation, then the request's
    own shape, then whether this uid has been wrapped before, then the rate
    limit. A refused request must never have consumed budget it was refused
    for."""
    assert action in ACTIONS, f"unknown action {action!r}"
    with _LOCK:
        refusal = None
        disabled = disabled_reason()
        if disabled is not None:
            refusal = Refusal(KIND_DISABLED, disabled)
        if refusal is None and not verdict.ok:
            refusal = Refusal(KIND_ATTESTATION, verdict.reason or "attestation refused")
        if refusal is None and precheck is not None:
            refusal = Refusal(KIND_REQUEST, precheck)
        if refusal is None and action == ACTION_WRAP:
            refusal = _wrap_once_refusal(uid)
        if refusal is None:
            refusal = _rate_refusal(uid, action)
        audit.record(
            uid, action,
            decision=audit.DENY if refusal else audit.ALLOW,
            reason=refusal.reason if refusal else None,
            fingerprint=verdict.fingerprint,
            measurement=verdict.measurement,
            attested=verdict.attested,
        )
    if refusal is not None:
        _alert(uid, action, refusal)
    return refusal
