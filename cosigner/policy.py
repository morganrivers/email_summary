"""What the co-signer will do, how often, and for whom.

This is the number that bounds a live enclave breach. Nothing stops an attacker
who owns the enclave from asking for one mailbox at a time -- the enclave is
what talks to Google, so a refresh token has to exist in its RAM at the moment
of use. What is available is the rate: set the aggregate ceiling low enough
that draining the user base takes longer than noticing it (plan §0).

Volume is only half of it. Draining the user base is one request per account,
which every per-account rule reads as normal, so there is a second measure of
breadth -- how many *different* accounts were unwrapped in a short window
(`_sweep_refusal`). It is the rule aimed at the pattern that looks most
ordinary to the other rules.

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

from cosigner import alerts, audit, protocol

ACTION_WRAP = "wrap"
ACTION_UNWRAP = "unwrap-and-sign"
ACTION_UNWRAP_DATA = "unwrap"
ACTION_SIGN = "sign-dpop"
ACTION_REWRAP = "rewrap"

ACTIONS = (ACTION_WRAP, ACTION_UNWRAP, ACTION_UNWRAP_DATA, ACTION_SIGN, ACTION_REWRAP)

# The actions that hand an account's key material back to the enclave. Named
# once, because every rule about blast radius is a rule about this set and not
# about one endpoint: an attacker choosing between two unwrap paths must not be
# able to halve a ceiling by using both.
#
# `rewrap` is deliberately not one of them. It returns ciphertext under a
# different key, which is worth no more to a caller than the ciphertext they
# already had to present to ask.
KEY_RELEASING = (ACTION_UNWRAP, ACTION_UNWRAP_DATA)

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

# The sweep limit. A short window, because breadth is what it measures and a
# breach that spreads itself over an hour has already been caught by the
# aggregate ceiling.
DISTINCT_WINDOW_SECONDS = 900

# Bulk exfiltration looks like this and nothing else does: every account touched
# once. Per account that is one unwrap, comfortably inside the per-user ceiling,
# and 100 of them is half the aggregate one -- the exact pattern that reads as
# normal to both existing rules. Counting distinct accounts is what sees it.
#
# A fully subscribed box (MAX_ACCOUNTS = 100, roughly one unwrap per active
# account per hour once the access token is cached) produces about 25 distinct
# accounts in a quarter hour. 40 leaves half again as much headroom over that
# and still refuses a sweep before it has reached half the user base.
DEFAULT_DISTINCT_UIDS = 40

# Refuse and alert; do not trip the kill switch. Automatic disablement would
# bound the loss without an operator awake, but there is deliberately no bypass
# in this design, so a false positive stops mail for everyone until a human
# clears it. At 100 accounts a sweep refused 40 accounts in and alerted is a
# response fast enough to make by hand. Revisit when the account count makes
# that too slow.
SWEEP_REASON = "distinct-account ceiling reached"

# `/sign-dpop` carries no uid, so the per-user limit cannot reach it and this
# ceiling is the only thing bounding it. Without one it is the unmetered path
# around the metered one: an enclave-side attacker skips `/unwrap-and-sign`,
# uses a refresh token they already lifted, and asks here for the proof that
# makes it work. The legitimate pattern is at most one retry proof per unwrap
# plus onboarding, so the default matches the unwrap ceiling rather than
# doubling it.
DEFAULT_SIGN_HOUR = DEFAULT_TOTAL_HOUR

# A full rotation is one request per account and the box holds at most
# MAX_ACCOUNTS of them, so this is several complete passes an hour. It exists
# because an endpoint with no ceiling is one an attacker can use as an oracle
# for free, not because a legitimate rotation is expected to come near it.
DEFAULT_REWRAP_HOUR = 500

# One alert per reason per interval. A breach produces the same refusal over
# and over, and a Telegram channel that gets a thousand of them is a channel
# the operator mutes.
ALERT_INTERVAL = 300

# The sweep refusal keeps firing for as long as its window holds the grants that
# tripped it, so anything shorter than the window reports one incident several
# times. One alert per incident is the whole point of the throttle.
SWEEP_ALERT_INTERVAL = DISTINCT_WINDOW_SECONDS

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
    """One ceiling, from the unit's environment or from the default beside it.

    A raise and not an assert: the value is what an operator typed into a unit
    file, so it is the same class of input as `int(raw)` failing on the line
    above, and a limit that vanishes under `-O` is a limit."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    value = int(raw)
    if value <= 0:
        raise ValueError(f"{name} must be positive, got {value}")
    return value


def per_user_limit():
    """A mailbox wake needs one unwrap; the access token it yields is good for
    about an hour and is cached in-process by the enclave."""
    return _limit("COSIGNER_RATE_PER_USER_HOUR", DEFAULT_PER_USER_HOUR)


def total_limit():
    return _limit("COSIGNER_RATE_TOTAL_HOUR", DEFAULT_TOTAL_HOUR)


def sign_limit():
    return _limit("COSIGNER_RATE_SIGN_HOUR", DEFAULT_SIGN_HOUR)


def rewrap_limit():
    return _limit("COSIGNER_RATE_REWRAP_HOUR", DEFAULT_REWRAP_HOUR)


def distinct_uid_limit():
    """How many different accounts may be unwrapped inside one
    `DISTINCT_WINDOW_SECONDS`."""
    return _limit("COSIGNER_RATE_DISTINCT_UIDS", DEFAULT_DISTINCT_UIDS)


def longest_window():
    """The oldest row any limiter still reads. Retention's floor is derived from
    this rather than restated, so adding a limiter with a longer window cannot
    leave a prune deleting rows it counts."""
    return max(WINDOW_SECONDS, DISTINCT_WINDOW_SECONDS)


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


def _sweep_refusal(uid, action):
    """Breadth, not volume: how many *different* accounts have been unwrapped
    recently.

    An account already counted in the window is not refused by this rule. It has
    contributed its uid to the total already, so refusing it would neither
    narrow the breach nor bound anything -- it would only take ordinary mail
    processing down for whoever was busiest when a sweep started. What the rule
    stops is the next *new* account, which is the only direction a sweep can
    go.

    Counted across every key-releasing action rather than per endpoint. There
    are two ways to obtain an account's data key, and a rule that metered each
    separately would let a sweep take half its accounts down one path and half
    down the other, staying under both ceilings while touching twice as many
    people as either allows."""
    assert action in KEY_RELEASING, f"{action} does not release key material"
    since = time.time() - DISTINCT_WINDOW_SECONDS
    if audit.granted_since(since, action=KEY_RELEASING, uid=uid):
        return None
    seen = audit.distinct_uids_since(since, action=KEY_RELEASING)
    if seen >= distinct_uid_limit():
        minutes = DISTINCT_WINDOW_SECONDS // 60
        return Refusal(KIND_RATE, f"{SWEEP_REASON} ({seen}/{distinct_uid_limit()} accounts "
                                  f"in {minutes} minutes)")
    return None


def _rate_refusal(uid, action):
    """A wrap happens once per user at onboarding and is bounded by
    `_wrap_once_refusal` instead, so it consumes no budget.

    A bare sign is counted against its own ceiling and nothing else: the uid is
    optional there (at the code exchange none exists yet), so charging it to a
    user would meter only the callers honest enough to name one.

    The sweep check sits between the per-user rule and the aggregate one because
    it is the refusal that names what is happening: a sweep trips it long before
    the hourly total, and an operator reading "aggregate ceiling" learns only
    that the box is busy."""
    if action == ACTION_WRAP:
        return None
    since = time.time() - WINDOW_SECONDS
    if action == ACTION_SIGN:
        signed = audit.granted_since(since, action=action)
        if signed >= sign_limit():
            return Refusal(KIND_RATE,
                           f"sign ceiling reached ({signed}/{sign_limit()} per hour)")
        return None
    if action == ACTION_REWRAP:
        # No per-account rule and no sweep rule: touching every account once is
        # what a rotation *is*, so the shape this box treats as an incident
        # everywhere else is the expected shape here. What bounds it is that it
        # releases nothing -- the caller ends up holding ciphertext they already
        # held, under a different key.
        rewrapped = audit.granted_since(since, action=action)
        if rewrapped >= rewrap_limit():
            return Refusal(KIND_RATE,
                           f"rewrap ceiling reached ({rewrapped}/{rewrap_limit()} per hour)")
        return None
    used = audit.granted_since(since, action=action, uid=uid)
    if used >= per_user_limit():
        return Refusal(KIND_RATE,
                       f"per-user rate limit reached ({used}/{per_user_limit()} per hour)")
    sweep = _sweep_refusal(uid, action)
    if sweep is not None:
        return sweep
    total = audit.granted_since(since, action=action)
    if total >= total_limit():
        return Refusal(KIND_RATE,
                       f"aggregate ceiling reached ({total}/{total_limit()} per hour)")
    return None


def _alert_interval(reason):
    """How long one refusal silences the next identical one. A sweep is refused
    once per account for as long as its window holds the grants that tripped it,
    which is one incident and wants one message."""
    return SWEEP_ALERT_INTERVAL if reason == SWEEP_REASON else ALERT_INTERVAL


def _alert(uid, action, refusal):
    reason = refusal.reason.split("(")[0].strip()
    key = (action, refusal.kind, reason)
    now = time.time()
    if now - _LAST_ALERT.get(key, 0) < _alert_interval(reason):
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
