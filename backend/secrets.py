"""Single source of truth for how a secret reaches this process.

Eight modules used to call ``load_dotenv(paths.ENV_FILE)`` for themselves, so
nothing could answer the one question that matters inside an enclave: did this
value arrive as injected environment, or was it read off the volume? dstack
encrypts the LLM keys, the Telegram token, the Google OAuth client secret and
the Polar keys to the app KMS key and injects them as environment variables
that decrypt only inside an attested CVM (docs/tee_enclaves_and_upgrades.md
§5.3). A ``.env`` file sitting on the volume next to them is exactly the
at-rest leak the custody design removes everywhere else, so under
``TEE_REQUIRED`` this module reads no file at all and ``file_backed()`` is
empty by construction rather than by convention.

Three things live here and nothing else should copy them:

  * ``load()`` -- the one read of ``.env``, idempotent, skipped under
    ``TEE_REQUIRED``. Injected environment always wins over the file, so a
    stale checkout cannot shadow what the KMS released.
  * the ``*_configured()`` checks -- whether a secret is present.
    ``tee_boot.run_gate()`` and ``deploy/preflight.py`` are both built on them,
    so the boot gate and the deploy check cannot disagree about what
    "configured" means. ``REQUIRED`` is the whole box; ``REQUIRED_BY_ROLE`` is
    the same question per enclave container, because the compose file hands
    each one a different subset and the gate must not refuse a role for
    lacking a secret the partition deliberately withholds from it.
  * ``fingerprint()`` -- how a secret is named in a log. Every service captures
    its secrets once at startup, so "is this process holding what the file now
    says" is a question only a startup line can answer, and it must be
    answerable without printing the value.

A check asks the owning module whenever presence is a judgement rather than a
lookup: ``PolarBilling()`` applies the sandbox/prod suffix switch,
``telegram.operator_target()`` wants a token *and* a chat. Where presence is
just "was this variable injected", the name lives here and the consumer reads
it from here -- ``frontend/session.py`` takes ``SESSION_SECRET_ENV`` off this
module rather than the reverse, so nothing in backend/ reaches up into
frontend/ to ask. Those service imports are deferred into the check bodies
because the services import this one for ``load()``.
"""

import hashlib
import os

from dotenv import dotenv_values

from backend import paths

_TRUTHY = ("1", "true", "yes")

# The shared Google OAuth app. One app serves every user, so its client_secret
# has the widest blast radius of any value here. It was the last secret read off
# the volume rather than released post-attestation; ``oauth_app.load_keys()``
# now takes this pair first and refuses the file under TEE_REQUIRED, so inside
# the enclave these names are the only way in.
GOOGLE_CLIENT_ID_ENV = "GOOGLE_OAUTH_CLIENT_ID"
GOOGLE_CLIENT_SECRET_ENV = "GOOGLE_OAUTH_CLIENT_SECRET"

# The cookie signing key. frontend/session.py takes the name from here rather
# than the other way round: deciding where a secret comes from is this module's
# job, and HMAC-ing a cookie with one is that module's.
SESSION_SECRET_ENV = "SESSION_SECRET"

# The key that signed the cookies minted before the last rotation. Accepted at
# verification, never used to sign. A single-valued signing key cannot be
# rotated without signing every user out in the same second, which is how a key
# ends up never rotated at all; naming the outgoing value here lets it keep
# opening what it already signed while the new one takes over minting. Optional
# by design, so ``session_configured()`` asks only for the current key: a box
# that has never rotated has no previous one, and dropping the variable is what
# finally retires the sessions that key signed.
SESSION_SECRET_PREVIOUS_ENV = "SESSION_SECRET_PREVIOUS"

_loaded = False
_from_file = set()


def tee_required():
    """Whether this process must prove it runs attested before touching mail.
    The one read of the flag; tee_boot's gate and the loader below both ask
    here, so 'we are in the enclave' means the same thing to both."""
    return os.environ.get("TEE_REQUIRED", "").strip().lower() in _TRUTHY


def volume_secrets():
    """Secret files sitting on the volume, in the order they are worth naming.

    Under TEE_REQUIRED every one of these is a provisioning error rather than a
    fallback: a file the KMS does not gate and the measurement does not cover.
    The list lives here rather than in ``tee_boot`` so the gate refuses exactly
    the files the loaders refuse -- ``load()`` reads no ``.env`` and
    ``oauth_app.load_keys()`` reads no key file once TEE_REQUIRED is set, and a
    gate that enumerated its own subset would let a re-added mount through."""
    from backend.integrations.gmail_gcal import oauth_app

    return tuple(p for p in (paths.ENV_FILE, paths.BILLING_ENV_FILE,
                             paths.ALERTS_ENV_FILE,
                             oauth_app.keys_path()) if p.exists())


def secret_files():
    """Every file ``load()`` reads, in the order it reads them.

    Two, because one unit must not hold the other's secrets: ``.env.billing``
    carries the Polar webhook signing secret alone and is the only file the
    Polar receiver can open. Each is read best-effort, so a process entitled to
    one and not the other gets what it is entitled to and no exception."""
    return (paths.ENV_FILE, paths.BILLING_ENV_FILE)


def _file_values():
    """The secret files as one dict, skipping any this process may not read.

    Not every unit on this box is meant to. The egress proxy runs as its own
    account precisely so that the process with unrestricted network access is
    not the process holding the API keys, and it reaches the source through a
    supplementary group that stops at the 0600 files. It still imports modules
    that call ``load()`` on the way to a constant, and a ``PermissionError``
    raised out of one of those imports would take the unit down for succeeding
    at what it was configured to do.

    Absent and forbidden are the same answer here, and deliberately so: both
    mean this process gets its configuration from the environment or not at
    all. They are not the same everywhere -- ``preflight._definitely_absent``
    refuses to read a permission error as "missing" for exactly the opposite
    reason -- because that one is judging another unit's provisioning, and this
    one is describing its own."""
    values = {}
    for path in secret_files():
        try:
            values.update(dotenv_values(path))
        except PermissionError:
            continue
    return values


def load():
    """Populate the environment from ``.env`` once, outside a TEE.

    Values already in the environment are never overwritten: on the box the
    file is the source, in a CVM the KMS is, and the KMS must win wherever both
    exist."""
    global _loaded
    if _loaded:
        return
    _loaded = True
    if tee_required():
        return
    for name, value in _file_values().items():
        assert name, f"unnamed entry in {secret_files()}"
        if value is None or name in os.environ:
            continue
        os.environ[name] = value
        _from_file.add(name)


def get(name, default=None):
    """A secret's value, loading ``.env`` first if that has not happened yet."""
    assert name, "get() needs a variable name"
    load()
    return os.environ.get(name, default)


def require(name):
    """A secret's value, or an assertion naming what is missing. Never logs or
    returns the value on failure."""
    value = get(name)
    assert value, f"{name} must be set"
    return value


def fingerprint(value):
    """A stable, non-reversible label for a secret, safe to log.

    A service captures its secrets at startup and never rereads them, so a
    ``.env`` edited underneath a running process leaves no trace: the only
    symptom is whatever the stale value breaks downstream, which is how a
    rotated Polar webhook secret read as an attacker probing a public endpoint
    for twenty minutes. Printing this beside the value's name at startup makes
    "the process is not holding what the file says" answerable without ever
    putting the secret in a log, and comparable against
    ``printf %s "$secret" | sha256sum``."""
    if not value:
        return "(unset)"
    raw = value.encode("utf-8") if isinstance(value, str) else value
    assert isinstance(raw, (bytes, bytearray)), "fingerprint() needs str or bytes"
    return f"sha256:{hashlib.sha256(raw).hexdigest()[:8]}"


def file_backed():
    """Which secrets this process took off the disk rather than from injected
    environment. Empty inside a TEE, which is the property the boot gate and
    the docker-compose file exist to keep true."""
    load()
    return tuple(sorted(_from_file))


def google_oauth_client():
    """The shared Google OAuth app's ``(client_id, client_secret)`` from
    injected environment, or ``None`` when it was not injected. Half a pair is
    no pair: ``oauth_app.load_keys()`` falls back to the volume file on this
    answer, and falling back on a stray client_id would send the wrong app to
    Google."""
    client_id = get(GOOGLE_CLIENT_ID_ENV)
    client_secret = get(GOOGLE_CLIENT_SECRET_ENV)
    if not client_id or not client_secret:
        return None
    return client_id, client_secret


def inference_configured():
    """Reason no drafting can happen, or None.

    Every provider in the catalog must be reachable, not just the default: the
    web UI offers a route only when its key is present, so a box missing the
    confidential provider's key silently narrows the user's choice instead of
    failing where an operator would see it."""
    from backend.integrations import llm_client

    absent = sorted({p.key_env for p in llm_client.PROVIDERS.values() if not p.configured()})
    return f"{', '.join(absent)} not set" if absent else None


def telegram_configured():
    """Reason box-level failure alerts cannot be delivered, or None. The
    operator chat is what reports a co-signer outage or a refused unwrap, so an
    unprovisioned one is a gap in the alerting path, not a preference."""
    from backend.integrations import telegram

    if telegram.operator_target() is None:
        return "TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set"
    return None


def session_configured():
    """Reason the web UI cannot sign anyone in, or None. The cookie signer reads
    the same name through ``require()``, so it is stated once."""
    if not get(SESSION_SECRET_ENV):
        return f"{SESSION_SECRET_ENV} not set"
    return None


def polar_api_configured():
    """Reason the Polar API client cannot be built, or None. PolarBilling's own
    asserts are the check, so the sandbox/prod suffix switch is applied exactly
    once."""
    from backend.billing import billing

    try:
        billing.PolarBilling()
    except AssertionError as err:
        return str(err)
    return None


def polar_webhook_configured():
    """Reason a Polar webhook cannot be verified, or None. Read through
    ``billing.webhook_secret()`` so the check and the verifier sit on the same
    side of the sandbox toggle."""
    from backend.billing import billing

    if not billing.webhook_secret():
        return "POLAR_WEBHOOK_SECRET not set"
    return None


def polar_configured():
    """Both halves of the billing surface: mint checkouts and verify events."""
    return polar_api_configured() or polar_webhook_configured()


def google_oauth_configured():
    """Reason nobody can sign in with Google, or None.

    Asked of ``oauth_app.load_keys()`` rather than answered here, because which
    source counts is that module's decision and it differs by environment: the
    volume file is a valid answer on the box and a refusal inside the enclave.
    A copy of the rule here would approve a source the reader rejects, which is
    a gate that passes and a sign-in that 500s."""
    from backend.integrations.gmail_gcal import oauth_app

    try:
        oauth_app.load_keys()
    except (AssertionError, OSError, ValueError) as err:
        return str(err)
    return None


# Everything a fully provisioned box needs before it is allowed to touch a
# mailbox. The boot gate refuses on any of these; the deploy preflight applies
# them per unit, since a Hetzner box legitimately runs only some services.
REQUIRED = (
    inference_configured,
    telegram_configured,
    session_configured,
    polar_api_configured,
    polar_webhook_configured,
    google_oauth_configured,
)

# The same question asked per enclave role, because the enclave answers it per
# role. `deploy/phala/docker-compose.yml` hands each container exactly the
# secrets its own `environment:` block names, and that partition is measured
# into RTMR3 -- so a gate applying the whole-box tuple refuses `web` for having
# no inference key and `mail` for having no SESSION_SECRET, and both roles
# crash-loop on first boot. The obvious fix under time pressure is to give every
# container every variable, which is the partition undone, so the gate has to be
# the thing that knows better.
#
# Names the roles `flake.nix`'s entrypoint accepts. `hook` requires nothing: it
# verifies a Pub/Sub JWT and appends an address to a spool, and its own
# WEBHOOK_AUD / PUBSUB_SERVICE_ACCOUNT are not secrets.
REQUIRED_BY_ROLE = {
    "mail": (inference_configured, telegram_configured, polar_api_configured,
             google_oauth_configured),
    "web": (session_configured, polar_api_configured),
    "hook": (),
}

# Checks in REQUIRED that no enclave role can satisfy, and why. Separated rather
# than dropped so the assert below still covers REQUIRED whole: adding a check
# to REQUIRED and forgetting every role is the drift this catches, and an
# exemption has to be argued for in writing here.
#
# No role is a Polar receiver. Entitlement inside the enclave is exactly
# `confirm_checkout()` in `web` and the 3-hourly reconcile in `mail`, both of
# which read Polar's API rather than verify an event signature, so there is no
# correct value of POLAR_WEBHOOK_SECRET to inject.
ROLE_EXEMPT = (polar_webhook_configured,)

assert set(REQUIRED) == set(ROLE_EXEMPT).union(*REQUIRED_BY_ROLE.values()), (
    "REQUIRED and REQUIRED_BY_ROLE disagree about what a deployment needs; "
    "a new check must be given to the roles that need it or exempted by name"
)


def missing(role=None):
    """Why this deployment is not fully provisioned, one reason per gap. Empty
    when it is. Reasons name variables, never values.

    With no role this is the whole box, which is what `deploy/preflight.py`
    narrows per unit. With one it is that enclave container alone."""
    load()
    if role is None:
        checks = REQUIRED
    else:
        assert role in REQUIRED_BY_ROLE, f"unknown role {role!r}"
        checks = REQUIRED_BY_ROLE[role]
    return [reason for reason in (check() for check in checks) if reason]
