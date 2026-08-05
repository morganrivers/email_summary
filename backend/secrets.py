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
    "configured" means.
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
# has the widest blast radius of any value here, and it is the last one still
# read off the volume rather than released post-attestation
# (backend/integrations/gmail_gcal/oauth_app.py). These names are the contract
# for injecting it instead; `onboarding-exchange-4` owns that change, per §8 of
# docs/plan_token_custody.md, and adds google_oauth_configured() to REQUIRED
# when oauth_app.py actually reads them. Requiring them before then would fail
# the boot gate on a value nothing consults.
GOOGLE_CLIENT_ID_ENV = "GOOGLE_OAUTH_CLIENT_ID"
GOOGLE_CLIENT_SECRET_ENV = "GOOGLE_OAUTH_CLIENT_SECRET"

# The cookie signing key. frontend/session.py takes the name from here rather
# than the other way round: deciding where a secret comes from is this module's
# job, and HMAC-ing a cookie with one is that module's.
SESSION_SECRET_ENV = "SESSION_SECRET"

_loaded = False
_from_file = set()


def tee_required():
    """Whether this process must prove it runs attested before touching mail.
    The one read of the flag; tee_boot's gate and the loader below both ask
    here, so 'we are in the enclave' means the same thing to both."""
    return os.environ.get("TEE_REQUIRED", "").strip().lower() in _TRUTHY


def env_file_present():
    """Whether a ``.env`` exists on the volume. Under TEE_REQUIRED that is a
    provisioning error, not a fallback: see ``tee_boot.run_gate()``."""
    return paths.ENV_FILE.exists()


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
    for name, value in dotenv_values(paths.ENV_FILE).items():
        assert name, f"unnamed entry in {paths.ENV_FILE}"
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
    injected environment, or ``None`` when it was not injected. ``oauth_app.py``
    reads ``gcp-oauth.keys.json`` off the volume today and does not consult this
    yet; see the note on the env names above."""
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

    absent = [p.key_env for p in llm_client.PROVIDERS.values() if not p.configured()]
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
    """Reason the Google OAuth app was not injected, or None. Deliberately not
    in ``REQUIRED`` yet: ``oauth_app.py`` still reads the client secret off the
    volume, so requiring the injected form would refuse boot over a value no
    caller consults. `onboarding-exchange-4` flips both together."""
    if google_oauth_client() is None:
        return f"{GOOGLE_CLIENT_ID_ENV} / {GOOGLE_CLIENT_SECRET_ENV} not set"
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
)


def missing():
    """Why this box is not fully provisioned, one reason per gap. Empty when it
    is. Reasons name variables, never values."""
    load()
    return [reason for reason in (check() for check in REQUIRED) if reason]
