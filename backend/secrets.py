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

Two things live here and nothing else should copy them:

  * ``load()`` -- the one read of ``.env``, idempotent, skipped under
    ``TEE_REQUIRED``. Injected environment always wins over the file, so a
    stale checkout cannot shadow what the KMS released.
  * ``fingerprint()`` -- how a secret is named in a log. Every service captures
    its secrets once at startup, so "is this process holding what the file now
    says" is a question only a startup line can answer, and it must be
    answerable without printing the value.

The variable-name constants live here too, because deciding where a secret
comes from is this module's job: ``frontend/session.py`` takes
``SESSION_SECRET_ENV`` off this module rather than the reverse, so nothing in
backend/ reaches up into frontend/ to ask.

The ``*_configured()`` presence checks used to be a third thing here, but each
one imports the module that owns its judgement -- ``llm_client``, ``telegram``,
``billing``, ``oauth_app`` -- and the enclave image ships every module a role
imports, function-local imports included. So a role that imported this one only
for ``load()`` -- the Pub/Sub receiver above all -- carried the whole inference,
alerting and billing fan-out behind it. The checks now live in
``backend.secrets_checks`` (still their single definition, just off the import
graph of a process that only needs to read a variable). ``tee_boot.run_gate()``
and ``deploy/preflight.py``, the two callers, import that module directly.
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
GOOGLE_CLIENT_SECRET_ENV = "GOOGLE_OAUTH_CLIENT_SECRET"  # nosec B105  # the variable name

# The cookie signing key. frontend/session.py takes the name from here rather
# than the other way round: deciding where a secret comes from is this module's
# job, and HMAC-ing a cookie with one is that module's.
SESSION_SECRET_ENV = "SESSION_SECRET"  # nosec B105  # the variable name

# The key that signed the cookies minted before the last rotation. Accepted at
# verification, never used to sign. A single-valued signing key cannot be
# rotated without signing every user out in the same second, which is how a key
# ends up never rotated at all; naming the outgoing value here lets it keep
# opening what it already signed while the new one takes over minting. Optional
# by design, so ``session_configured()`` asks only for the current key: a box
# that has never rotated has no previous one, and dropping the variable is what
# finally retires the sessions that key signed.
SESSION_SECRET_PREVIOUS_ENV = "SESSION_SECRET_PREVIOUS"  # nosec B105  # the variable name

_loaded = False
_from_file = set()


def tee_required():
    """Whether this process must prove it runs attested before touching mail.
    The one read of the flag; tee_boot's gate and the loader below both ask
    here, so 'we are in the enclave' means the same thing to both."""
    return os.environ.get("TEE_REQUIRED", "").strip().lower() in _TRUTHY


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
