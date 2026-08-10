"""Whether a secret is present -- the provisioning presence checks, split out of
``backend.secrets`` so the modules they ask about do not follow ``secrets``
everywhere it is imported.

These were fields of ``secrets`` itself, and each one reaches for the module
that owns the judgement: ``inference_configured`` imports ``llm_client``,
``telegram_configured`` imports ``telegram``, the Polar checks import
``billing``, ``google_oauth_configured`` and ``volume_secrets`` import
``oauth_app``. Those imports were written inside the check bodies so a service
importing ``secrets`` only for ``load()`` would not load them at runtime -- but
the enclave image is built from ``tools.reachability``, which walks the whole
AST and counts a function-local import exactly like a top-level one, because a
lazy import can still execute. So every one of those modules shipped into every
role that imports ``secrets`` -- including the Pub/Sub receiver, whose one use of
``secrets`` is ``load()`` and which has no business carrying the inference
client, the Telegram client, the billing code or the custody stack they pull in
behind them.

The presence checks belong to exactly two callers, and neither is the receiver:
``backend.tee.tee_boot`` (the enclave's mail and web roles run the boot gate) and
``deploy.preflight`` (the box, per unit). Moving them here leaves ``secrets`` as
load/get/fingerprint and the variable-name constants -- what a JWT verifier
actually needs -- and keeps the heavy fan-out on the import graph of the roles
that already hold those keys. This is still the single definition of "this value
is present": the checks did not fork, they moved, and ``secrets`` re-exports
nothing so there is one place to read.
"""

from backend import secrets


def volume_secrets():
    """Secret files sitting on the volume, in the order they are worth naming.

    Under ``TEE_REQUIRED`` every one of these is a provisioning error rather than
    a fallback: a file the KMS does not gate and the measurement does not cover.
    The list lives beside the boot gate that reads it so the gate refuses exactly
    the files the loaders refuse -- ``secrets.load()`` reads no ``.env`` and
    ``oauth_app.load_keys()`` reads no key file once ``TEE_REQUIRED`` is set, and
    a gate that enumerated its own subset would let a re-added mount through."""
    from backend import paths
    from backend.integrations.gmail_gcal import oauth_app

    return tuple(p for p in (paths.ENV_FILE, paths.BILLING_ENV_FILE,
                             paths.ALERTS_ENV_FILE,
                             oauth_app.keys_path()) if p.exists())


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
    the same name through ``secrets.require()``, so it is stated once."""
    if not secrets.get(secrets.SESSION_SECRET_ENV):
        return f"{secrets.SESSION_SECRET_ENV} not set"
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


def missing():
    """Why this box is not fully provisioned, one reason per gap. Empty when it
    is. Reasons name variables, never values."""
    secrets.load()
    return [reason for reason in (check() for check in REQUIRED) if reason]
