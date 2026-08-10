"""The Google OAuth application itself: keys, scopes, endpoints.

One OAuth app serves every user, so its client_secret is read in exactly one
place. It used to be copied into each account's creds directory, which turned a
single leaked user directory into a leak of the whole app.

This is the widest-blast-radius value the deployment holds, and it arrives as
injected environment first. Inside the enclave
that is the only route: the volume copy is a file the KMS does not gate and the
measurement does not cover, so ``load_keys()`` refuses it under ``TEE_REQUIRED``
and ``tee_boot.run_gate()`` will not boot with one present. On a plain box the
file is still the source, which is why the fallback exists at all.

It deliberately did *not* move to the co-signer. Google's token endpoint wants
``client_secret`` and ``refresh_token`` in the same POST and the enclave is what
makes that POST, so a co-signer holding this either performs the exchange and
sees a refresh token -- breaking the invariant the whole split rests on -- or
hands the secret straight back. There is no marginal loss from the enclave
holding it: an attacker with enclave memory already has refresh tokens.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from backend import paths, secrets, site
from cosigner import protocol as cosigner_protocol

KEYS_ENV = "GMAIL_OAUTH_KEYS"
DEFAULT_KEYS_PATH = paths.REPO_ROOT / ".gmail-mcp" / "gcp-oauth.keys.json"

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
# The URL this box POSTs to and the only `htu` the co-signer will sign a proof
# for are the same string, so they are one constant. Written twice they can
# drift, and the failure is total and silent from here: the co-signer refuses
# every proof as a wrong target, which reads as an attack rather than a typo.
# The co-signer still holds its own copy of this file, so the check remains its
# own judgement rather than something the enclave states on the wire.
TOKEN_ENDPOINT = cosigner_protocol.TOKEN_ENDPOINT

# Where a grant is given back. One caller, `tokens.revoke`, on the deletion
# path: it is the only way to stop Letterlock appearing on a departed user's
# Google security page with a live grant. Not the co-signer's business --
# `/revoke` takes the refresh token itself and signs no proof -- so it is named
# here beside the other two rather than in `cosigner/protocol.py`. The same host
# as the token endpoint today, and `backend/egress.py` derives it from this name
# rather than from that coincidence.
REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke"

# openid/email/profile grant the login identity (name + email) alongside the
# Gmail/Calendar scopes, so one consent yields both the account and the token.
# Ask for nothing beyond what the code calls: gmail.settings.basic was requested
# and never used, and an unused scope is only ever a bigger loss when a token
# leaks.
#
BASE_SCOPES = (
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar.events",
)

# calendar.acls.readonly is the one scope here that buys a refusal rather than a
# capability. Event bodies are written from the account's own mail, so writing
# one to a calendar the world can read republishes that mail, and the ACL is how
# the app tells one from the other rather than trusting. It is the read-only
# half of the ACL pair, so it grants no way to change who a calendar is shared
# with. See `calendar_api.write_calendar_audience()`, the only caller.
#
# It is off by default, and this switch is the one place that decides. A scope
# is not ours to request: it has to be registered on the OAuth app's Data Access
# page in the Google Cloud console, and being sensitive it puts a published app
# back into verification. Asking for one that is not registered is how a consent
# fails at Google rather than in code. When it is off, `calendar_public` answers
# the same question over the public internet instead -- weaker, and its own
# module says exactly how -- so the two are alternatives and never both.
ACL_SCOPE = "https://www.googleapis.com/auth/calendar.acls.readonly"
ACL_SCOPE_ENV = "LETTERLOCK_CALENDAR_ACL_SCOPE"


def acl_scope_registered():
    """Whether `ACL_SCOPE` is registered on the consent screen, and so whether
    anything may ask for it or expect a token to carry it."""
    return os.environ.get(ACL_SCOPE_ENV, "").strip() == "1"


def scopes():
    """What the consent asks for."""
    return BASE_SCOPES + ((ACL_SCOPE,) if acl_scope_registered() else ())


# What a consent has to come back with, as opposed to what it asks for. Google's
# screen lets a user untick individual permissions, and a sign-in that dropped
# one used to succeed and fail later at whatever call needed it: a mailbox the
# daemon cannot read, or -- when the calendar ACL check is on -- scheduling that
# refuses every event. The identity scopes are absent on
# purpose. Nothing breaks without them, because the address comes from the Gmail
# profile and `split_name` falls back, so requiring them would refuse a consent
# that works.
BASE_REQUIRED_SCOPES = (
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar.events",
)


def required_scopes():
    """What the consent has to come back with."""
    required = BASE_REQUIRED_SCOPES + ((ACL_SCOPE,) if acl_scope_registered() else ())
    assert set(required) <= set(scopes()), (
        "a scope is required of the consent but never asked for in it"
    )
    return required


def keys_path():
    override = os.environ.get(KEYS_ENV, "")
    return Path(override) if override else DEFAULT_KEYS_PATH


def load_keys():
    """The app's client_id and client_secret, injected pair first.

    Raises rather than returning a half-configured pair: every caller is about
    to talk to Google with it. The injected pair wins wherever both exist, so a
    stale file cannot shadow what the KMS released, and inside a CVM the file is
    not a fallback at all."""
    injected = secrets.google_oauth_client()
    if injected:
        return injected
    path = keys_path()
    assert not secrets.tee_required(), (
        f"{secrets.GOOGLE_CLIENT_ID_ENV} and {secrets.GOOGLE_CLIENT_SECRET_ENV} "
        "must be injected as encrypted environment inside the enclave; the "
        f"volume copy at {path} is not released post-attestation and is "
        "refused here"
    )
    assert path.exists(), (
        f"no Google OAuth app: set {secrets.GOOGLE_CLIENT_ID_ENV} and "
        f"{secrets.GOOGLE_CLIENT_SECRET_ENV}, or place gcp-oauth.keys.json at "
        f"{path} (overridable with {KEYS_ENV})"
    )
    blob = json.loads(path.read_text())
    keys = blob.get("web") or blob.get("installed") or {}
    client_id = keys.get("client_id")
    client_secret = keys.get("client_secret")
    assert client_id and client_secret, (
        f"OAuth keys at {path} are missing client_id/client_secret"
    )
    return client_id, client_secret


def redirect_uri():
    """Where Google returns the user. Must match byte for byte between the auth
    URL and the exchange, and must be registered on the OAuth client."""
    return os.environ.get("WEB_OAUTH_REDIRECT_URI") or site.oauth_callback_url()


def scope_param():
    return " ".join(scopes())


def missing_scopes(granted):
    """Which required scopes a consent did not come back with.

    `granted` is the space separated list Google puts in the callback query and
    again in the token response. Absent or empty counts as granting nothing,
    which is the fail-closed reading and the correct one: a response that does
    not say what was granted is not evidence that everything was."""
    have = set((granted or "").split())
    return tuple(scope for scope in required_scopes() if scope not in have)


def describe_scopes(scopes):
    """Scope names short enough to put in front of a person."""
    return ", ".join(scope.rsplit("/", 1)[-1] for scope in scopes)
