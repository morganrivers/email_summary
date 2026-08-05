"""The Google OAuth application itself: keys, scopes, endpoints.

One OAuth app serves every user, so its client_secret is read in exactly one
place. It used to be copied into each account's creds directory, which turned a
single leaked user directory into a leak of the whole app.

This is the widest-blast-radius value the deployment holds, and it arrives as
injected environment first (docs/plan_token_custody.md §8). Inside the enclave
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

# openid/email/profile grant the login identity (name + email) alongside the
# Gmail/Calendar scopes, so one consent yields both the account and the token.
# Ask for nothing beyond what the code calls: gmail.settings.basic was requested
# and never used, and an unused scope is only ever a bigger loss when a token
# leaks.
SCOPES = (
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar.events",
)


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
    return " ".join(SCOPES)
