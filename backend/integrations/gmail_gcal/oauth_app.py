"""The Google OAuth application itself: keys, scopes, endpoints.

One OAuth app serves every user, so its client_secret lives in exactly one file
and is read in exactly one place. It used to be copied into each account's creds
directory, which turned a single leaked user directory into a leak of the whole
app.

This is the widest-blast-radius value the deployment holds and the one secret
still read off a volume rather than released post-attestation
(docs/plan_token_custody.md §8). Moving it to the co-signer, which already does
the token exchange's crypto, is the fix; keeping every reader behind this
module is what makes that a one-file change.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from backend import paths, site

KEYS_ENV = "GMAIL_OAUTH_KEYS"
DEFAULT_KEYS_PATH = paths.REPO_ROOT / ".gmail-mcp" / "gcp-oauth.keys.json"

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"

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
    """The app's client_id and client_secret. Raises rather than returning a
    half-configured pair: every caller is about to talk to Google with it."""
    path = keys_path()
    assert path.exists(), (
        f"no Google OAuth app keys at {path}; set {KEYS_ENV} or place "
        "gcp-oauth.keys.json there"
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
