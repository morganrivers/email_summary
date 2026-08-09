"""Google consent -> a provisioned account. One copy of the sequence.

This used to exist twice: once in onboarding_server.py (the standalone
/onboard flow) and once inline in frontend/web_server.py, each with its own
staging directory, its own creds move, its own register_account + watch
registration. Two implementations of the path that takes custody of a user's
Gmail refresh token is the last place duplication belongs, so the standalone
server was retired and its logic moved here for the web app to import.

The code exchange is in Python rather than shelled out to Node because Google
binds a refresh token to a DPoP key at the exchange and nowhere else. The proof
has to be attached to that one request, and the key it is signed with lives on
the co-signer, so the exchange has to sit next to backend.custody. Nothing about
the token touches disk on the way through: exchange_code() returns it in memory
and tokens.take_custody() seals it before it is stored.

The redirect URI is a parameter rather than a module constant: it is whatever
the calling server registered with Google, and it must match byte for byte on
both the auth-url and the exchange.

handle_callback() is the whole decision path for an OAuth callback, kept free of
HTTP plumbing so it can be tested directly.
"""

import base64
import hashlib
import json
import sys
from urllib.parse import urlencode

import requests

from backend import audit, paths
from backend.accounts import account
from backend.billing import billing
from backend.custody import client as cosigner
from backend.custody import tokens, wrapping
from backend.integrations.gmail_gcal import gmail_api, google_client, oauth_app
from backend.onboarding import watch_renew

HTTP_TIMEOUT = 30


def log(msg):
    sys.stderr.write(f"provisioning {msg}\n")
    sys.stderr.flush()


class ProvisionError(Exception):
    """Carries the HTTP status the caller should answer with, so the transport
    layer never has to re-derive whether a failure was the user's or ours."""

    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code
        self.msg = msg


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def pkce_verifier(state):
    """The PKCE verifier for one consent, derived rather than stored.

    It has to survive a redirect through Google and come back usable at the
    exchange, and the alternative -- a server-side map from state to verifier --
    is a second piece of mutable state on the sign-in path that can be lost by a
    restart or a second web worker. Deriving it from the enclave's own KMS
    secret keyed by the state value means the exchange reproduces it exactly,
    and nobody without that secret can. The state value is already the CSRF
    token and is compared against the cookie before this is ever called."""
    assert state, "pkce_verifier needs the consent's state value"
    return _b64u(wrapping.derive(state.encode(), b"oauth-pkce"))


def _challenge(verifier):
    return _b64u(hashlib.sha256(verifier.encode()).digest())


def scope_refusal(missing):
    """What a user who unticked a box on the consent screen is told. One wording
    for both places the grant is checked."""
    return (
        f"this sign-in did not grant everything Letterlock needs "
        f"({oauth_app.describe_scopes(missing)}); sign in again and leave every "
        f"permission ticked"
    )


def _require_full_grant(granted):
    missing = oauth_app.missing_scopes(granted)
    if missing:
        raise ProvisionError(403, scope_refusal(missing))


def build_auth_url(state, redirect_uri):
    """The Google consent URL. `dpop_jkt` names the co-signer's public key, which
    is what Google will bind the issued refresh token to; without it the token
    would be usable by anyone who ever holds it, which is the property this
    design removes."""
    assert state and redirect_uri, "build_auth_url needs a state and a redirect"
    client_id, _ = oauth_app.load_keys()
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": oauth_app.scope_param(),
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "true",
        "state": state,
        "code_challenge": _challenge(pkce_verifier(state)),
        "code_challenge_method": "S256",
        "dpop_jkt": cosigner.dpop_jkt(),
    }
    return f"{oauth_app.AUTH_ENDPOINT}?{urlencode(params)}"


def _id_token_claims(id_token):
    """Claims out of the id_token without verifying its signature. It arrived in
    the body of a TLS response from Google's token endpoint, in answer to a code
    only we hold, so the signature adds nothing here; it would matter if this
    token had been handed to us by the user."""
    if not id_token:
        return {}
    parts = id_token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    return json.loads(raw)


def split_name(claims, email):
    first = (claims.get("given_name") or "").strip()
    last = (claims.get("family_name") or "").strip()
    if not first and claims.get("name"):
        parts = claims["name"].strip().split()
        first = parts[0] if parts else ""
        last = last or " ".join(parts[1:])
    if not first:
        first = email.split("@")[0] or "User"
    # UserIdentity requires a non-empty last name; fall back to the first name
    # so masking still tags the owner rather than failing onboarding.
    if not last:
        last = first
    return first, last


def exchange_code(code, redirect_uri, state):
    """Trade the one-time code for tokens and the user's identity.

    Returns {email, first, last, refresh_token}. The refresh token is in memory
    only: this function must never write it, and its only caller hands it
    straight to tokens.take_custody()."""
    assert code and redirect_uri and state, "exchange_code needs code, redirect, state"
    client_id, client_secret = oauth_app.load_keys()
    htm, htu = "POST", oauth_app.TOKEN_ENDPOINT
    try:
        payload = tokens.exchange_with_dpop(
            {
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
                "code_verifier": pkce_verifier(state),
            },
            sign=lambda nonce: cosigner.sign_dpop(htm, htu, nonce),
        )
    except wrapping.CustodyError as err:
        raise ProvisionError(502, f"code exchange failed: {err}") from err
    # The grant as Google recorded it, which is the authoritative answer; the
    # callback query said the same thing a moment earlier, but that parameter is
    # a convenience of the redirect and this is the token itself. Checked before
    # anything is stored, so a partial consent leaves nothing behind.
    _require_full_grant(payload.get("scope"))
    refresh_token = payload.get("refresh_token")
    if not refresh_token:
        raise ProvisionError(
            502, "Google returned no refresh_token (prior grant without prompt=consent?)"
        )
    access_token = payload.get("access_token")
    if not access_token:
        raise ProvisionError(502, "Google returned no access_token")
    try:
        email = gmail_api.profile_address(access_token)
    except requests.RequestException as err:
        raise ProvisionError(502, f"could not read the mailbox address: {err}") from err
    first, last = split_name(_id_token_claims(payload.get("id_token")), email)
    return {"email": email, "first": first, "last": last,
            "refresh_token": refresh_token}


def provision(code, redirect_uri, state):
    """Exchange the code and stand up the account: take custody of the refresh
    token, register the account (inactive), and register its Gmail watch.

    There is no staging directory any more. It existed because the owning email
    was unknown before the exchange and the credentials file had to land
    somewhere first; nothing is written before the identity is known now, so the
    move-into-place dance is gone with it.

    The consent is audited here rather than in account.register_account, and in
    addition to it: taking custody of a refresh token and writing a manifest
    entry are two different facts, and this is the only one that says we now
    hold a way into somebody's mailbox."""
    profile = exchange_code(code, redirect_uri, state)
    # Checked here as well as in account_dir, so an id that cannot be stored is
    # refused before the co-signer is asked to wrap anything for it -- but
    # through the same function, because two spellings of a path-traversal guard
    # is one that can be relaxed without the other noticing.
    email = account.check_id(profile["email"])
    # A returning user keeps the handle they already have: every record they own
    # is encrypted with it as the salt and the AAD, and the co-signer's
    # wrap-once rule is keyed on it. Custody is taken before the manifest entry
    # is written, so the pair is carried explicitly rather than read back off an
    # account that does not exist yet.
    handle = account.handle_for_email(email) or account.new_handle()
    account.secure_dir(account.ACCOUNTS_DIR)
    try:
        token_file = tokens.take_custody((email, handle), profile["refresh_token"])
    except wrapping.CustodyError as err:
        # Fail closed: without the co-signer there is no way to store a token
        # that both boxes are needed to open, and storing one any other way is
        # the arrangement this design exists to avoid.
        raise ProvisionError(503, f"custody unavailable: {err}") from err
    try:
        acct = account.register_account(
            email, profile["first"], profile["last"],
            token_file=paths.relative_if_inside(token_file),
            handle=handle,
        )
    except account.AccountLimitReached as err:
        # The token we just took custody of is unusable now, so it does not stay
        # on disk. Refusing after the exchange is the only place we can refuse:
        # the identity is not known before it.
        tokens.discard((email, handle))
        audit.record(email, audit.CONSENT, "refused", ("account-limit",))
        raise ProvisionError(503, f"signup refused: {err}") from err
    audit.record(acct.id, audit.CONSENT, "granted")
    # A re-consent replaces the custody this account's credentials derive from,
    # so anything cached against the old one has to go with it.
    tokens.forget(acct)
    google_client.forget_services(email)
    watch_renew.renew_account(acct, log=log)
    log(f"provisioned account {acct.id}")
    return acct


def checkout_redirect(email, fallback="/dashboard"):
    """Where to send a user who has asked to pay: Polar hosted checkout when
    configured (carrying customer_email so the order.paid webhook resolves to
    this account), else the caller's own landing spot. Reached from the billing
    page, never from sign-in: signing in and subscribing are separate decisions,
    and a subscriber sent back to checkout is refused by Polar."""
    return billing.checkout_url(email, fallback=fallback)


def handle_callback(query, state_is_ours, redirect_uri, fallback="/dashboard"):
    """Pure decision path for an OAuth callback, shared by the server and the
    tests. Returns (account, redirect location). Raises ProvisionError.

    `state_is_ours(state)` answers whether this browser is actually waiting on
    this consent. It is a predicate rather than the one expected value because a
    browser can have more than one sign-in pending at once, and comparing
    against only the newest turns a second tab into a CSRF alarm. Where the
    answer comes from is frontend.session's business; that it must be true
    before a code is exchanged is this module's."""
    err = query.get("error")
    if err:
        raise ProvisionError(400, f"consent denied: {err}")
    code = query.get("code")
    state = query.get("state")
    if not code or not state:
        raise ProvisionError(400, "missing code or state")
    if not state_is_ours(state):
        raise ProvisionError(
            403, "this sign-in did not start in this browser, or took too long")
    # Google puts the granted scopes on the redirect, so a consent with a box
    # unticked is refused here, before the code is exchanged and before the
    # co-signer is asked to wrap anything. Only when the parameter is present:
    # absent, this is not the grant and says nothing, and `exchange_code` checks
    # the token response, which is.
    if query.get("scope"):
        _require_full_grant(query["scope"])
    acct = provision(code, redirect_uri, state)
    return acct, fallback
