"""Google consent -> a provisioned account. One copy of the sequence.

This used to exist twice: once in onboarding_server.py (the standalone
/onboard flow) and once inline in frontend/web_server.py, each with its own
staging directory, its own creds move, its own register_account + watch
registration. Two implementations of the path that takes custody of a user's
Gmail refresh token is the last place duplication belongs, so the standalone
server was retired and its logic moved here for the web app to import.

The redirect URI is a parameter rather than a module constant: it is whatever
the calling server registered with Google, and it must match byte for byte on
both the auth-url and the exchange.

handle_callback() is the whole decision path for an OAuth callback, kept free of
HTTP plumbing so it can be tested directly.
"""

import json
import shutil
import subprocess
import sys
import tempfile
from hmac import compare_digest
from pathlib import Path

from backend import paths
from backend.accounts import account
from backend.billing import billing
from backend.onboarding import watch_renew

OAUTH_HELPER = paths.node_script("oauth_helper.mjs")


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


def run_helper(args):
    """Run oauth_helper.mjs, returning its stdout. A non-zero exit surfaces as
    502: the failure is Google's or the helper's, not a bug in the request."""
    result = subprocess.run(
        ["node", str(OAUTH_HELPER), *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
    )
    if result.returncode != 0:
        raise ProvisionError(
            502, f"oauth_helper {args[0]} failed: {result.stderr.decode().strip()}"
        )
    return result.stdout.decode()


def build_auth_url(state, redirect_uri):
    return run_helper(
        ["auth-url", "--state", state, "--redirect", redirect_uri]
    ).strip()


def exchange_code(code, redirect_uri, creds_dir):
    return json.loads(run_helper([
        "exchange", "--code", code, "--redirect", redirect_uri,
        "--creds-dir", str(creds_dir),
    ]))


CREDS_FILE = "credentials.json"


def provision(code, redirect_uri):
    """Exchange the code and stand up the account: write the per-user creds dir,
    register the account (inactive), and register its Gmail watch.

    The creds land in a staging directory first because the owning email is only
    known after the exchange; they are then moved under the final per-user path
    recorded in the manifest. Only the refresh token is per user: the OAuth app
    keys stay in one place (gmail_lib.OAUTH_KEYS_PATH)."""
    account.secure_dir(account.ACCOUNTS_DIR)
    staging = Path(tempfile.mkdtemp(dir=account.ACCOUNTS_DIR, prefix=".staging-"))
    try:
        profile = exchange_code(code, redirect_uri, staging)
        email = profile["email"]
        assert email and "/" not in email and "\\" not in email and ".." not in email, (
            f"refusing to build a creds path from {email!r}"
        )
        creds_abs = account.ACCOUNTS_DIR / email / ".gmail-mcp"
        creds_rel = creds_abs.relative_to(paths.REPO_ROOT)
        account.secure_dir(creds_abs.parent)
        account.secure_dir(creds_abs)
        target = creds_abs / CREDS_FILE
        shutil.move(str(staging / CREDS_FILE), str(target))
        target.chmod(0o600)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    try:
        acct = account.register_account(
            email, profile["first"], profile["last"], str(creds_rel)
        )
    except account.AccountLimitReached as err:
        # The token we just took custody of is unusable now, so it does not stay
        # on disk. Refusing after the exchange is the only place we can refuse:
        # the identity is not known before it.
        shutil.rmtree(creds_abs.parent, ignore_errors=True)
        raise ProvisionError(503, f"signup refused: {err}") from err
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


def handle_callback(query, cookie_state, redirect_uri, fallback="/dashboard"):
    """Pure decision path for an OAuth callback, shared by the server and the
    tests. Returns (account, redirect location). Raises ProvisionError."""
    err = query.get("error")
    if err:
        raise ProvisionError(400, f"consent denied: {err}")
    code = query.get("code")
    state = query.get("state")
    if not code or not state:
        raise ProvisionError(400, "missing code or state")
    if not cookie_state or not compare_digest(state, cookie_state):
        raise ProvisionError(403, "state mismatch (possible CSRF)")
    acct = provision(code, redirect_uri)
    return acct, fallback
