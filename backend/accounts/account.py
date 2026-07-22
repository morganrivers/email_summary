"""Per-account context threaded through every processing path.

An Account bundles everything that varies per user: the masking identity, the
state cursor, the notification target, and the Gmail creds directory. A shared
process holds one Account per user without any ambient single-tenant globals.

load_accounts() reads the multi-tenant store (database/accounts.json) when it
exists, one Account per registered user. When the manifest is absent it falls
back to default_account(), which reproduces the historical single-tenant config
(Morgan's identity, state.json, env-based Telegram, default Gmail creds), so the
deployed single-tenant box behaves exactly as the pre-refactor code did.

Store schema (database/accounts.json), one object per user:
    {
      "id": "user@example.com",
      "identity": {"first": "...", "last": "...",
                   "first_aliases": [...], "emails": [...],
                   "phones": [...], "contacts": [...]},
      "creds_dir": "database/user@example.com/.gmail-mcp",
      "state_file": "database/user@example.com/state.json",
      "telegram": {"chat_id": "...", "token": "<optional; env fallback>"},
      "plan_status": "active",
      "polar_customer_id": "<optional; set at checkout for exact billing link>"
    }
Relative creds_dir/state_file paths resolve against the repo root. The manifest
holds per-user PII and tokens, so it is git-ignored and lives only on the host
(a sealed store subclasses this later for the TEE lift).
"""

import json
import os
from pathlib import Path

from backend import paths
from backend.masking import pseudonymizer
from backend.accounts import state

ACCOUNTS_DIR = paths.DATABASE_DIR
MANIFEST = ACCOUNTS_DIR / "accounts.json"


class TelegramTarget:
    def __init__(self, token, chat_id):
        assert token and chat_id, "telegram target needs token and chat_id"
        self.token = token
        self.chat_id = chat_id


class Account:
    def __init__(self, id, identity, state, telegram, creds_dir=None,
                 plan_status="active", polar_customer_id=None):
        assert id and identity and state and telegram, "account requires id, identity, state, telegram"
        assert identity.account_id == id, (
            f"identity account_id {identity.account_id!r} does not match account id {id!r}"
        )
        self.id = id
        self.identity = identity
        self.state = state
        self.telegram = telegram
        self.creds_dir = creds_dir
        self.plan_status = plan_status
        self.polar_customer_id = polar_customer_id


def _resolve(path):
    p = Path(path)
    return p if p.is_absolute() else (paths.REPO_ROOT / p)


def default_account():
    telegram = TelegramTarget(
        os.environ["TELEGRAM_BOT_TOKEN"],
        os.environ["TELEGRAM_CHAT_ID"],
    )
    return Account(
        id="default",
        identity=pseudonymizer.DEFAULT_IDENTITY,
        state=state.StateStore(state.DEFAULT_STATE_FILE),
        telegram=telegram,
        creds_dir=os.environ.get("GMAIL_MCP_DIR"),
    )


def _account_from_entry(entry):
    aid = entry["id"]
    ident = entry["identity"]
    identity = pseudonymizer.UserIdentity(
        ident["first"],
        ident["last"],
        first_aliases=ident.get("first_aliases", ()),
        emails=ident.get("emails", ()),
        phones=ident.get("phones", ()),
        contacts=ident.get("contacts", ()),
        account_id=aid,
    )
    tg = entry["telegram"]
    token = tg.get("token") or os.environ.get("TELEGRAM_BOT_TOKEN")
    telegram = TelegramTarget(token, tg["chat_id"])
    state_file = _resolve(entry.get("state_file") or (ACCOUNTS_DIR / aid / "state.json"))
    creds_dir = entry.get("creds_dir")
    return Account(
        id=aid,
        identity=identity,
        state=state.StateStore(state_file),
        telegram=telegram,
        creds_dir=str(_resolve(creds_dir)) if creds_dir else None,
        plan_status=entry.get("plan_status", "active"),
        polar_customer_id=entry.get("polar_customer_id"),
    )


def _read_manifest():
    """Raw manifest dict, or None when no store exists (single-tenant box)."""
    if not MANIFEST.exists():
        return None
    return json.loads(MANIFEST.read_text())


def all_accounts():
    """Every registered account regardless of plan status. Billing needs to see
    inactive accounts to reactivate a lapsed subscriber; routing must not, so it
    goes through load_accounts() instead. Falls back to the single-tenant default
    when no manifest exists. The sealed-store swap (Track F) replaces this body."""
    data = _read_manifest()
    if data is None:
        return [default_account()]
    accounts = [_account_from_entry(e) for e in data["accounts"]]
    ids = [a.id for a in accounts]
    assert len(ids) == len(set(ids)), f"duplicate account ids in manifest: {ids}"
    return accounts


def load_accounts():
    """Every registered, active account. The sole entry point for enumerating
    users the pipeline may act on; inactive (unpaid) accounts are filtered here,
    which is the Gmail-processing gate (D2)."""
    return [a for a in all_accounts() if a.plan_status != "inactive"]


def _match(pool, email):
    email = (email or "").strip().lower()
    if not email:
        return None
    for a in pool:
        if a.id.lower() == email or any(e.lower() == email for e in a.identity.emails):
            return a
    return None


def get_account(email):
    """The active account owning `email`, or None. Matches an account id or any
    address in its masking identity, so the single-tenant default (id "default",
    real address in identity.emails) resolves from a Pub/Sub emailAddress too.

    The sole targeted accessor: routing (webhook, daemon) looks up users only
    through here, so callers never construct a creds/token path themselves and
    the sealed-store swap stays contained to this module. Inactive accounts are
    excluded (they are absent from load_accounts), so an unpaid user is
    unroutable end to end."""
    return _match(load_accounts(), email)


def account_for_email(email, include_inactive=True):
    """The account whose id or masking-identity address matches `email`. Billing
    resolves Polar customers to local accounts through here and, unlike
    get_account(), includes inactive accounts so a lapsed subscriber can be
    reactivated on their next payment."""
    return _match(all_accounts() if include_inactive else load_accounts(), email)


def account_for_customer_id(customer_id):
    """The account linked to a Polar customer id via its stored polar_customer_id,
    or None. Onboarding stores this at checkout so billing has an exact link that
    does not depend on the pay-email matching the Gmail address."""
    customer_id = (customer_id or "").strip()
    if not customer_id:
        return None
    for a in all_accounts():
        if a.polar_customer_id and a.polar_customer_id == customer_id:
            return a
    return None


def set_plan_status(account_id, status):
    """Persist `status` ('active'|'inactive') for account_id and return the prior
    status. The sole writer of plan gating: billing flips entitlement only through
    here, so the sealed-store swap stays contained to this module."""
    assert status in ("active", "inactive"), f"invalid plan_status {status!r}"
    data = _read_manifest()
    assert data is not None, "cannot set plan_status without an accounts manifest"
    aid = (account_id or "").strip().lower()
    for entry in data["accounts"]:
        if entry["id"].strip().lower() == aid:
            prior = entry.get("plan_status", "active")
            entry["plan_status"] = status
            MANIFEST.write_text(json.dumps(data, indent=2))
            return prior
    raise KeyError(f"no account with id {account_id!r}")
