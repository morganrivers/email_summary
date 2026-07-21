"""Per-account context threaded through every processing path.

An Account bundles everything that varies per user: the masking identity, the
state cursor, the notification target, and the Gmail creds directory. A shared
process holds one Account per user without any ambient single-tenant globals.

load_accounts() reads the multi-tenant store (accounts/accounts.json) when it
exists, one Account per registered user. When the manifest is absent it falls
back to default_account(), which reproduces the historical single-tenant config
(Morgan's identity, state.json, env-based Telegram, default Gmail creds), so the
deployed single-tenant box behaves exactly as the pre-refactor code did.

Store schema (accounts/accounts.json), one object per user:
    {
      "id": "user@example.com",
      "identity": {"first": "...", "last": "...",
                   "first_aliases": [...], "emails": [...],
                   "phones": [...], "contacts": [...]},
      "creds_dir": "accounts/user@example.com/.gmail-mcp",
      "state_file": "accounts/user@example.com/state.json",
      "telegram": {"chat_id": "...", "token": "<optional; env fallback>"},
      "plan_status": "active"
    }
Relative creds_dir/state_file paths resolve against this script's directory.
The manifest holds per-user PII and tokens, so it is git-ignored and lives only
on the host (a sealed store subclasses this later for the TEE lift).
"""

import json
import os
from pathlib import Path

import pseudonymizer
import state

SCRIPT_DIR = Path(__file__).parent
ACCOUNTS_DIR = SCRIPT_DIR / "accounts"
MANIFEST = ACCOUNTS_DIR / "accounts.json"


class TelegramTarget:
    def __init__(self, token, chat_id):
        assert token and chat_id, "telegram target needs token and chat_id"
        self.token = token
        self.chat_id = chat_id


class Account:
    def __init__(self, id, identity, state, telegram, creds_dir=None, plan_status="active"):
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


def _resolve(path):
    p = Path(path)
    return p if p.is_absolute() else (SCRIPT_DIR / p)


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
    )


def load_accounts():
    """Every registered, active account. The sole entry point for enumerating
    users; the sealed-store swap (Track F) replaces this body alone."""
    if not MANIFEST.exists():
        return [default_account()]
    data = json.loads(MANIFEST.read_text())
    accounts = [_account_from_entry(e) for e in data["accounts"]]
    ids = [a.id for a in accounts]
    assert len(ids) == len(set(ids)), f"duplicate account ids in manifest: {ids}"
    return [a for a in accounts if a.plan_status != "inactive"]


def get_account(email):
    """The active account owning `email`, or None. Matches an account id or any
    address in its masking identity, so the single-tenant default (id "default",
    real address in identity.emails) resolves from a Pub/Sub emailAddress too.

    The sole targeted accessor: routing (webhook, daemon) looks up users only
    through here, so callers never construct a creds/token path themselves and
    the sealed-store swap stays contained to this module."""
    email = (email or "").strip().lower()
    if not email:
        return None
    for a in load_accounts():
        if a.id.lower() == email or any(e.lower() == email for e in a.identity.emails):
            return a
    return None
