"""Per-account context threaded through every processing path.

An Account bundles everything that varies per user: the masking identity, the
state cursor, the notification target, and the Gmail creds directory. A shared
process holds one Account per user without any ambient single-tenant globals.

load_accounts() reads the multi-tenant store (database/accounts.json), one
Account per registered user. The manifest is required: the box owner is a normal
entry in it, seeded once by backend.accounts.seed_owner, not an implicit
fallback. See owner_account() for why.

Store schema (database/accounts.json), one object per user:
    {
      "id": "user@example.com",
      "identity": {"first": "...", "last": "...",
                   "first_aliases": [...], "emails": [...],
                   "phones": [...], "contacts": [...]},
      "creds_dir": "database/user@example.com/.gmail-mcp",
      "state_file": "database/user@example.com/state.json",
      "telegram": {"chat_id": "...", "token": "<optional; shared bot otherwise>"},
      "timezone": "Europe/Berlin",
      "auto_schedule": false,
      "inference_provider": "<optional; llm_client provider name, default deepseek>",
      "pii_analyzer": true,
      "voice_file": "<optional; per-user voice profile>",
      "plan_status": "active",
      "polar_customer_id": "<optional; set at checkout for exact billing link>"
    }
Writers: register_account (introduce), set_plan_status (billing gate),
set_telegram (notification target), set_settings (user preferences), set_voice
(voice profile pointer), delete_account (remove). Nothing outside this module
edits the manifest, so the sealed-store swap has one seam.

Relative creds_dir/state_file paths resolve against the repo root. The manifest
holds per-user PII and tokens, so it is git-ignored, written 0600 inside a 0700
directory, and lives only on the host (a sealed store subclasses this later for
the TEE lift).
"""

import json
import os
import shutil
from pathlib import Path

from backend import paths
from backend.integrations import llm_client
from backend.integrations.telegram import TelegramTarget, bot_token, operator_target
from backend.masking import pseudonymizer
from backend.accounts import state

ACCOUNTS_DIR = paths.DATABASE_DIR
MANIFEST = ACCOUNTS_DIR / "accounts.json"

DEFAULT_TIMEZONE = "UTC"

# Google caps an unverified OAuth app at 100 users, and every signup costs a
# creds directory plus a Gmail watch registration. Signup is unauthenticated, so
# without a ceiling anyone can script it into disk and quota exhaustion.
MAX_ACCOUNTS = int(os.environ.get("LETTERLOCK_MAX_ACCOUNTS", "100"))


class AccountLimitReached(Exception):
    """Raised by register_account when the box is already at MAX_ACCOUNTS."""


class Account:
    def __init__(self, id, identity, state, telegram=None, creds_dir=None,
                 plan_status="active", polar_customer_id=None,
                 timezone=DEFAULT_TIMEZONE, auto_schedule=False, voice_file=None,
                 inference_provider=None, pii_analyzer=True):
        assert id and identity and state, "account requires id, identity, state"
        assert identity.account_id == id, (
            f"identity account_id {identity.account_id!r} does not match account id {id!r}"
        )
        self.id = id
        self.identity = identity
        self.state = state
        # None until the user links a chat. Notifications are skipped rather
        # than redirected: the env fallback that used to live here delivered
        # every new signup's mail metadata to the box owner's Telegram.
        self.telegram = telegram
        self.creds_dir = creds_dir
        self.plan_status = plan_status
        self.polar_customer_id = polar_customer_id
        self.timezone = timezone or DEFAULT_TIMEZONE
        self.auto_schedule = auto_schedule
        self.voice_file = voice_file
        # None means "whatever llm_client defaults to". Stored rather than
        # resolved here so the provider catalog stays in llm_client and an
        # account never pins a stale copy of it.
        self.inference_provider = inference_provider
        # The stated preference, not the effective one: a box without the
        # analyzer installed serves the regex-only path regardless, and
        # pseudonymizer.new_state() is where the two are reconciled. Keeping the
        # preference intact means it comes back if the model is installed later.
        self.pii_analyzer = bool(pii_analyzer)

    @property
    def display_name(self):
        """What the drafter calls this user in a prompt. Masked to [USER_FIRST]
        before it reaches the model and restored afterwards."""
        return self.identity.first

    @property
    def primary_email(self):
        """The mailbox this account owns. For a signup the id is that address,
        but the seeded owner is keyed "default" with the real address in its
        masking identity, so anything building a mail address goes through
        here rather than assuming the id is one."""
        return self.identity.emails[0] if self.identity.emails else self.id


def _resolve(path):
    p = Path(path)
    return p if p.is_absolute() else (paths.REPO_ROOT / p)


def secure_dir(path):
    """Create a directory only its owner can read. It holds Gmail refresh
    tokens; the default 0755 makes every local account able to read them."""
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _write_manifest(data):
    """Sole manifest write. 0600 for the same reason as secure_dir: the file
    carries per-user identity, chat ids, and billing links."""
    secure_dir(ACCOUNTS_DIR)
    tmp = MANIFEST.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.chmod(0o600)
    tmp.replace(MANIFEST)


def owner_account():
    """The box owner's account built from module constants and the environment
    rather than the manifest: DEFAULT_IDENTITY, the historical state.json, the
    env Telegram target, the env Gmail creds.

    This is NOT a runtime fallback. all_accounts() requires a manifest, so an
    unseeded box refuses to route mail instead of inventing an account whose
    existence silently ends the moment anyone signs up. Two callers only: the
    one-time seed (backend.accounts.seed_owner), which turns this into a real
    manifest entry, and the test harness, which needs an account without a
    store."""
    telegram = operator_target()
    assert telegram is not None, (
        "owner_account needs TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in the "
        "environment; those are the operator's own chat"
    )
    return Account(
        id="default",
        identity=pseudonymizer.DEFAULT_IDENTITY,
        state=state.StateStore(state.DEFAULT_STATE_FILE),
        telegram=telegram,
        creds_dir=os.environ.get("GMAIL_MCP_DIR"),
        timezone=os.environ.get("LETTERLOCK_TIMEZONE", DEFAULT_TIMEZONE),
        auto_schedule=True,
    )


def _telegram_from_entry(entry):
    """The account's notification target, or None when no chat is linked.

    The token defaults to the shared bot: one bot serves every account and only
    the chat id varies. A chat id with no bot token anywhere yields None rather
    than a target that cannot send."""
    tg = entry.get("telegram") or {}
    chat_id = tg.get("chat_id")
    if not chat_id:
        return None
    token = tg.get("token") or bot_token()
    if not token:
        return None
    return TelegramTarget(token, chat_id)


def _account_from_entry(entry):
    aid = entry["id"]
    ident = entry["identity"]
    pii_analyzer = bool(entry.get("pii_analyzer", True))
    identity = pseudonymizer.UserIdentity(
        ident["first"],
        ident["last"],
        first_aliases=ident.get("first_aliases", ()),
        emails=ident.get("emails", ()),
        phones=ident.get("phones", ()),
        contacts=ident.get("contacts", ()),
        account_id=aid,
        analyzer=pii_analyzer,
    )
    state_file = _resolve(entry.get("state_file") or (ACCOUNTS_DIR / aid / "state.json"))
    creds_dir = entry.get("creds_dir")
    voice_file = entry.get("voice_file")
    return Account(
        id=aid,
        identity=identity,
        state=state.StateStore(state_file),
        telegram=_telegram_from_entry(entry),
        creds_dir=str(_resolve(creds_dir)) if creds_dir else None,
        plan_status=entry.get("plan_status", "active"),
        polar_customer_id=entry.get("polar_customer_id"),
        timezone=entry.get("timezone", DEFAULT_TIMEZONE),
        auto_schedule=bool(entry.get("auto_schedule", False)),
        voice_file=_resolve(voice_file) if voice_file else None,
        inference_provider=entry.get("inference_provider"),
        pii_analyzer=pii_analyzer,
    )


def _read_manifest():
    """Raw manifest dict, or None when no store exists (single-tenant box)."""
    if not MANIFEST.exists():
        return None
    return json.loads(MANIFEST.read_text())


def all_accounts():
    """Every registered account regardless of plan status. Billing needs to see
    inactive accounts to reactivate a lapsed subscriber; routing must not, so it
    goes through load_accounts() instead. The sealed-store swap (Track F)
    replaces this body.

    The manifest is required. There used to be a fallback to owner_account()
    when it was missing, which meant the first signup by anyone made the owner
    disappear from routing: the manifest existed, so the fallback stopped, and
    the owner had no entry in it. Refusing to run is the safe failure."""
    data = _read_manifest()
    assert data is not None, (
        f"no account manifest at {MANIFEST}. Seed the owner once with "
        "`python -m backend.accounts.seed_owner`."
    )
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


def register_account(email, first, last, creds_dir, *, first_aliases=(),
                     telegram_chat_id=None, telegram_token=None,
                     plan_status="inactive", state_file=None,
                     timezone=None, auto_schedule=False, voice_file=None):
    """Add (or update) a manifest entry for a freshly onboarded user and return
    the loaded Account. The sole writer that introduces users to the store,
    mirroring set_plan_status as the sole plan writer, so onboarding never
    hand-edits the manifest and the sealed-store swap stays contained here.

    New accounts default to plan_status='inactive': the Polar order.paid webhook
    flips them active (Track D), so an unpaid signup is unroutable until payment.

    A Google consent carries no Telegram chat and no environment value stands in
    for one, so a fresh signup has no notification target until the user links a
    chat themselves (frontend settings -> telegram.claim_chat_id). Accounts
    without a target are fully functional; they just get no Telegram messages.

    Raises AccountLimitReached when the box is full. Signup is unauthenticated,
    so the ceiling is what stops a scripted signup flood from exhausting disk and
    Google quota."""
    email = (email or "").strip().lower()
    assert email and "@" in email, f"register_account needs a real email, got {email!r}"
    # The email becomes a directory name under the store; a separator in it
    # would put creds outside their account's home. Google will not issue one,
    # which is exactly why it must be asserted rather than assumed.
    assert not set(email) & {"/", "\\"} and ".." not in email, (
        f"refusing to register an account id with path separators: {email!r}"
    )
    telegram = {}
    if telegram_chat_id:
        telegram["chat_id"] = str(telegram_chat_id)
    if telegram_token:
        telegram["token"] = telegram_token
    entry = {
        "id": email,
        "identity": {
            "first": first,
            "last": last,
            "first_aliases": list(first_aliases),
            "emails": [email],
        },
        "creds_dir": str(creds_dir),
        "telegram": telegram,
        "timezone": timezone or DEFAULT_TIMEZONE,
        "auto_schedule": bool(auto_schedule),
        "plan_status": plan_status,
    }
    if voice_file:
        entry["voice_file"] = str(voice_file)
    # Omitted for a fresh signup, which gets database/<id>/state.json. Passed by
    # the owner seed so the box keeps the Gmail history cursor it already has
    # instead of restarting from an empty one.
    if state_file:
        entry["state_file"] = str(state_file)
    data = _read_manifest() or {"accounts": []}
    accounts = data["accounts"]
    for i, existing in enumerate(accounts):
        if existing["id"].strip().lower() == email:
            # A returning user re-consenting must not lose what they configured.
            entry["plan_status"] = existing.get("plan_status", plan_status)
            entry["telegram"] = {**existing.get("telegram", {}), **telegram}
            entry["timezone"] = existing.get("timezone", entry["timezone"])
            entry["auto_schedule"] = existing.get("auto_schedule", entry["auto_schedule"])
            for carried in ("polar_customer_id", "voice_file"):
                if existing.get(carried) and carried not in entry:
                    entry[carried] = existing[carried]
            if existing.get("state_file") and "state_file" not in entry:
                entry["state_file"] = existing["state_file"]
            accounts[i] = entry
            break
    else:
        if len(accounts) >= MAX_ACCOUNTS:
            raise AccountLimitReached(
                f"account store is at its {MAX_ACCOUNTS}-account limit"
            )
        accounts.append(entry)
    _write_manifest(data)
    return _account_from_entry(entry)


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
            _write_manifest(data)
            return prior
    raise KeyError(f"no account with id {account_id!r}")


def _entry_for(data, account_id):
    aid = (account_id or "").strip().lower()
    for entry in data["accounts"]:
        if entry["id"].strip().lower() == aid:
            return entry
    raise KeyError(f"no account with id {account_id!r}")


def set_telegram(account_id, chat_id=None, token=None, clear=False):
    """Persist an account's notification target and return the loaded Account.
    Sole writer of the telegram block, so the web UI never hand-edits the
    manifest. Omitted fields are left as they were; clear=True unlinks the chat
    entirely, which is how a user turns notifications off (blanking the field
    used to be a silent no-op)."""
    assert clear or chat_id or token, "set_telegram needs a chat_id, a token, or clear"
    data = _read_manifest()
    assert data is not None, "cannot set a telegram target without an accounts manifest"
    entry = _entry_for(data, account_id)
    if clear:
        entry["telegram"] = {}
    else:
        tg = entry.setdefault("telegram", {})
        if chat_id:
            tg["chat_id"] = str(chat_id)
        if token:
            tg["token"] = token
    _write_manifest(data)
    return _account_from_entry(entry)


def set_polar_customer_id(account_id, customer_id):
    """Link an account to its Polar customer and return the loaded Account. Sole
    writer of polar_customer_id.

    account_for_customer_id() and portal_url() have always read this field, but
    nothing wrote it, so every account carried None: the customer-portal link
    could never render and every billing event had to be resolved by matching the
    pay-email against the Gmail address. The checkout return sets it."""
    assert customer_id, "set_polar_customer_id needs a customer id"
    data = _read_manifest()
    assert data is not None, "cannot link a Polar customer without an accounts manifest"
    entry = _entry_for(data, account_id)
    entry["polar_customer_id"] = str(customer_id)
    _write_manifest(data)
    return _account_from_entry(entry)


def set_voice(account_id, voice_file=None, clear=False):
    """Persist which file holds an account's voice profile and return the loaded
    Account. Sole writer of voice_file, for the same reason as set_telegram:
    backend.drafting.voice_dna owns the document, this owns the pointer to it.
    clear=True drops the pointer, which puts the account back on the default
    profile."""
    assert clear or voice_file, "set_voice needs a voice_file or clear"
    data = _read_manifest()
    assert data is not None, "cannot set a voice profile without an accounts manifest"
    entry = _entry_for(data, account_id)
    if clear:
        entry.pop("voice_file", None)
    else:
        entry["voice_file"] = str(voice_file)
    _write_manifest(data)
    return _account_from_entry(entry)


def set_settings(account_id, timezone=None, auto_schedule=None,
                 inference_provider=None, pii_analyzer=None):
    """Persist the per-user preferences the web UI owns and return the loaded
    Account. Sole writer of them, for the same reason as set_telegram.

    pii_analyzer is stored as asked even on a box that cannot run the analyzer:
    availability is a property of the box, the preference is the user's, and
    pseudonymizer.new_state() decides what actually runs."""
    assert (timezone is not None or auto_schedule is not None
            or inference_provider is not None
            or pii_analyzer is not None), "set_settings needs something to set"
    data = _read_manifest()
    assert data is not None, "cannot set settings without an accounts manifest"
    entry = _entry_for(data, account_id)
    if timezone is not None:
        entry["timezone"] = timezone
    if auto_schedule is not None:
        entry["auto_schedule"] = bool(auto_schedule)
    if inference_provider is not None:
        provider = llm_client.PROVIDERS.get(inference_provider)
        assert provider is not None, (
            f"unknown inference provider {inference_provider!r}; "
            f"known: {sorted(llm_client.PROVIDERS)}"
        )
        assert provider.configured(), (
            f"provider {provider.name!r} cannot be selected: {provider.key_env} "
            f"is not set on this box"
        )
        entry["inference_provider"] = provider.name
    if pii_analyzer is not None:
        entry["pii_analyzer"] = bool(pii_analyzer)
    _write_manifest(data)
    return _account_from_entry(entry)


def _owned_paths(entry):
    """The files an entry owns outright, meaning the ones under its own
    directory in the store (ACCOUNTS_DIR/<id>/) -- where provisioning puts a
    signup's creds and where an unspecified state file defaults to.

    Anything outside it is shared: the seeded owner points at the top-level
    .gmail-mcp and state/, which belong to the box and outlive any one entry, so
    deleting the owner's account must not wipe the box's Gmail tokens. The same
    rule covers the voice profile: a generated one lives in the account's own
    directory and goes, while the operator's copy under config/ is only unlinked
    from. Keying on the entry's own directory rather than on the store root keeps
    that true even if the store were ever configured to sit at the app root."""
    home = ACCOUNTS_DIR / entry["id"]
    owned = []
    for value in (entry.get("creds_dir"), entry.get("state_file"),
                  entry.get("voice_file")):
        if not value:
            continue
        path = _resolve(value)
        if path != home and home not in path.parents:
            continue
        owned.append(path)
    return owned


def delete_account(account_id):
    """Remove an account and the credentials it owns. Sole deleter, mirroring
    register_account as the sole writer.

    A user asking to be deleted is asking us to stop holding their Gmail refresh
    token, so the per-user creds directory goes too -- dropping the manifest row
    alone would leave a live token on disk with nothing referencing it. Returns
    True when an entry was removed.

    Not revocation: the token stops being ours but stays valid at Google until
    the user revokes access in their account settings."""
    data = _read_manifest()
    assert data is not None, "cannot delete an account without an accounts manifest"
    aid = (account_id or "").strip().lower()
    remaining = [e for e in data["accounts"] if e["id"].strip().lower() != aid]
    removed = [e for e in data["accounts"] if e["id"].strip().lower() == aid]
    if not removed:
        return False
    data["accounts"] = remaining
    _write_manifest(data)
    for path in _owned_paths(removed[0]):
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        elif path.exists():
            path.unlink()
    return True
