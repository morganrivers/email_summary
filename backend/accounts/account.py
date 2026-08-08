"""Per-account context threaded through every processing path.

An Account bundles everything that varies per user: the masking identity, the
state cursor, the notification target, and the custody record its Gmail access
is derived from. A shared process holds one Account per user without any ambient
single-tenant globals.

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
      "token_file": "database/user@example.com/token.bin",
      "state_file": "database/user@example.com/state.json",
      "telegram": {"chat_id": "...", "token": "<optional; shared bot otherwise>"},
      "timezone": "Europe/Berlin",
      "auto_schedule": false,
      "community_calendar": "<optional; a second calendar id read into the summary>",
      "inference_provider": "<optional; llm_client provider name, default deepseek>",
      "pii_analyzer": true,
      "ban_dashes": true,
      "voice_file": "<optional; per-user voice profile>",
      "plan_status": "active",
      "polar_customer_id": "<optional; set at checkout for exact billing link>"
    }
Writers: register_account (introduce), set_plan_status (billing gate),
set_telegram (notification target), set_settings (user preferences), set_voice
(voice profile pointer), delete_account (remove). Nothing outside this module
edits the manifest, so the sealed-store swap has one seam.

Each of those writers records what it did to backend.audit, after the write
rather than before it, so the log never claims a change the manifest did not
take. The call belongs here rather than in the route handlers for the same
reason the manifest write does: a second caller cannot forget what the sole
writer already does.

Relative token_file/state_file paths resolve against the repo root. The manifest
holds per-user PII, so it is git-ignored, written 0600 inside a 0700 directory,
and lives only on the host (a sealed store subclasses this later for the TEE
lift). It no longer holds anything that can reach a mailbox: the token itself is
a nested-wrapped record (backend.custody.tokens) that this box cannot open on
its own.
"""

import json
import os
import re
import shutil
from pathlib import Path

from backend import audit
from backend import paths
from backend import secrets
from backend.integrations import llm_client
from backend.integrations.telegram import TelegramTarget, bot_token, operator_target
from backend.masking import pseudonymizer
from backend.accounts import state

ACCOUNTS_DIR = paths.DATABASE_DIR
MANIFEST = ACCOUNTS_DIR / "accounts.json"

DEFAULT_TIMEZONE = "UTC"

# What a Google calendar id looks like: an address, which is what both a shared
# calendar and an imported one are named by. Checked rather than trusted because
# the value is typed by a user and then handed to the Calendar API as a path
# segment. Defined here rather than in calendar_api because that module imports
# the Google client, which imports custody, which imports this one.
CALENDAR_ID_RE = re.compile(r"[a-z0-9][a-z0-9._%+-]{0,127}@[a-z0-9.-]{1,128}\.[a-z]{2,24}")

# The name an account is known by off this box.
#
# The co-signer needs a stable per-user value to enforce its per-uid ceiling and
# its wrap-once rule. It does not need that value to be a name, and while it was
# one, the co-signer's audit table was a copy of the customer list plus a
# timestamped record of when each of those people's mail was processed -- on the
# box whose stated premise is that compromising it yields nothing worth having.
#
# 128 bits from the system CSPRNG, stored rather than derived: there is no key
# to lose and no function to invert, so the mapping back to a person exists in
# exactly one file (this manifest) and nowhere else. Only the enclave can make
# it, which is what `whois` is for.
HANDLE_BYTES = 16
HANDLE_RE = re.compile(r"\A[0-9a-f]{%d}\Z" % (HANDLE_BYTES * 2))

# The box owner's own identity, for the one-time seed. It is configuration and
# not a constant, because the operator of a given box is not a fact about this
# software: hardcoding a name and an address here would ship one person's PII in
# an open source repository and mask every other account's mail under it. Read
# through secrets.get so a .env on the box is enough, the same route the
# operator's Telegram chat takes.
OWNER_EMAIL_ENV = "LETTERLOCK_OWNER_EMAIL"
OWNER_FIRST_ENV = "LETTERLOCK_OWNER_FIRST"
OWNER_LAST_ENV = "LETTERLOCK_OWNER_LAST"
OWNER_FIRST_ALIASES_ENV = "LETTERLOCK_OWNER_FIRST_ALIASES"

# Google caps an unverified OAuth app at 100 users, and every signup costs a
# creds directory plus a Gmail watch registration. Signup is unauthenticated, so
# without a ceiling anyone can script it into disk and quota exhaustion.
MAX_ACCOUNTS = int(os.environ.get("LETTERLOCK_MAX_ACCOUNTS", "100"))


class AccountLimitReached(Exception):
    """Raised by register_account when the box is already at MAX_ACCOUNTS."""


class Account:
    def __init__(self, id, identity, state, telegram=None, token_file=None,
                 plan_status="active", polar_customer_id=None,
                 timezone=DEFAULT_TIMEZONE, auto_schedule=False, voice_file=None,
                 inference_provider=None, pii_analyzer=True, ban_dashes=True,
                 handle=None, community_calendar=None):
        assert id and identity and state, "account requires id, identity, state"
        assert identity.account_id == id, (
            f"identity account_id {identity.account_id!r} does not match account id {id!r}"
        )
        self.id = id
        # None for an account that predates the opaque handle, and for the
        # unstored owner_account(). Custody refuses to work without one rather
        # than falling back to the id, because a fallback would put an address
        # back on the co-signer's wire the first time an entry was hand-edited.
        self.handle = handle
        self.identity = identity
        self.state = state
        # None until the user links a chat. Notifications are skipped rather
        # than redirected: the env fallback that used to live here delivered
        # every new signup's mail metadata to the box owner's Telegram.
        self.telegram = telegram
        # Where this account's wrapped refresh token sits. Not a credential:
        # opening it takes the enclave's KMS key and a co-signer round trip.
        # None until the user has consented.
        self.token_file = token_file
        self.plan_status = plan_status
        self.polar_customer_id = polar_customer_id
        self.timezone = timezone or DEFAULT_TIMEZONE
        self.auto_schedule = auto_schedule
        # A second calendar this user wants read into their daily summary, or
        # None. Per account and never a box-wide default: a calendar id names
        # one person's subscription, so a constant here would put the operator's
        # own community events into every other user's summary.
        self.community_calendar = community_calendar or None
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
        # Whether a draft carrying an em-dash or en-dash is retried and then
        # rejected. Sole answer to that question: the rule used to be read out of
        # the voice document's text, which meant two places (the document and
        # the drafter's own punctuation rule) had to agree about one behaviour.
        self.ban_dashes = bool(ban_dashes)

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


def new_handle():
    """A fresh opaque account handle. Sole generator, so the length and the
    alphabet are stated once and `HANDLE_RE` can be trusted to describe every
    handle that exists."""
    return os.urandom(HANDLE_BYTES).hex()


def check_handle(handle):
    """The handle, or an assertion. Everything that sends one to the co-signer
    or derives a key from one calls this first: a caller that passed an account
    id by mistake would otherwise put the address back on the wire and, worse,
    derive a different key with it, so the mistake would surface as unopenable
    records rather than as a leak anyone noticed."""
    assert handle and HANDLE_RE.match(str(handle)), (
        f"not an account handle: {handle!r}. An account registered before "
        "handles existed has none; re-onboard it through /auth/callback."
    )
    return str(handle)


def handle_for_email(email):
    """This account's handle, or None when there is no such account and when
    there is no manifest at all.

    Tolerates a missing manifest because the first signup on a fresh box happens
    before one exists, and `all_accounts()` deliberately refuses that case."""
    data = _read_manifest()
    if data is None:
        return None
    wanted = (email or "").strip().lower()
    for entry in data["accounts"]:
        if entry["id"].strip().lower() == wanted:
            return entry.get("handle")
    return None


def email_for_handle(handle):
    """The person behind an opaque handle, or None. The enclave is the only
    place this mapping exists; `backend.accounts.whois` is the operator command
    that reads it, and it is why making the co-signer's log opaque does not make
    an incident unactionable."""
    data = _read_manifest()
    if data is None:
        return None
    for entry in data["accounts"]:
        if entry.get("handle") == handle:
            return entry["id"]
    return None


def _resolve(path):
    p = Path(path)
    return p if p.is_absolute() else (paths.REPO_ROOT / p)


def secure_dir(path):
    """Create a directory only its owner can read. It holds each account's
    identity and its wrapped token; the default 0755 makes every local account
    able to read them."""
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def check_id(account_id):
    """Refuse an id that would name a path outside the account's own directory.

    The id is a directory name under the store and it arrives from Google's
    profile response, so a separator in one puts an account's files outside its
    own home or reads another account's. Exported because custody, onboarding
    and the document modules all build paths from it; one guard is one that
    cannot be relaxed for a single caller."""
    assert account_id and "/" not in account_id and "\\" not in account_id \
        and ".." not in account_id, (
        f"refusing to build an account path from {account_id!r}"
    )
    return account_id


def account_dir(account_id):
    """The one directory an account owns: its wrapped data key, its refresh
    token, its documents, its state file.

    Sole definition, so `_owned_paths` (and therefore `delete_account`) cannot
    fall out of step with the modules that write into it."""
    home = ACCOUNTS_DIR / check_id(account_id)
    assert home.parent == ACCOUNTS_DIR, (
        f"account id {account_id!r} does not name a directory in the store"
    )
    return home


def _write_manifest(data):
    """Sole manifest write. 0600 for the same reason as secure_dir: the file
    carries per-user identity, chat ids, and billing links."""
    secure_dir(ACCOUNTS_DIR)
    tmp = MANIFEST.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.chmod(0o600)
    tmp.replace(MANIFEST)


def owner_identity():
    """The masking identity of whoever runs this box, from the environment.

    Nothing in the repository names a person, so this is the one place an
    operator's own name and address enter the process, and it enters as
    configuration they set. Aliases are comma separated: a Google profile often
    carries a formal first name where the mail addresses a nickname, and the
    masker has to tag both."""
    email = (secrets.get(OWNER_EMAIL_ENV) or "").strip().lower()
    first = (secrets.get(OWNER_FIRST_ENV) or "").strip()
    last = (secrets.get(OWNER_LAST_ENV) or "").strip()
    assert email and "@" in email, (
        f"{OWNER_EMAIL_ENV} must be the owner's mailbox address; it is what the "
        "seed registers and what masking tags as the account owner"
    )
    assert first and last, (
        f"{OWNER_FIRST_ENV} and {OWNER_LAST_ENV} must be set; the masker tags the "
        "owner's own name deterministically and cannot do it from an address"
    )
    aliases = [a.strip() for a in (secrets.get(OWNER_FIRST_ALIASES_ENV) or "").split(",")]
    return pseudonymizer.UserIdentity(
        first, last,
        first_aliases=[a for a in aliases if a],
        emails=[email],
        account_id="default",
    )


def owner_account():
    """The box owner's account built from the environment rather than the
    manifest: owner_identity(), the historical state.json, the env Telegram
    target.

    It carries no Gmail custody. The owner gets a token the same way everyone
    else does, by consenting through /auth/callback; there is no environment
    variable that points at a mailbox any more, because there is no longer a
    credentials file for one to point at.

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
    # A fresh handle on every call, because this account is not in the manifest
    # and there is nowhere for a stable one to come from. That is correct for
    # both callers: the seed writes the one it is handed and the manifest owns it
    # from then on, and the test harness never takes custody. An account whose
    # handle changed between calls could not open its own records, which is why
    # this is the only place one is minted outside register_account.
    return Account(
        id="default",
        identity=owner_identity(),
        state=state.StateStore(state.DEFAULT_STATE_FILE),
        telegram=telegram,
        timezone=os.environ.get("LETTERLOCK_TIMEZONE", DEFAULT_TIMEZONE),
        auto_schedule=True,
        handle=new_handle(),
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
    token_file = entry.get("token_file")
    voice_file = entry.get("voice_file")
    return Account(
        id=aid,
        identity=identity,
        state=state.StateStore(state_file),
        telegram=_telegram_from_entry(entry),
        token_file=str(_resolve(token_file)) if token_file else None,
        plan_status=entry.get("plan_status", "active"),
        polar_customer_id=entry.get("polar_customer_id"),
        timezone=entry.get("timezone", DEFAULT_TIMEZONE),
        auto_schedule=bool(entry.get("auto_schedule", False)),
        community_calendar=entry.get("community_calendar"),
        voice_file=_resolve(voice_file) if voice_file else None,
        inference_provider=entry.get("inference_provider"),
        pii_analyzer=pii_analyzer,
        ban_dashes=bool(entry.get("ban_dashes", True)),
        handle=entry.get("handle"),
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
    handles = [a.handle for a in accounts if a.handle]
    assert len(handles) == len(set(handles)), (
        "two accounts share an opaque handle, so one can open the other's "
        "records and spend the other's co-signer budget"
    )
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


def register_account(email, first, last, *, token_file=None, first_aliases=(),
                     telegram_chat_id=None, telegram_token=None,
                     plan_status="inactive", state_file=None,
                     timezone=None, auto_schedule=False, voice_file=None,
                     handle=None):
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
    # would put an account's files outside its own home. Google will not issue
    # one, which is exactly why it must be asserted rather than assumed.
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
        # Minted here when the caller has none. Onboarding passes the one it
        # already looked up, because custody is taken before the entry is
        # written and both halves have to name the same account.
        "handle": check_handle(handle or new_handle()),
        "identity": {
            "first": first,
            "last": last,
            "first_aliases": list(first_aliases),
            "emails": [email],
        },
        "telegram": telegram,
        "timezone": timezone or DEFAULT_TIMEZONE,
        "auto_schedule": bool(auto_schedule),
        "plan_status": plan_status,
    }
    if token_file:
        entry["token_file"] = str(token_file)
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
            # The handle least of all: every record this account owns is
            # encrypted with it as the salt and the AAD, so a new one on a
            # re-consent would leave the user's own data unreadable.
            if existing.get("handle"):
                entry["handle"] = check_handle(existing["handle"])
            entry["plan_status"] = existing.get("plan_status", plan_status)
            entry["telegram"] = {**existing.get("telegram", {}), **telegram}
            entry["timezone"] = existing.get("timezone", entry["timezone"])
            entry["auto_schedule"] = existing.get("auto_schedule", entry["auto_schedule"])
            # The rest of what set_settings owns, carried by presence rather than
            # by truthiness: a stored False is a choice the user made, and a
            # truthiness test would silently reset it to the default on the next
            # consent. A re-consent is a Google round trip, not a preferences
            # reset.
            for setting in ("inference_provider", "pii_analyzer", "ban_dashes",
                            "community_calendar"):
                if setting in existing:
                    entry[setting] = existing[setting]
            # token_file is carried for the seed's sake: seeding the owner after
            # they have already signed in must not drop the custody record the
            # sign-in wrote, since nothing outside a consent can recreate it.
            for carried in ("polar_customer_id", "voice_file", "token_file"):
                if existing.get(carried) and carried not in entry:
                    entry[carried] = existing[carried]
            if existing.get("state_file") and "state_file" not in entry:
                entry["state_file"] = existing["state_file"]
            accounts[i] = entry
            outcome = "updated"
            break
    else:
        if len(accounts) >= MAX_ACCOUNTS:
            raise AccountLimitReached(
                f"account store is at its {MAX_ACCOUNTS}-account limit"
            )
        accounts.append(entry)
        outcome = "created"
    _write_manifest(data)
    audit.record(email, audit.ACCOUNT, outcome)
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
            audit.record(entry["id"], audit.PLAN, status, (f"from:{prior}",))
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
        changed = ()
    else:
        tg = entry.setdefault("telegram", {})
        if chat_id:
            tg["chat_id"] = str(chat_id)
        if token:
            tg["token"] = token
        changed = tuple(name for name, given in (("chat_id", chat_id), ("token", token))
                        if given)
    _write_manifest(data)
    audit.record(entry["id"], audit.TELEGRAM,
                 "unlinked" if clear else "linked", changed)
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
    audit.record(entry["id"], audit.BILLING_CUSTOMER, "linked")
    return _account_from_entry(entry)


def set_voice(account_id, voice_file=None, clear=False):
    """Persist which file holds an account's voice profile and return the loaded
    Account. Sole writer of voice_file, for the same reason as set_telegram:
    backend.drafting.voice_dna owns the document, this owns the pointer to it.
    clear=True drops the pointer, which puts the account back on the default
    profile.

    This is also where an edit to the voice document is audited, rather than in
    voice_dna: save() and clear() each call this exactly once, so logging here
    is one row per edit, and logging in both places would be two."""
    assert clear or voice_file, "set_voice needs a voice_file or clear"
    data = _read_manifest()
    assert data is not None, "cannot set a voice profile without an accounts manifest"
    entry = _entry_for(data, account_id)
    if clear:
        entry.pop("voice_file", None)
    else:
        entry["voice_file"] = str(voice_file)
    _write_manifest(data)
    audit.record(entry["id"], audit.VOICE, "cleared" if clear else "saved")
    return _account_from_entry(entry)


def set_settings(account_id, timezone=None, auto_schedule=None,
                 inference_provider=None, pii_analyzer=None, ban_dashes=None,
                 community_calendar=None):
    """Persist the per-user preferences the web UI owns and return the loaded
    Account. Sole writer of them, for the same reason as set_telegram.

    community_calendar is the one field a user can empty: "" clears it, None
    means the caller did not ask. The others are a timezone that always has a
    value, a radio group that always has one selected, and checkboxes.

    pii_analyzer is stored as asked even on a box that cannot run the analyzer:
    availability is a property of the box, the preference is the user's, and
    pseudonymizer.new_state() decides what actually runs.

    The audit row names the fields that actually changed, not the fields the
    form submitted: the settings form posts every field on every save, so
    logging what arrived would say a user changed five things every time they
    changed one."""
    assert (timezone is not None or auto_schedule is not None
            or inference_provider is not None
            or pii_analyzer is not None
            or ban_dashes is not None
            or community_calendar is not None), "set_settings needs something to set"
    data = _read_manifest()
    assert data is not None, "cannot set settings without an accounts manifest"
    entry = _entry_for(data, account_id)
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
        inference_provider = provider.name
    asked = (
        ("timezone", timezone, DEFAULT_TIMEZONE),
        ("auto_schedule", None if auto_schedule is None else bool(auto_schedule), False),
        ("inference_provider", inference_provider, None),
        ("pii_analyzer", None if pii_analyzer is None else bool(pii_analyzer), True),
        ("ban_dashes", None if ban_dashes is None else bool(ban_dashes), True),
    )
    changed = tuple(field for field, value, default in asked
                    if value is not None and entry.get(field, default) != value)
    for field, value, _ in asked:
        if value is not None:
            entry[field] = value
    if community_calendar is not None:
        calendar = community_calendar.strip().lower()
        assert not calendar or CALENDAR_ID_RE.fullmatch(calendar), (
            f"{calendar!r} is not a calendar id; the caller validates this before "
            "asking, so reaching here means an unchecked path"
        )
        if entry.get("community_calendar", "") != calendar:
            changed += ("community_calendar",)
        if calendar:
            entry["community_calendar"] = calendar
        else:
            entry.pop("community_calendar", None)
    _write_manifest(data)
    audit.record(entry["id"], audit.SETTINGS,
                 "saved" if changed else "unchanged", changed)
    return _account_from_entry(entry)


def _owned_paths(entry):
    """The files an entry owns outright, meaning everything under its own
    directory in the store (ACCOUNTS_DIR/<id>/) -- where provisioning puts a
    signup's wrapped token, where an unspecified state file defaults to, and
    where the documents the user writes about themselves live.

    The directory is the unit rather than a list of manifest keys, because not
    every document has a key: backend.drafting.personal_context derives its path
    instead of storing a pointer, so a key list would have quietly left a user's
    personal information on disk after they asked to be deleted.

    Anything outside the directory is shared: the seeded owner points at the
    box's own state/, which outlives any one entry, so deleting the owner's
    account must not wipe it. The same rule covers the voice profile: a
    generated one lives in the account's own directory and goes, while the
    operator's copy under config/ is only unlinked from."""
    home = account_dir(entry["id"])
    return [home] if home.is_dir() else []


def delete_account(account_id):
    """Remove an account and the files it owns. Sole deleter, mirroring
    register_account as the sole writer.

    A user asking to be deleted is asking us to stop holding their Gmail refresh
    token, so the custody record goes too -- dropping the manifest row alone
    would leave a wrapped token on disk with nothing referencing it. Returns
    True when an entry was removed.

    Not revocation: the token stops being ours but stays valid at Google until
    the user revokes access in their account settings.

    The account's audit rows are the one thing that does not go with it. The row
    saying an account was deleted is worth more than any other row in the table,
    and a log a user can empty by asking is not a log; backend.audit.RETENTION_DAYS
    is what bounds how long their address stays there."""
    data = _read_manifest()
    assert data is not None, "cannot delete an account without an accounts manifest"
    aid = (account_id or "").strip().lower()
    remaining = [e for e in data["accounts"] if e["id"].strip().lower() != aid]
    removed = [e for e in data["accounts"] if e["id"].strip().lower() == aid]
    if not removed:
        return False
    data["accounts"] = remaining
    _write_manifest(data)
    audit.record(removed[0]["id"], audit.ACCOUNT, "deleted")
    # The data key first, then the files it opened. That order is what makes
    # this a deletion rather than an unlinking: everything below becomes bytes
    # nobody can read the moment the key is gone, so an rmtree interrupted
    # halfway leaves ciphertext instead of a half-deleted account, and a backup
    # of the directory taken this morning does not become readable again by
    # being restored.
    #
    # Imported here rather than at the top because custody is built on this
    # module and the reverse import would be a cycle. The direction is
    # deliberate -- the store knows nothing about crypto -- and this one call is
    # the exception deletion requires.
    from backend.custody import keyring
    keyring.destroy(removed[0]["id"])
    for path in _owned_paths(removed[0]):
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        elif path.exists():
            path.unlink()
    return True
