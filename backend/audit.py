"""One SQLite row per change a person made to their account: who, what, when.

The co-signer logs every custody decision (`cosigner/audit.py`). Nothing else
was logged anywhere but stderr, which goes to the journal, is unstructured, and
rotates on the host default. There was no record of who signed in, what they
changed, or that an account was deleted. This is that record, for the
application side.

**This is deliberately not the co-signer's log, and shares no code with it.**
The co-signer must not learn who its users are (Track F makes its `uid` opaque
precisely so it cannot), and `cosigner/` imports nothing from `backend/` except
the Telegram seam, so it stays movable to its own box under its own operator. A
shared SQLite helper would break that in the wrong direction. The thirty lines
of connection boilerplate the two modules have in common are the price of the
trust boundary, not an oversight to factor out.

Invariant, the same one `cosigner/audit.py` states: **no content, ever.** Not a
token, not a cookie, not a document body, not a chat id. `record()` has no
parameter that can carry one:

    account_id  the account the change belongs to
    action      one of ACTIONS, a closed set
    outcome     what happened, a single short token
    detail      a tuple of short tokens naming *which* fields changed

`detail` is a sequence of tokens matching TOKEN, not free text. A field name
(`timezone`), a small count (`chars:2048`) or a small enum (`provider:deepseek`)
fits; a document body cannot, and the shape is checked rather than trusted. If
you find yourself wanting to widen this for debugging, that is the change an
attacker who reads this file is hoping someone made.

Where the row comes from -- the browser's address and user agent -- is ambient
rather than a parameter, because the writers are the account mutators in
`backend/accounts/account.py` and they have no request in scope. The web server
opens a `request_context()` around each request; anything running outside one (a
background voice generation, the billing webhook, the seed) writes a row with no
origin, which is itself the correct answer.

A failing write propagates. Silently swallowing it would mean a box that keeps
mutating accounts with no trail, which is the state this module exists to end.

Retention: rows older than RETENTION_DAYS are pruned. An account deletion does
*not* take that account's rows with it -- the row saying the account was deleted
is the one most worth keeping -- so the retention window is the only bound on
how long a departed user's address stays here.
"""

import contextlib
import os
import re
import sqlite3
import threading
import time
from pathlib import Path

from backend import paths

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    account_id  TEXT NOT NULL,
    action      TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    detail      TEXT,
    source_ip   TEXT,
    user_agent  TEXT
);
CREATE INDEX IF NOT EXISTS events_account_ts ON events (account_id, ts);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
"""

SIGN_IN = "sign-in"
SIGN_OUT = "sign-out"
CONSENT = "consent"
ACCOUNT = "account"
SETTINGS = "settings"
TELEGRAM = "telegram"
VOICE = "voice"
PERSONAL = "personal-context"
PLAN = "plan"
BILLING_CUSTOMER = "billing-customer"

ACTIONS = frozenset({SIGN_IN, SIGN_OUT, CONSENT, ACCOUNT, SETTINGS, TELEGRAM,
                     VOICE, PERSONAL, PLAN, BILLING_CUSTOMER})

TOKEN = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,31}\Z")

MAX_DETAIL_TOKENS = 12

# A user agent is a fingerprint, not evidence, and the interesting part is at
# the front. Truncating bounds what a client can write into the file.
MAX_USER_AGENT = 200

# Long enough to answer a dispute that spans a full billing cycle plus a margin
# ("I never changed that", "when did they cancel"), short enough that a table of
# addresses paired with an activity timeline does not accumulate for years. The
# rows are one per human action, so this is a privacy bound rather than a
# volume one.
RETENTION_DAYS = 180

# How often a running process bothers to check. Pruning is cheap and the table
# is small; doing it from record() rather than a timer means there is no unit to
# forget to deploy.
PRUNE_INTERVAL = 3600

_LOCK = threading.Lock()
_CONN = None
_LAST_PRUNE = 0.0

_ORIGIN = threading.local()


def state_dir():
    """Where the log lives. Overridable so a test can point at a fresh
    directory without inheriting the checkout's own state/."""
    override = os.environ.get("LETTERLOCK_AUDIT_DIR")
    return Path(override) if override else paths.ensure_run_dir()


def db_path():
    return state_dir() / "audit.db"


def connect():
    """One connection, shared across the web server's threads under `_LOCK`.

    `secure_delete` is on because the prune is the whole point of a retention
    period: without it SQLite leaves deleted rows readable in the file's free
    list, and a table whose stated job is not to hand over a customer list would
    hand over the pruned half of one."""
    global _CONN
    if _CONN is None:
        path = db_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), check_same_thread=False)
        conn.execute("PRAGMA secure_delete=ON")
        conn.executescript(SCHEMA)
        conn.commit()
        try:
            path.chmod(0o600)
        except OSError:
            pass
        _CONN = conn
    return _CONN


def reset_for_test(path=None):
    """Drop the cached connection so a test can point at a fresh directory."""
    global _CONN, _LAST_PRUNE
    with _LOCK:
        if _CONN is not None:
            _CONN.close()
        _CONN = None
        _LAST_PRUNE = 0.0
    if path is not None:
        os.environ["LETTERLOCK_AUDIT_DIR"] = str(path)


@contextlib.contextmanager
def request_context(source_ip=None, user_agent=None):
    """Attach a browser origin to every row written on this thread.

    The mutators that write the rows are the manifest writers, which is where a
    second caller cannot forget to log; they have no request in scope and should
    not grow a parameter for one. The web server wraps each request in this, so
    the origin travels with the thread instead of through nine signatures.

    Nested and restored on exit: one connection thread serves several keep-alive
    requests, so leaving a stale origin behind would attribute one user's change
    to another's address."""
    previous = getattr(_ORIGIN, "value", None)
    _ORIGIN.value = (source_ip or None, (user_agent or "")[:MAX_USER_AGENT] or None)
    try:
        yield
    finally:
        _ORIGIN.value = previous


def origin():
    """The (source_ip, user_agent) of the request being served on this thread,
    or (None, None) outside one."""
    return getattr(_ORIGIN, "value", None) or (None, None)


def _detail_string(detail):
    """`detail` as it is stored: comma-joined tokens, or None when empty.

    Every token is checked into shape rather than trusted, which is what stops a
    caller passing a document body, an address or a token as "context"."""
    tokens = tuple(detail or ())
    assert len(tokens) <= MAX_DETAIL_TOKENS, (
        f"audit detail takes at most {MAX_DETAIL_TOKENS} tokens, got {len(tokens)}"
    )
    for token in tokens:
        assert isinstance(token, str) and TOKEN.fullmatch(token), (
            f"audit detail takes short name tokens, not values: {token!r}"
        )
    return ",".join(tokens) or None


def record(account_id, action, outcome, detail=(), ts=None):
    """Write one row. Arguments are identifiers, verdicts and field names only;
    there is deliberately no parameter that can carry a token, a cookie or a
    document body."""
    assert account_id, "audit.record requires an account id"
    assert action in ACTIONS, f"unknown audit action {action!r}; known: {sorted(ACTIONS)}"
    assert isinstance(outcome, str) and TOKEN.fullmatch(outcome), (
        f"audit outcome must be a short token, got {outcome!r}"
    )
    detail = _detail_string(detail)
    source_ip, user_agent = origin()
    now = float(ts if ts is not None else time.time())
    with _LOCK:
        conn = connect()
        conn.execute(
            "INSERT INTO events (ts, account_id, action, outcome, detail, "
            "source_ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (now, account_id, action, outcome, detail, source_ip, user_agent),
        )
        conn.commit()
    _maybe_prune(now)


def _maybe_prune(now):
    """Prune at most once per PRUNE_INTERVAL per process."""
    global _LAST_PRUNE
    with _LOCK:
        if now - _LAST_PRUNE < PRUNE_INTERVAL:
            return
        _LAST_PRUNE = now
    prune(before=now - RETENTION_DAYS * 86400)


def prune(before=None):
    """Delete rows older than `before` (default: the retention window) and
    return how many went. Safe to run at any time: nothing reads this table to
    make a decision, unlike the co-signer's, whose wrap-once state a prune would
    destroy."""
    cutoff = float(before if before is not None else time.time() - RETENTION_DAYS * 86400)
    with _LOCK:
        conn = connect()
        cur = conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        conn.commit()
        return cur.rowcount


def recent(limit=50, account_id=None):
    """Newest rows first, for an operator looking at what an account did."""
    sql = ("SELECT ts, account_id, action, outcome, detail, source_ip, user_agent "
           "FROM events")
    args = []
    if account_id is not None:
        sql += " WHERE account_id = ?"
        args.append(account_id)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(int(limit))
    with _LOCK:
        cur = connect().execute(sql, args)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
