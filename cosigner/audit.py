"""One SQLite row per co-signer request: what was asked, and what was decided.

The enclave cannot rewrite this. Attestation says the right code booted; this
says what happened afterwards. Neither prevents anything -- a live enclave
attacker can still ask for one mailbox at a time -- but together they bound the
breach to what the rate limit allowed and leave evidence of exactly which users
were touched.

No row is ever modified: no UPDATE appears anywhere in this package, and a
decision once written stays as it was written. Rows are deleted only by
`cosigner/retention.py`, only by age, and never on a request path. Enforcing
even that in SQLite would need triggers plus a second connection with different
rights, which buys nothing against an attacker who already owns the box. What
does buy something is a copy off the box (`sqlite3 audit.db .backup`), which is
the operator's job, not this module's.

Two tables, because the log does two jobs and only one of them may be pruned:

  * `requests` is the log and the windowed rate limiter's counter
    (`granted_since`, `distinct_uids_since`). Every reader of it is bounded by a
    window, so a row older than the longest window cannot change an answer.
  * `grants` is state, not history: the first time a (uid, action) pair was
    allowed, which is what `ever_granted` reads and what makes `/wrap`
    idempotent-by-refusal. It is never pruned. Kept in `requests` instead, a
    retention rule that deleted the wrong row would silently re-open a uid for a
    second wrap -- correctness resting on a WHERE clause that any future limiter
    could invalidate.

Both are written by the same `record()` call, in one transaction under one
lock, so the pair cannot disagree.

Invariant 4 lives here: **no ciphertext, ever**. Not `inner`, not `outer`, not
a proof. Neither schema has anywhere to put one and `record()` takes no
argument that could carry one. A column added for "debugging" would hand an
attacker who reads this file one half of what they need.

Counting grants out of the log rather than out of a dictionary means the limit
survives a restart and means the number the limiter used is the number the
audit shows.
"""

import contextlib
import os
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL NOT NULL,
    uid          TEXT NOT NULL,
    action       TEXT NOT NULL,
    decision     TEXT NOT NULL,
    reason       TEXT,
    fingerprint  TEXT,
    measurement  TEXT,
    attested     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS requests_uid_action_ts ON requests (uid, action, ts);
CREATE INDEX IF NOT EXISTS requests_ts ON requests (ts);

CREATE TABLE IF NOT EXISTS grants (
    uid              TEXT NOT NULL,
    action           TEXT NOT NULL,
    first_granted_ts REAL NOT NULL,
    PRIMARY KEY (uid, action)
);
"""

# Every (uid, action) that was ever allowed, recovered from the log. Runs once
# per process against a table `requests` is only ever appended to, so it is
# idempotent. It exists because `grants` arrived after the log did: a box whose
# audit.db predates this schema has wrap grants recorded only as log rows, and
# an empty `grants` would tell `ever_granted` that every existing user is
# eligible for a second wrap.
BACKFILL = (
    "INSERT OR IGNORE INTO grants (uid, action, first_granted_ts) "
    "SELECT uid, action, MIN(ts) FROM requests WHERE decision = ? GROUP BY uid, action"
)

ALLOW = "allow"
DENY = "deny"

_LOCK = threading.Lock()
_CONN = None


def state_dir():
    """Where the log lives. `StateDirectory=cosigner` in the unit makes systemd
    create and own /var/lib/cosigner; a dev run overrides it."""
    return Path(os.environ.get("COSIGNER_STATE_DIR") or os.environ.get("STATE_DIRECTORY")
                or "state/cosigner")


def db_path():
    return state_dir() / "audit.db"


def connect():
    """One connection, shared across the server's threads under `_LOCK`."""
    global _CONN
    if _CONN is None:
        path = db_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), check_same_thread=False)
        # A plain DELETE leaves the row readable in the file's free list until a
        # VACUUM reuses the page. For a table whose stated point is not to hand
        # over a customer list, a deleted row that is still on the disk is a row
        # that was not deleted. Retention vacuums as well; this covers the gap
        # between the two.
        conn.execute("PRAGMA secure_delete=ON")
        conn.executescript(SCHEMA)
        conn.execute(BACKFILL, (ALLOW,))
        conn.commit()
        try:
            path.chmod(0o600)
        except OSError:
            pass
        _CONN = conn
    return _CONN


@contextlib.contextmanager
def transaction():
    """The connection under `_LOCK`, committed on exit. The one seam anything
    outside this module may write through, so every write to the log is still
    serialized against the read-then-write pairs the limiter depends on."""
    with _LOCK:
        conn = connect()
        try:
            yield conn
        except Exception:
            conn.rollback()
            raise
        conn.commit()


def vacuum():
    """Reclaim the pages a prune freed. Cannot run inside a transaction, so it
    is its own call rather than the tail of `retention.prune`."""
    with _LOCK:
        connect().execute("VACUUM")


def reset_for_test(path=None):
    """Drop the cached connection so a test can point at a fresh directory."""
    global _CONN
    with _LOCK:
        if _CONN is not None:
            _CONN.close()
        _CONN = None
    if path is not None:
        os.environ["COSIGNER_STATE_DIR"] = str(path)


def record(uid, action, decision, reason=None, fingerprint=None, measurement=None,
           attested=False, ts=None):
    """Write the decision. Arguments are identifiers and verdicts only; there is
    deliberately no parameter that can carry key or token material.

    An allowed request also lands in `grants`, in the same transaction, because
    that row is what survives retention and answers `ever_granted`. Written here
    rather than by the caller so a decision cannot be logged as allowed without
    the state that says so."""
    assert decision in (ALLOW, DENY), f"decision must be {ALLOW!r} or {DENY!r}, got {decision!r}"
    assert action, "record requires an action"
    at = float(ts if ts is not None else time.time())
    with transaction() as conn:
        conn.execute(
            "INSERT INTO requests (ts, uid, action, decision, reason, fingerprint, "
            "measurement, attested) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (at, uid or "", action, decision,
             reason, fingerprint, measurement, 1 if attested else 0),
        )
        if decision == ALLOW:
            conn.execute(
                "INSERT OR IGNORE INTO grants (uid, action, first_granted_ts) "
                "VALUES (?, ?, ?)", (uid or "", action, at),
            )


def _action_clause(action):
    """`(sql, args)` restricting a count to one action or to a set of them.

    A set rather than one string because a limiter whose subject is "the ways to
    get a key" has to count them together; written here rather than as a second
    query in the caller so both counters ask the same question the same way."""
    if action is None:
        return "", []
    if isinstance(action, str):
        return " AND action = ?", [action]
    actions = list(action)
    assert actions, "an empty action set counts nothing and is never what a caller meant"
    return f" AND action IN ({','.join('?' * len(actions))})", actions


def granted_since(since, action=None, uid=None):
    """How many requests were allowed in a window. The rate limiter's only
    source of counts, so what it enforced and what this log shows cannot
    disagree. `action` is one action, a set of them, or None for all."""
    clause, action_args = _action_clause(action)
    sql = ("SELECT COUNT(*) FROM requests "
           "WHERE decision = ? AND ts >= ?" + clause)  # nosec B608  # clause is placeholders only
    args = [ALLOW, float(since)] + action_args
    if uid is not None:
        sql += " AND uid = ?"
        args.append(uid)
    with _LOCK:
        return connect().execute(sql, args).fetchone()[0]


def distinct_uids_since(since, action):
    """How many different accounts were allowed these actions in a window.

    The shape the per-user and aggregate ceilings both miss: a sweep that
    touches every account once each is, per account, indistinguishable from
    normal use. Counting accounts rather than requests is what tells the two
    apart, and `requests_ts` already indexes it."""
    assert action, "distinct_uids_since is only meaningful for a named action"
    clause, action_args = _action_clause(action)
    with _LOCK:
        return connect().execute(
            "SELECT COUNT(DISTINCT uid) FROM requests "
            "WHERE decision = ? AND ts >= ?" + clause,  # nosec B608  # clause is placeholders only
            [ALLOW, float(since)] + action_args,
        ).fetchone()[0]


def ever_granted(uid, action):
    """Has this uid ever been allowed this action? `/wrap` is idempotent-by-
    refusal on this: a second wrap for a user who already has one is either a
    bug or an attacker asking us to re-wrap something we should not.

    Reads `grants`, not the log. This is the only unbounded-lookback question
    anything asks, so it is the only one retention could break, and keeping its
    answer in a table nothing prunes is what makes the log freely prunable."""
    with _LOCK:
        row = connect().execute(
            "SELECT 1 FROM grants WHERE uid = ? AND action = ? LIMIT 1",
            (uid, action),
        ).fetchone()
    return row is not None


def recent(limit=50):
    """Newest rows first, for an operator looking at a refusal."""
    with _LOCK:
        cur = connect().execute(
            "SELECT ts, uid, action, decision, reason, fingerprint, measurement, attested "
            "FROM requests ORDER BY id DESC LIMIT ?", (int(limit),),
        )
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
