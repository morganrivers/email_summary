"""One SQLite row per co-signer request: what was asked, and what was decided.

The enclave cannot rewrite this. Attestation says the right code booted; this
says what happened afterwards. Neither prevents anything -- a live enclave
attacker can still ask for one mailbox at a time -- but together they bound the
breach to what the rate limit allowed and leave evidence of exactly which users
were touched.

Append-only by convention: no UPDATE and no DELETE appears anywhere in this
package. Enforcing it in SQLite would need triggers plus a second connection
with different rights, which buys nothing against an attacker who already owns
the box. What does buy something is a copy off the box (`sqlite3 audit.db
.backup`), which is the operator's job, not this module's.

Invariant 4 lives here: **no ciphertext, ever**. Not `inner`, not `outer`, not
a proof. The schema has nowhere to put one and `record()` takes no argument
that could carry one. A column added for "debugging" would hand an attacker who
reads this file one half of what they need.

The table also doubles as the rate limiter's state (`granted_since`). Counting
grants out of the log rather than out of a dictionary means the limit survives
a restart and means the number the limiter used is the number the audit shows.
"""

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
"""

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
    deliberately no parameter that can carry key or token material."""
    assert decision in (ALLOW, DENY), f"decision must be {ALLOW!r} or {DENY!r}, got {decision!r}"
    assert action, "record requires an action"
    with _LOCK:
        conn = connect()
        conn.execute(
            "INSERT INTO requests (ts, uid, action, decision, reason, fingerprint, "
            "measurement, attested) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (float(ts if ts is not None else time.time()), uid or "", action, decision,
             reason, fingerprint, measurement, 1 if attested else 0),
        )
        conn.commit()


def granted_since(since, action=None, uid=None):
    """How many requests were allowed in a window. The rate limiter's only
    source of counts, so what it enforced and what this log shows cannot
    disagree."""
    sql = "SELECT COUNT(*) FROM requests WHERE decision = ? AND ts >= ?"
    args = [ALLOW, float(since)]
    if action is not None:
        sql += " AND action = ?"
        args.append(action)
    if uid is not None:
        sql += " AND uid = ?"
        args.append(uid)
    with _LOCK:
        return connect().execute(sql, args).fetchone()[0]


def ever_granted(uid, action):
    """Has this uid ever been allowed this action? `/wrap` is idempotent-by-
    refusal on this: a second wrap for a user who already has one is either a
    bug or an attacker asking us to re-wrap something we should not."""
    with _LOCK:
        row = connect().execute(
            "SELECT 1 FROM requests WHERE uid = ? AND action = ? AND decision = ? LIMIT 1",
            (uid, action, ALLOW),
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
