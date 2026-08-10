"""The only thing in this package that deletes an audit row.

Kept out of `cosigner/audit.py` so that module stays readable as what it is:
one place that appends decisions and answers questions about them. Deleting is
a different job with a different risk, and it is the whole of this file.

**What a prune may not change.** Every enforcement answer the co-signer gives
must be identical before and after. Two things make that hold:

  * `ever_granted` -- the unbounded-lookback question, and the one that makes
    `/wrap` refuse a second time -- reads `grants`, which is never touched
    here. Delete a wrap row from the log and the uid stays wrapped.
  * `granted_since` and `distinct_uids_since` are windowed, and the cutoffs
    below are derived from `policy.longest_window()` rather than restated, so
    a limiter added later with a longer window moves the floor with it. The
    assertion in `prune()` is what refuses to run if that stops being true.

**Why prune at all.** Volume is one reason: roughly one unwrap per active
account per hour is near a million rows a year at a full box, in a file the
co-signer reads on every request. The other is that a row is not free of
consequence. `uid` is an account identifier and `ts` is when that account's
mail was processed, so the log is a per-account activity timeline for as long
as it is kept -- working hours, timezone, the week someone stopped using the
product. Keeping it forever is a choice to hold that forever.

**What is kept forever, and what that costs.** `grants` is never pruned and no
endpoint deletes a row from it, so a handle wrapped once stays after the enclave
destroys that account: this box holds one opaque identifier and the time of its
first wrap, indefinitely, for every account that has ever existed. That is the
price of `/wrap` refusing a second time, and a deletion path would be a larger
problem rather than a smaller one -- it is the call an attacker holding the
enclave makes before re-wrapping a live handle around an inner ciphertext they
chose, and the only party who could authorize it is the enclave whose compromise
it defends against. So the row stays and what it carries is bounded instead: a
handle this box cannot turn back into a person (`account.new_handle`), an action
name, and one timestamp. The mapping to a person lives only in the enclave's
manifest, and deleting the account there deletes it.

DENY rows are the exception and are kept far longer. Nothing enforcement-side
reads them at all -- both counters filter on ALLOW -- and they are the highest
value evidence in the table: a refusal is either a bug or a breach. If they are
ever numerous enough to be a volume problem, that is `policy._sweep_refusal`
firing, which is an incident, not a retention question.

`PRAGMA secure_delete=ON` is set on the connection (`audit.connect`) and this
vacuums afterwards, because a DELETE alone leaves the row in the file's free
list. A customer list that is merely unlinked is a customer list.

Runs on a daemon thread inside the co-signer rather than as its own systemd
unit: a second process would need a second connection, and `audit._LOCK` only
serializes one. A VACUUM from outside would take an exclusive lock on the file
the co-signer answers every request out of, which on a service with no bypass
is an availability risk bought for nothing.

    python -m cosigner.retention     # one prune by hand, reports what it did
"""

import threading
import time

from cosigner import alerts, audit, policy

DAY = 86400

# Long enough that the log is still an investigation's evidence, short enough
# that the activity timeline it constitutes is not permanent.
ALLOW_RETENTION_SECONDS = 30 * DAY

# Kept an order of magnitude longer: see the module docstring.
DENY_RETENTION_SECONDS = 365 * DAY

PRUNE_INTERVAL_SECONDS = DAY


def cutoffs(now):
    """`(allow_cutoff, deny_cutoff)`: rows strictly older than these go."""
    return now - ALLOW_RETENTION_SECONDS, now - DENY_RETENTION_SECONDS


def prune(now=None):
    """Delete aged-out log rows and reclaim their pages. Returns
    `(allowed_deleted, denied_deleted)`."""
    now = time.time() if now is None else float(now)
    floor = policy.longest_window()
    assert ALLOW_RETENTION_SECONDS > floor, (
        f"retention of {ALLOW_RETENTION_SECONDS}s would delete rows the rate limiter "
        f"still counts over its {floor}s window"
    )
    assert DENY_RETENTION_SECONDS >= ALLOW_RETENTION_SECONDS, (
        "denials are evidence and are kept at least as long as grants"
    )
    allow_cutoff, deny_cutoff = cutoffs(now)
    with audit.transaction() as conn:
        allowed = conn.execute(
            "DELETE FROM requests WHERE decision = ? AND ts < ?",
            (audit.ALLOW, allow_cutoff),
        ).rowcount
        denied = conn.execute(
            "DELETE FROM requests WHERE decision = ? AND ts < ?",
            (audit.DENY, deny_cutoff),
        ).rowcount
    if allowed or denied:
        audit.vacuum()
    return allowed, denied


def _loop(interval):
    while True:
        try:
            allowed, denied = prune()
            if allowed or denied:
                alerts.log(f"retention pruned {allowed} allow / {denied} deny rows")
        except Exception as err:
            # Never takes the service down. A log that grew too long is a
            # smaller problem than a co-signer that stopped answering, and this
            # thread has no part in any decision.
            alerts.log(f"retention prune failed: {type(err).__name__}: {err}")
        time.sleep(interval)


def start(interval=PRUNE_INTERVAL_SECONDS):
    """Prune now, then once per interval, on a daemon thread."""
    assert interval > 0, f"prune interval must be positive, got {interval}"
    thread = threading.Thread(target=_loop, args=(interval,), daemon=True,
                              name="cosigner-retention")
    thread.start()
    return thread


def main():
    allowed, denied = prune()
    print(f"pruned {allowed} allow row(s) older than {ALLOW_RETENTION_SECONDS // DAY}d "
          f"and {denied} deny row(s) older than {DENY_RETENTION_SECONDS // DAY}d "
          f"from {audit.db_path()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
