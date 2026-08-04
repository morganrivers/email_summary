"""Payload-carrying wake protocol shared by the webhook and the daemon.

The FIFO wake is a content-free byte: it says "work arrived" but not for whom.
This spool carries the routing key. On an inbound Pub/Sub push the webhook
resolves the emailAddress to an account and enqueue()s that account id, then
pokes the FIFO; the daemon drain()s the spool and processes only the queued
accounts instead of fanning out over every mailbox.

Single source of truth for the queue file, its lock, and the framing, so the
webhook and daemon can never disagree on the protocol. enqueue is append-only
under an exclusive lock; drain reads-then-truncates under the same lock, so a
push landing mid-drain is either fully included or left for the next wake, never
lost or half-read. Multiple wakes between drains coalesce (deduped by id).
"""

import fcntl
import json

from backend import paths

QUEUE_FILE = paths.RUN_DIR / "wake_queue.jsonl"
LOCK_FILE = paths.RUN_DIR / "wake_queue.lock"


def enqueue(account_id):
    assert account_id, "cannot enqueue an empty account id"
    paths.ensure_run_dir()
    with open(LOCK_FILE, "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        with open(QUEUE_FILE, "a") as qf:
            qf.write(json.dumps({"account_id": account_id}) + "\n")


def drain():
    """Return the deduped list of queued account ids and clear the spool."""
    paths.ensure_run_dir()
    with open(LOCK_FILE, "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        if not QUEUE_FILE.exists():
            return []
        lines = QUEUE_FILE.read_text().splitlines()
        QUEUE_FILE.write_text("")
    ids = []
    seen = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        aid = json.loads(line)["account_id"]
        if aid not in seen:
            seen.add(aid)
            ids.append(aid)
    return ids
