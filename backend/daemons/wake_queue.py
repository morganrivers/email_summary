"""Payload-carrying wake protocol shared by the webhook and the daemon.

The FIFO wake is a content-free byte: it says "work arrived" but not for whom.
This spool carries the routing key. On an inbound Pub/Sub push the webhook
enqueue()s the address Google named and pokes the FIFO; the daemon drain()s the
spool and processes only those mailboxes instead of fanning out over every one.

What crosses is the address, not an account id, and that is the whole reason
the receiver can run without read access to the account store. Resolving an
address to an account means reading `database/accounts.json`, which is the
list of every user and whether they are paid up; a process that verifies a JWT
and appends a line has no business holding it. `account.get_account` matches an
id or any address in the account's identity, so the daemon's lookup is
unchanged and unregistered addresses are dropped there instead of here.

Single source of truth for the queue file, its lock and the framing, so the
webhook and daemon can never disagree on the protocol. Locking and modes come
from `backend/spool.py`, shared with the billing spool; the group is
paths.WAKE_GROUP, whose members are these two units alone.
"""

from backend import paths
from backend.spool import Spool

_SPOOL = Spool("wake_queue", paths.wake_gid)


def enqueue(email):
    assert email, "cannot enqueue an empty address"
    _SPOOL.append({"email": email})


def drain():
    """The deduped list of queued addresses, in arrival order, spool cleared.

    Multiple pushes for one mailbox between drains coalesce: Gmail sends one
    per message and the daemon's pass reads the whole delta from that account's
    stored cursor either way.

    `account_id` is read as well as `email` so entries spooled by the previous
    release drain rather than stranding a push across the deploy that changes
    the key. Both resolve through the same lookup."""
    seen = []
    for entry in _SPOOL.drain():
        value = entry.get("email") or entry.get("account_id")
        if value and value not in seen:
            seen.append(value)
    return seen
