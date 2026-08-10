"""A file one process appends to and another drains, and the modes that decide
which processes those are.

Two of them exist. The Gmail push receiver spools an address for the mail
daemon (`backend/daemons/wake_queue.py`); the Polar receiver spools an
entitlement event for the same daemon (`backend/billing/billing_queue.py`).
Both ends of both spools are separate uids, which is the whole reason this
module exists: a webhook that faces the open internet writes here and reaches
nothing else the application owns.

One implementation, so the two cannot disagree about locking. Append takes an
exclusive lock; drain reads-then-truncates under the same lock, so an entry
landing mid-drain is either fully included or left for the next pass, never
lost or half-read.

Each spool names its own group. Not one shared group: writing to the wake spool
starts a drafting pass against a named account and writing to the billing spool
does not, so the two capabilities are handed out separately. A group that does
not exist yet -- a laptop, or the box before the deploy that creates it --
leaves the files owner-only, which stops the webhook writing rather than
opening the spool to everyone.

What a spool holds, and for how long, since neither file is touched by account
deletion and both name people. The wake spool carries raw email addresses; the
billing spool carries whole Polar event bodies, `customer_email` included. Each
entry lives until the next drain, which is the daemon's next pass -- so the
bound is "until the daemon runs", and a daemon that is down is a plaintext list
of who has mail waiting. That is the stated lifetime rather than an oversight:
a deleted account's entry clears on the next pass because the daemon drops an
address it cannot resolve, and nothing here is a record anyone reads later.
Anything wanted for longer belongs in `backend/audit.py`, which has a retention
policy; a spool does not, because a spool that keeps things is a queue that
never drains.
"""

import fcntl
import json

from backend import paths


class Spool:
    def __init__(self, name, gid):
        assert callable(gid), "gid is looked up per call, not captured at import"
        self.name = name
        self._gid = gid

    # Resolved per call, not at construction. These objects are module-level
    # and `paths.RUN_DIR` is a constant a test redirects, so capturing the
    # directory at import would pin every spool to the real state/ the moment
    # the module is imported.
    @property
    def path(self):
        return paths.RUN_DIR / f"{self.name}.jsonl"

    @property
    def lock_path(self):
        return paths.RUN_DIR / f"{self.name}.lock"

    def _ready(self, path):
        """`path`, existing and writable by both ends.

        Runs on every call rather than once at startup because either end may
        be the process that creates a given file, and only its creator can set
        its mode."""
        if not path.exists():
            path.touch()
        return paths.group_file(path, self._gid())

    def append(self, entry):
        assert isinstance(entry, dict), "a spool entry is one JSON object"
        paths.ensure_run_dir()
        with open(self._ready(self.lock_path), "w") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            with open(self._ready(self.path), "a") as qf:
                qf.write(json.dumps(entry) + "\n")

    def pending(self):
        """Whether a drain would return anything, without consuming it.

        `drain()` clears the spool, so a caller that cannot yet act on what it
        drained has already lost it. This is the cheap check that lets such a
        caller build what it needs first and leave the entries alone if it
        cannot. Unlocked and approximate by design: it is a hint that work
        exists, and every answer it gives is re-decided under the lock by the
        drain that follows."""
        try:
            return self.path.stat().st_size > 0
        except FileNotFoundError:
            return False

    def drain(self):
        """Every entry written since the last drain, and clear the spool."""
        paths.ensure_run_dir()
        with open(self._ready(self.lock_path), "w") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            if not self.path.exists():
                return []
            lines = self.path.read_text().splitlines()
            self.path.write_text("")
        return [json.loads(line) for line in lines if line.strip()]
