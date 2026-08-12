"""How a container says "there is a process in here that should not be", and
how that reaches a person.

`backend/procwatch.py` finds the process; this is the only way it gets told.
The two are separate modules because the roles that can report and the roles
that can only die are not the same set, and the watcher must not carry a
`state/` dependency into the two containers that deliberately mount no volume.

The channel is the append-and-drain spool in `backend/spool.py`, for the reason
the wake and billing queues use it: the writer and the drainer are different
uids, and one file per role is what keeps them that way. `mail` and `web` share
`letterlock-data`; `hook` is in `letterlock-wake` and deliberately not in the
data group, so it writes its own file under its own group rather than being let
into theirs. The mail daemon is in both and drains all three.

There is no Telegram call here. Only the mail role holds `TELEGRAM_BOT_TOKEN`,
and a notifier imported here would ship `backend/integrations/telegram.py` into
the receiver Google posts to -- function-local imports count in
`deploy/render_image_manifest.py` exactly like top-level ones. So the report
travels as data to the role that already holds the token, and
`backend/daemons/daemon_loop.py` is what sends it.

`egress` and `ingress` mount no volume and appear nowhere below. They have
nothing to write a report onto and nothing worth reporting beyond the fact
itself, so their signal is the one every role also gives: the container exits
non-zero and `restart: always` puts it into a visible loop. That is a weaker
report than a message, and it is the price of those two roles holding no
filesystem at all.

Best-effort by construction. A process writing one of these has already found
something it cannot explain about itself, so the write may be into a filesystem
an attacker controls, and it must not delay the exit that follows it. Failures
here are logged and swallowed; the exit is not conditional on them.
"""

from __future__ import annotations

import sys
import time

from backend import paths
from backend.spool import Spool

REPORTING_ROLES = ("mail", "web", "hook")

_GROUPS = {
    "mail": paths.data_gid,
    "web": paths.data_gid,
    "hook": paths.wake_gid,
}


def log(msg):
    sys.stderr.write(f"[intrusion] {msg}\n")
    sys.stderr.flush()


def spool_for(role):
    """The one file that role writes its reports to."""
    assert role in _GROUPS, f"{role} has no volume to report onto"
    return Spool(f"intrusion_{role}", _GROUPS[role])


def reporter(role):
    """A one-argument callable for `procwatch.start`, or None for a role with
    nowhere to write. Returned rather than looked up inside the watcher so the
    two containers that mount no volume never import this module."""
    if role not in _GROUPS:
        return None

    def report(entry):
        try:
            spool_for(role).append(dict(entry, role=role, at=time.time()))
        except Exception as err:
            log(f"{role} could not record {entry}: {err}")

    return report


def drain():
    """Every report waiting from any role, oldest file first. Run by the mail
    daemon, which is the only uid in both groups and the only role holding a
    way to tell a person."""
    found = []
    for role in REPORTING_ROLES:
        try:
            found.extend(spool_for(role).drain())
        except Exception as err:
            log(f"could not drain {role}: {err}")
    return found


def summarize(entries):
    """One operator message for a drained batch. Kept here rather than in the
    daemon so the wording of a breach alert lives with the thing that defines
    one."""
    assert entries, "summarize is for a non-empty drain"
    roles_seen = sorted({str(entry.get("role")) for entry in entries})
    lines = [f"unexpected process in {', '.join(roles_seen)}"]
    for entry in entries[:10]:
        lines.append(f"  pid {entry.get('pid')}: {entry.get('cmdline')}")
    if len(entries) > 10:
        lines.append(f"  ... and {len(entries) - 10} more")
    return "\n".join(lines)
