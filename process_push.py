#!/usr/bin/env python3
"""Push-triggered Gmail processor.

Invoked by gmail-hook.php after Pub/Sub fires. Delegates to pipeline.process_account
(the same routing the always-on daemon uses) for every account, so the fetch +
route + cursor logic has a single source of truth.

A file lock guards against concurrent pushes racing on the state file.
"""

import os
import sys
import fcntl
from pathlib import Path

os.umask(0)

import account as account_mod
import pipeline
from notify import notify_error

SCRIPT_DIR = Path(__file__).parent
LOCK_FILE = SCRIPT_DIR / "process_push.lock"


def _log(msg):
    sys.stderr.write(msg + "\n")


def main():
    import datetime
    sys.stderr.write(f"[{datetime.datetime.utcnow().isoformat()}Z] process_push started; argv={sys.argv}\n")
    for acct in account_mod.load_accounts():
        pipeline.process_account(
            acct,
            log=_log,
            notify_err=lambda ctx, err, a=acct: notify_error(ctx, err, a.telegram),
        )
    return 0


if __name__ == "__main__":
    with open(LOCK_FILE, "w") as lf:
        try:
            fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            sys.stderr.write("Another process_push is running; exiting.\n")
            sys.exit(0)
        sys.exit(main())
