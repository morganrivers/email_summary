#!/usr/bin/env python3
"""Push-triggered Gmail processor.

Invoked by gmail-hook.php after Pub/Sub fires. Uses lastHistoryId from
state.json to fetch only new messages, runs them through draft_replies.process_emails,
and saves the new historyId.

A file lock guards against concurrent pushes racing on the state file.
"""

import os
import sys
import json
import fcntl
import subprocess
from pathlib import Path

os.umask(0)

import state
import manual_draft
from draft_replies import process_emails

SCRIPT_DIR = Path(__file__).parent
FETCH_SCRIPT = SCRIPT_DIR / "fetch_emails.mjs"
LOCK_FILE = SCRIPT_DIR / "process_push.lock"


def fetch_since(history_id):
    result = subprocess.run(
        ["node", str(FETCH_SCRIPT), "--since-history", str(history_id)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
    )
    assert result.returncode == 0, (
        f"fetch_emails.mjs exited {result.returncode}: {result.stderr.decode()}"
    )
    return json.loads(result.stdout)


def main():
    import datetime
    sys.stderr.write(f"[{datetime.datetime.utcnow().isoformat()}Z] process_push started; argv={sys.argv}\n")
    s = state.load()
    last = s.get("lastHistoryId")
    if not last:
        sys.stderr.write("No lastHistoryId in state; run watch_register.mjs first.\n")
        return 1

    payload = fetch_since(last)
    emails = payload.get("emails", [])
    new_history_id = payload.get("historyId")
    stale = payload.get("stale", False)
    sys.stderr.write(f"fetched {len(emails)} email(s) since historyId={last}\n")

    if stale:
        sys.stderr.write(
            f"history.list returned 404 (startHistoryId={last} too old); "
            f"bootstrapping to {new_history_id}, skipping any missed messages.\n"
        )

    bot_requests = [e for e in emails if manual_draft.is_bot_request(e)]
    auto_emails = [e for e in emails if not manual_draft.is_bot_request(e)]

    for req in bot_requests:
        try:
            manual_draft.process_draft_request(req)
        except Exception as err:
            sys.stderr.write(f"manual_draft failed for {req.get('id')}: {err}\n")

    if auto_emails:
        process_emails(auto_emails)

    if new_history_id:
        state.update(lastHistoryId=str(new_history_id))
    return 0


if __name__ == "__main__":
    with open(LOCK_FILE, "w") as lf:
        try:
            fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            sys.stderr.write("Another process_push is running; exiting.\n")
            sys.exit(0)
        sys.exit(main())
