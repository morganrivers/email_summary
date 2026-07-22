"""Per-user Gmail users.watch registration + weekly renewal (Track C2).

A Gmail push watch expires after ~7 days, so every account needs its watch
re-registered on a schedule. This is the multi-tenant successor to the old
single-account watch_register.mjs cron: it iterates accounts, runs the Node
worker under each account's creds dir (node_runner.node_env is the seam that
lets one process touch many mailboxes), and persists the result through the
account's StateStore. state.py stays the single source of truth for the state
schema; the Node worker only performs the API call and prints its result.

renew_account is also called at onboarding for the one just-registered account,
so registration and renewal share one code path. main() renews every active
account and is what the weekly gmail-watch.timer runs.

On first registration lastHistoryId is set to the watch's current historyId so
the daemon has a cursor to fetch from. On later renewals lastHistoryId is left
untouched (the daemon advances it as it processes); only watchExpiration is
refreshed, so a renewal never rewinds the cursor and drops unprocessed history.
"""

import json
import subprocess
import sys

from backend import paths
from backend.accounts import account
from backend.integrations.gmail_gcal.node_runner import node_env

WATCH_SCRIPT = paths.node_script("watch_register.mjs")


def log(msg):
    sys.stderr.write(f"watch-renew {msg}\n")
    sys.stderr.flush()


def renew_account(acct, *, log=log):
    """(Re)register the Gmail watch for one account and persist the cursor +
    expiry. Returns the parsed {historyId, expiration} worker result."""
    assert acct.identity.account_id == acct.id, (
        f"account {acct.id!r} carries identity for {acct.identity.account_id!r}"
    )
    result = subprocess.run(
        ["node", str(WATCH_SCRIPT)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
        env=node_env(acct.creds_dir),
    )
    assert result.returncode == 0, (
        f"watch_register.mjs exited {result.returncode} for {acct.id}: "
        f"{result.stderr.decode()}"
    )
    res = json.loads(result.stdout)
    fields = {"watchExpiration": str(res["expiration"])}
    if not acct.state.load().get("lastHistoryId"):
        fields["lastHistoryId"] = str(res["historyId"])
    acct.state.update(**fields)
    log(f"renewed {acct.id}: historyId={res['historyId']} expires={res['expiration']}")
    return res


def main():
    accounts = account.load_accounts()
    log(f"renewing {len(accounts)} active account(s)")
    failures = 0
    for acct in accounts:
        try:
            renew_account(acct)
        except Exception as err:
            failures += 1
            log(f"renew failed for {acct.id}: {err}")
    if failures:
        log(f"{failures} account(s) failed renewal")
        sys.exit(1)


if __name__ == "__main__":
    main()
