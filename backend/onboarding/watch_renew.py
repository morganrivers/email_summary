"""Per-user Gmail users.watch registration + weekly renewal (Track C2).

A Gmail push watch expires after ~7 days, so every account needs its watch
re-registered on a schedule. This is the multi-tenant successor to the old
single-account watch registration cron: it iterates accounts, calls users.watch
for each through gmail_api (the seam that lets one process touch many
mailboxes), and persists the result through the account's StateStore. state.py
stays the single source of truth for the state schema; gmail_api only performs
the API call.

renew_account is also called at onboarding for the one just-registered account,
so registration and renewal share one code path. main() renews every active
account and is what backend/daemons/scheduler.py calls once a week.

On first registration lastHistoryId is set to the watch's current historyId so
the daemon has a cursor to fetch from. On later renewals lastHistoryId is left
untouched (the daemon advances it as it processes); only watchExpiration is
refreshed, so a renewal never rewinds the cursor and drops unprocessed history.
"""

import os
import sys

import execguard
from backend import secrets
from backend.accounts import account
from backend.integrations.gmail_gcal import gmail_api

# The Pub/Sub topic Gmail pushes to. One topic serves every account; the push
# subscription's OIDC audience is what gmail_hook_server verifies.
PUBSUB_TOPIC = os.environ.get(
    "GMAIL_PUBSUB_TOPIC", "projects/coastal-mender-462719-q3/topics/gmail-events")


def log(msg):
    sys.stderr.write(f"watch-renew {msg}\n")
    sys.stderr.flush()


def renew_account(acct, *, log=log):
    """(Re)register the Gmail watch for one account and persist the cursor +
    expiry. Returns the {historyId, expiration} the API answered with."""
    assert acct.identity.account_id == acct.id, (
        f"account {acct.id!r} carries identity for {acct.identity.account_id!r}"
    )
    res = gmail_api.register_watch(acct, PUBSUB_TOPIC)
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
    execguard.lock_down(secrets.tee_required())
    main()
