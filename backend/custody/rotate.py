"""Move every stored data key onto the co-signer's current outer key version.

    python -m backend.custody.rotate            # report what would move
    python -m backend.custody.rotate --apply    # move it

This is the half of key rotation that lives on the enclave. The other half is
provisioning the new master key and bumping `cosigner.keys.KEY_VERSION`; the
procedure as a whole is written down once, in the module docstring of
`cosigner/keys.py`, and this command is step 3 of it.

What it does not touch is the point. No data key is opened, no document is
rewritten, and no plaintext exists on either box at any moment: each record is
handed to `/rewrap` as ciphertext and stored back as ciphertext under a
different key of the co-signer's. That is what a data key buys -- rotating the
operator's key costs 32 bytes of work per account rather than a decrypt and
re-encrypt of everything every account owns, which is the reason the old
derived-key scheme promised a rotation in a comment and could not perform one.

Rotation is not idempotent-by-refusal and does not need to be: re-wrapping a
record already on the current version produces another valid record on the
current version. Running this twice is a waste of two co-signer requests per
account, not a hazard.

It stops on the first failure rather than continuing. A co-signer that starts
refusing halfway through is either rate limiting or broken, and the accounts
already rewrapped are fine either way -- every record carries the version it is
on, so a half-finished rotation is a store with records on two versions, which
is exactly the state the whole design tolerates. Finish it by running again.
"""

from __future__ import annotations

import sys

from backend.accounts import account as account_store
from backend.custody import keyring


def log(msg):
    sys.stderr.write(f"rotate {msg}\n")
    sys.stderr.flush()


def candidates():
    """Every account with a data key record, and the handle that names it.

    An account with no record has never finished signing in, so there is
    nothing to move; it gets a current-version record the first time it does."""
    found = []
    for acct in account_store.all_accounts():
        if not acct.handle or not keyring.has_key(acct.id):
            continue
        found.append(acct)
    return found


def rotate(apply=False):
    """Returns (rewrapped, skipped). With `apply` false nothing is written."""
    accounts = candidates()
    rewrapped = 0
    for acct in accounts:
        if not apply:
            continue
        keyring.rewrap(acct.id, acct.handle)
        # The cached key is still correct -- the data key did not change, only
        # the wrapping around it -- but dropping it keeps "what this process
        # holds" derived from a record that still exists in the form it was
        # read in.
        keyring.forget(acct.id)
        rewrapped += 1
        log(f"rewrapped {acct.id}")
    return rewrapped, len(accounts) - rewrapped


def main(argv):
    apply = "--apply" in argv
    rewrapped, pending = rotate(apply=apply)
    if apply:
        print(f"rewrapped {rewrapped} record(s)")
    else:
        print(f"{pending} record(s) would be rewrapped; re-run with --apply")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
