"""One-time: write the box owner into the account manifest.

Before this existed, a box with no manifest fell back to an implicit account.
That fallback ended the instant anyone signed up -- the manifest then existed,
so the fallback stopped, and the owner (who had no entry) silently vanished from
routing. The fix is to make the owner an ordinary entry: row one, active,
with no special-cased id or state path -- the owner is seeded the same shape
of account a signup gets, keyed by the owner's own address.

Idempotent. Running it twice is a no-op beyond rewriting the same values, and it
will not clobber a plan_status that billing has since changed -- except for
forcing the owner active, which is the point (the owner runs the box; they are
not a Polar customer).

Who the owner is comes from the environment, not from the source: set
LETTERLOCK_OWNER_EMAIL, LETTERLOCK_OWNER_FIRST and LETTERLOCK_OWNER_LAST (and
LETTERLOCK_OWNER_FIRST_ALIASES, comma separated, if mail addresses them by a
different first name) in .env before running this. See account.owner_identity().

    python -m backend.accounts.seed_owner          # write it
    python -m backend.accounts.seed_owner --show   # print what it would write
"""

import sys

from backend import paths
from backend.accounts import account
from backend.drafting import voice_dna


def owner_entry_args():
    """The register_account() call the seed makes, derived from owner_account()
    so the identity and Telegram target come from one place.

    It writes no token_file. The seed introduces the owner to the store; it
    cannot take custody of a mailbox, because custody starts at a Google consent
    and ends at a record neither this box nor the co-signer can open alone. The
    owner signs in through /auth/callback like every other user, and re-running
    the seed afterwards carries the token_file that sign-in wrote.

    The owner is also the only account that points at the operator's personal
    voice profile. Everyone else gets the neutral default: a signup must not be
    drafted in, and signed with, the box owner's voice."""
    owner = account.owner_account()
    identity = owner.identity
    assert identity.emails, (
        f"owner identity has no email address; set {account.OWNER_EMAIL_ENV}"
    )
    args = {
        "email": identity.emails[0],
        "first": identity.first,
        "last": identity.last,
        "first_aliases": tuple(identity.first_aliases),
        "telegram_chat_id": owner.telegram.chat_id,
        "plan_status": "active",
        "timezone": owner.timezone,
        "auto_schedule": owner.auto_schedule,
    }
    voice = voice_dna.OWNER_PROFILE
    if voice.exists():
        args["voice_file"] = paths.relative_if_inside(voice)
    return args


def seed():
    args = owner_entry_args()
    acct = account.register_account(**args)
    # register_account preserves an existing plan_status, so an owner who signed
    # in through the web UI first (and landed inactive) still ends up active.
    if acct.plan_status != "active":
        prior = account.set_plan_status(acct.id, "active")
        print(f"plan_status {prior} -> active")
        acct = account.account_for_email(acct.id)
    return acct


def main(argv):
    if "--show" in argv:
        for k, v in owner_entry_args().items():
            print(f"{k}: {v}")
        return 0
    acct = seed()
    print(f"seeded {acct.id} ({acct.plan_status}) into {account.MANIFEST}")
    print(f"  token:  {acct.token_file or '(none yet; sign in to grant access)'}")
    print(f"  state:  {acct.state.path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
