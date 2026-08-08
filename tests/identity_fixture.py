"""The synthetic people every test runs as.

One definition, imported by conftest (which puts the owner in the environment
before any application module loads), by the harness, and by the tests that
assert on it. They are deliberately made-up people on example.com: the
repository is public and the box owner's real name and mailbox are
configuration, not source, so nothing here may be a live identity. See
account.owner_identity().

Because the goldens record already-masked prompts, these values are also what
the golden files hold. Fixture emails, goldens and environment all read from
here so they cannot name three different people.

Imports nothing, so conftest can read it before it has finished neutralizing
.env and the dotenv loader.
"""

OWNER_FIRST = "Jordan"
OWNER_LAST = "Avery"
OWNER_ALIASES = ["Jordy"]
OWNER_EMAIL = "jordan.avery@example.com"
OWNER_BOT_ALIAS = "jordan.avery+bot@example.com"

# A second mailbox belonging to the same person, the one correspondents write
# to. It is not in the owner identity, so it masks as an ordinary address
# rather than as [USER_EMAIL] -- which is the case the goldens cover and the
# reason it is not simply OWNER_EMAIL.
OWNER_ALT_EMAIL = "j.avery@example.net"

OWNER_NAME = f"{OWNER_FIRST} {OWNER_LAST}"
OWNER_FROM = f"{OWNER_NAME} <{OWNER_ALT_EMAIL}>"

# What account.owner_identity() reads. Aliases are comma separated there.
OWNER_ENV = {
    "LETTERLOCK_OWNER_EMAIL": OWNER_EMAIL,
    "LETTERLOCK_OWNER_FIRST": OWNER_FIRST,
    "LETTERLOCK_OWNER_LAST": OWNER_LAST,
    "LETTERLOCK_OWNER_FIRST_ALIASES": ",".join(OWNER_ALIASES),
}

# An unrelated person, for tests that mask text without going through an
# account. Nothing the fixtures mention belongs to them, so anything those
# tests feed in is third party PII and must come back tagged.
OTHER_FIRST = "Robin"
OTHER_LAST = "Sable"
OTHER_ALIASES = ["Rob"]
OTHER_EMAIL = "robin.sable@example.org"
