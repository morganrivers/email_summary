"""Who is behind an opaque handle, and what is one account's handle.

    python -m backend.accounts.whois <handle>          # handle -> address
    python -m backend.accounts.whois <address>         # address -> handle

The co-signer's audit log names accounts by handle and cannot do better: it is
not allowed to hold a customer list, which is the whole of Track F. That makes
every incident on that box start with an opaque value, and an operator reading
"refused 41 accounts in 15 minutes, most recent 9f3c..." needs to know whose
mailbox that is before they can decide anything.

The mapping exists in one file, `database/accounts.json`, on this box. This
command is the only reader of it in that direction, so the answer to "can
anyone turn a co-signer log back into people" stays "only someone who also has
the enclave's manifest", which is the property the split is for.

Deliberately a command and not an endpoint. It is used by a human during an
incident, perhaps twice a year; a route would put a handle-to-address oracle
inside the web tier, and the web tier is reachable from the internet.
"""

from __future__ import annotations

import sys

from backend.accounts import account


def resolve(value):
    """`(kind, answer)` for whichever direction this value points, or None.

    Which direction is decided by the shape of the argument rather than by a
    flag, because `HANDLE_RE` already describes exactly one of the two and an
    operator holding a value from a log should not have to say which kind it
    is."""
    value = (value or "").strip()
    if not value:
        return None
    if account.HANDLE_RE.match(value):
        email = account.email_for_handle(value)
        return None if email is None else ("account", email)
    handle = account.handle_for_email(value)
    return None if handle is None else ("handle", handle)


def main(argv):
    if len(argv) != 1:
        print(f"usage: python -m {__package__}.whois <handle|address>", file=sys.stderr)
        return 2
    answer = resolve(argv[0])
    if answer is None:
        print(f"no account matches {argv[0]!r}", file=sys.stderr)
        return 1
    kind, value = answer
    print(f"{kind}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
