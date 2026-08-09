"""Detach an account's Telegram chat without the usual proof.

    python -m backend.accounts.unlink_telegram <address>
    python -m backend.accounts.unlink_telegram <handle>

`chat_link` will not unlink a chat unless a code arrives from that chat, which
is what stops a compromised web tier repointing somebody's daily summary. A user
who has lost the Telegram account itself cannot produce that message, and their
mail keeps arriving in a chat they no longer read. This is their way out.

Deliberately a command and not a page, for the same reason `whois` is. A route
that unlinks without proof is the bypass the rule exists to remove, and it would
sit inside the process the rule is aimed at.

It runs as the mail uid on the box, so using it means having a shell there. That
is the intended cost: it should be a phone call to an operator, not a button.
"""

from __future__ import annotations

import sys

from backend.accounts import account, chat_link


def resolve(value):
    """The account this argument names, or None. Takes an address or a handle,
    the same two shapes `whois` takes, so an operator working from a co-signer
    log does not have to translate first."""
    value = (value or "").strip()
    if not value:
        return None
    if account.HANDLE_RE.match(value):
        value = account.email_for_handle(value)
        if not value:
            return None
    return account.account_for_email(value)


def main(argv):
    if len(argv) != 1:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print("usage: python -m backend.accounts.unlink_telegram <address|handle>",
              file=sys.stderr)
        return 2
    acct = resolve(argv[0])
    if acct is None:
        print(f"no account matches {argv[0]!r}", file=sys.stderr)
        return 1
    if not acct.telegram:
        print(f"{acct.id} has no Telegram chat linked")
        return 0
    was = acct.telegram.chat_id
    chat_link.force_unlink(acct.id)
    print(f"{acct.id}: unlinked chat {was}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
