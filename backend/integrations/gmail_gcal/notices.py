"""Messages Letterlock puts in a user's own inbox.

Separate from `drafts.py`, which builds a reply the user will send to somebody
else. This builds a message addressed to the account itself and inserted into
its mailbox, so it carries the headers a standalone message needs (From, Date,
Message-ID) and none of the reply machinery.

The header encoding is `drafts`', not a second copy: an address is split at the
angle brackets and a non-ASCII phrase is an encoded-word, and getting that
subtly different in two places is how one of them ends up wrong.

Nothing here sends. See `gmail_api.insert_message` for why that distinction is
the one worth keeping.
"""

from __future__ import annotations

import email.utils

from backend import site
from backend.integrations.gmail_gcal import drafts, gmail_api

# The From of a message that never leaves the box. It is not a deliverable
# address and is not meant to be one: no SMTP is involved, and a reply to it
# would bounce, which is why the body says not to reply.
NOTICE_FROM = f"Letterlock <noreply@{site.APP_HOST}>"


def build_notice(to_address, subject, body):
    """A complete RFC822 text/plain message, ready to insert."""
    assert to_address and subject and body, "a notice needs to, subject and body"
    headers = [
        f"From: {drafts.encode_address(NOTICE_FROM)}",
        f"To: {drafts.encode_address(to_address)}",
        f"Subject: {drafts.encode_header(subject)}",
        f"Date: {email.utils.formatdate(localtime=False)}",
        f"Message-ID: {email.utils.make_msgid(domain=site.APP_HOST)}",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=UTF-8",
        "Content-Transfer-Encoding: 8bit",
    ]
    assert not any(drafts.CRLF.search(h) for h in headers), (
        "a notice header carried a line break"
    )
    return "\r\n".join(headers) + "\r\n\r\n" + body


def insert_notice(account, subject, body):
    """Put one notice in this account's inbox. Returns the Gmail message id."""
    raw = build_notice(account.id, subject, body)
    return gmail_api.insert_message(account, drafts.b64url(raw))
