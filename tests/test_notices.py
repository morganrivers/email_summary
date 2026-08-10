"""Messages Letterlock puts in a user's own mailbox.

One call, `messages.insert`, and the reason it is that call rather than
`messages.send`: the scopes have permitted sending all along, so no code path
calling it is the whole of "Letterlock drafts, it never sends". A test that
watches which method is invoked is what keeps that from being undone by
somebody reaching for the obvious API.
"""

import base64

import pytest

from backend.integrations.gmail_gcal import notices


class Messages:
    def __init__(self):
        self.inserted = None
        self.sent = False

    def insert(self, **kwargs):
        self.inserted = kwargs
        return Execute({"id": "m1"})

    def send(self, **kwargs):
        self.sent = True
        return Execute({"id": "m1"})


class Execute:
    def __init__(self, result):
        self.result = result

    def execute(self):
        return self.result


class Service:
    def __init__(self, messages):
        self._messages = messages

    def users(self):
        return self

    def messages(self):
        return self._messages


class Acct:
    id = "dana@x.com"


@pytest.fixture
def messages(monkeypatch):
    msgs = Messages()
    monkeypatch.setattr(notices.gmail_api, "gmail", lambda account: Service(msgs))
    return msgs


def _raw_of(messages):
    padded = messages.inserted["body"]["raw"] + "=" * (
        -len(messages.inserted["body"]["raw"]) % 4)
    return base64.urlsafe_b64decode(padded).decode()


def test_a_notice_is_inserted_and_never_sent(messages):
    """The distinction the whole module rests on. `insert` writes into the
    mailbox and nothing traverses SMTP; `send` would put mail on the internet
    over a user's own address, which nothing here is allowed to do."""
    notices.insert_notice(Acct(), "Your code", "LL-ABCDEFGH")

    assert messages.inserted is not None
    assert messages.sent is False
    assert messages.inserted["userId"] == "me"
    assert messages.inserted["body"]["labelIds"] == ["INBOX", "UNREAD"]


def test_the_message_is_addressed_to_the_account_itself(messages):
    notices.insert_notice(Acct(), "Your code", "LL-ABCDEFGH")
    raw = _raw_of(messages)

    assert "To: dana@x.com" in raw
    assert "Subject: Your code" in raw
    assert raw.endswith("LL-ABCDEFGH")
    assert "Message-ID: <" in raw, "a standalone message needs one"


def test_a_header_cannot_be_ended_by_the_text_put_in_it():
    """Same rule as the draft path, and the same reason: a value carrying a line
    break appends a header of its own to a message we assembled."""
    raw = notices.build_notice("dana@x.com", "Your code\r\nBcc: attacker@evil.io",
                               "body")
    headers = raw.split("\r\n\r\n")[0].split("\r\n")
    assert not any(h.startswith("Bcc:") for h in headers), "a header was injected"
    subject = [h for h in headers if h.startswith("Subject:")]
    assert len(subject) == 1 and "Bcc: attacker@evil.io" in subject[0], (
        "the break became whitespace rather than the value being dropped"
    )


def test_a_notice_needs_all_three_parts():
    with pytest.raises(AssertionError):
        notices.build_notice("dana@x.com", "", "body")
