"""The RFC822 a draft is made of.

This is the riskiest part of the Node removal: the message shape is what Gmail
reads back, and a wrong header or a lost CRLF shows up as a mangled draft in a
user's mailbox rather than as an error. These cases were compared byte for byte
against the output of the create_draft.mjs builders before that file was
deleted, and they are pinned here so the comparison keeps its value now that the
other implementation is gone.

The boundary is passed in rather than generated so the output is stable; in use
it is random per message, as a MIME boundary must be.
"""

import base64

from backend.integrations.gmail_gcal import drafts

BOUNDARY = "BOUND_fixed0123456789ab"


def _built(payload):
    return drafts.build_rfc822(payload, boundary=BOUNDARY)


def _reply():
    return {
        "to": "alice@example.com",
        "subject": "Re: Lunch next week?",
        "body": "Hi Alice,\n\nLunch sounds great.\n\nBest,\nMorgan",
        "threadId": "t1",
        "inReplyTo": "<msg-e1@mail>",
        "references": "<a@mail> <b@mail>",
        "originalFrom": "Alice Adams <alice@contoso.com>",
        "originalDate": "Mon, 20 Jul 2026 09:00:00 +0000",
        "originalBody": "Hi Morgan,\r\nwant to grab lunch?\n\n<b>bold</b> & \"quotes\"\n",
    }


def test_reply_carries_threading_headers_and_gmails_quote_markup():
    out = _built(_reply())
    assert "In-Reply-To: <msg-e1@mail>\r\n" in out
    assert "References: <a@mail> <b@mail>\r\n" in out
    assert f'Content-Type: multipart/alternative; boundary="{BOUNDARY}"' in out
    # Both alternatives, in the order a mail client expects them.
    assert out.index("text/plain") < out.index("text/html")
    assert out.rstrip().endswith(f"--{BOUNDARY}--")
    # The quote block is Gmail's own, so a draft opened in the web UI collapses
    # the quoted text the way a native reply does.
    assert '<div class="gmail_quote gmail_quote_container">' in out
    assert '<div dir="ltr" class="gmail_attr">On Mon, 20 Jul 2026 09:00:00 +0000,' in out
    assert "&lt;b&gt;bold&lt;/b&gt; &amp; \"quotes\"" in out
    assert "> Hi Morgan,\n> want to grab lunch?" in out


def test_a_message_with_no_original_has_no_quote_at_all():
    out = _built({
        "to": "bob@example.com", "subject": "Plain", "body": "Just a body.",
    })
    assert "gmail_quote" not in out
    assert "wrote:" not in out
    assert out.endswith(f"--{BOUNDARY}--\r\n")


def test_non_ascii_headers_are_encoded_words():
    out = _built({
        "to": "Zoë Müller <zoe@example.com>",
        "subject": "Grüße",
        "body": "Héllo Zoë,\n\nBis bald.\n\nMorgan",
    })
    assert "To: =?UTF-8?B?" in out and "Subject: =?UTF-8?B?" in out
    assert "Zoë" not in out.split("\r\n\r\n")[0], "a raw non-ASCII header went out"
    # The body itself stays 8-bit UTF-8, which is what the parts declare.
    assert "Héllo Zoë," in out


def test_attribution_degrades_to_whichever_half_is_known():
    date_only = _built({"to": "c@x.com", "subject": "s", "body": "b",
                        "originalDate": "Tue, 21 Jul 2026 10:00:00 +0000"})
    assert "On Tue, 21 Jul 2026 10:00:00 +0000, wrote:" in date_only
    from_only = _built({"to": "d@x.com", "subject": "s", "body": "b",
                        "originalFrom": "Dave <dave@x.com>"})
    assert "Dave &lt;dave@x.com&gt; wrote:" in from_only


def test_the_raw_field_is_url_safe_base64_without_padding():
    raw = drafts.b64url(_built(_reply()))
    assert "+" not in raw and "/" not in raw and "=" not in raw
    decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode()
    assert decoded == _built(_reply())


def test_submit_updates_in_place_when_given_a_draft_id():
    """Progressive drafts depend on this: the placeholder and every status
    rewrite have to land on the same draft the user is watching."""
    seen = {}

    class Drafts:
        def create(self, userId, body):
            seen["create"] = body
            return _Execute({"id": "draft-1"})

        def update(self, userId, id, body):
            seen["update"] = (id, body)
            return _Execute({"id": id})

    class _Execute:
        def __init__(self, result):
            self._result = result

        def execute(self):
            return self._result

    class Users:
        def drafts(self):
            return Drafts()

    class Service:
        def users(self):
            return Users()

    import backend.integrations.gmail_gcal.drafts as mod
    original = mod.gmail
    mod.gmail = lambda account: Service()
    try:
        first = mod.submit(object(), _reply())
        again = mod.submit(object(), _reply(), draft_id=first)
    finally:
        mod.gmail = original
    assert first == "draft-1" and again == "draft-1"
    assert seen["update"][0] == "draft-1"
    assert seen["create"]["message"]["threadId"] == "t1"
