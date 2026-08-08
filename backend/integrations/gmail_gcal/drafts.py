"""Gmail draft creation. The Python replacement for create_draft.mjs.

Two things live here: the RFC822 assembly (multipart/alternative, a plain part
and an HTML part carrying Gmail's own quote markup) and the drafts.create /
drafts.update call. The update path is what makes progressive drafts work: the
manual path creates a placeholder immediately and overwrites the same draft id
on every drafter iteration, so the user watches it fill in rather than waiting.

The message shape is deliberately the one Gmail itself produces for a reply --
the `gmail_quote` container and the attribution line -- so a draft opened in the
web UI collapses the quoted text the way a native reply does.
"""

from __future__ import annotations

import base64
import html
import re
import secrets

from backend.integrations.gmail_gcal.gmail_api import gmail

NON_ASCII = re.compile(r"[^\x20-\x7e]")
CRLF = re.compile(r"[\r\n]")
ADDRESS = re.compile(r"^\s*(?P<phrase>.*?)\s*<(?P<addr>[^<>]*)>\s*$")
MESSAGE_ID = re.compile(r"<[^<>\s]{1,512}>")


def strip_folding(value):
    """Collapse CR and LF in a value destined for a header.

    Every value that reaches a header here came out of Gmail's parser already
    unfolded, so a line break in one is not a legal fold: it is a sender's
    attempt to end our header and start their own. Nothing downstream needs to
    tell the two apart, so both become a space."""
    return CRLF.sub(" ", value or "")


def encode_header(value):
    """RFC 2047 encoded-word for a header phrase that is not plain ASCII."""
    value = strip_folding(value)
    if NON_ASCII.search(value):
        encoded = base64.b64encode(value.encode()).decode()
        value = f"=?UTF-8?B?{encoded}?="
    assert not CRLF.search(value), "a header value kept a line break"
    return value


def encode_address(value):
    """An address header. RFC 2047 encoded-words are legal in the display
    phrase and nowhere else, so encoding `Zoe Muller <zoe@x.com>` whole
    produces a header no mail server will route. The two halves are encoded
    apart, and a value with no angle brackets is a bare addr-spec."""
    value = strip_folding(value)
    match = ADDRESS.match(value)
    if not match:
        return encode_header(value)
    addr = match.group("addr").strip()
    assert not NON_ASCII.search(addr), f"non-ASCII address: {addr!r}"
    phrase = match.group("phrase").strip().strip('"')
    return f"{encode_header(phrase)} <{addr}>" if phrase else f"<{addr}>"


def message_ids(value):
    """The msg-id tokens of In-Reply-To / References, and nothing else.

    These are copied from the incoming mail's own headers, so their content is
    chosen by whoever sent it. Keeping only well-formed <...> tokens is what
    stops one from carrying a line break and appending a header of its own,
    a Bcc for instance, to a draft the account owner is about to send."""
    return " ".join(MESSAGE_ID.findall(value or ""))


def escape_html(text):
    """Escape text for HTML, quotes included.

    Everything this escapes today lands in element content, where a quote is
    already inert, so `quote=True` buys nothing at present. It is what keeps
    the function safe for the caller who has not been written yet: put one of
    these values in an attribute (a `title`, an `href`) with only `&<>`
    escaped and the value closes the attribute and opens another. The escaping
    is stdlib rather than a chain of `.replace()` calls so the ordering `&`
    depends on is not ours to get wrong."""
    return html.escape(text or "", quote=True)


def plain_to_html(text):
    return re.sub(r"\r?\n", "<br>\n", escape_html(text))


def plain_quote(original_body):
    lines = (original_body or "").replace("\r\n", "\n").split("\n")
    return "\n".join("> " + line for line in lines)


def build_attribution(payload):
    parts = []
    if payload.get("originalDate"):
        parts.append(f"On {payload['originalDate']},")
    if payload.get("originalFrom"):
        parts.append(payload["originalFrom"])
    parts.append("wrote:")
    return " ".join(parts)


def has_quote(payload):
    return bool(payload.get("originalBody") or payload.get("originalFrom")
                or payload.get("originalDate"))


def build_plain(payload):
    if not has_quote(payload):
        return payload["body"]
    header = build_attribution(payload)
    quoted = plain_quote(payload["originalBody"]) if payload.get("originalBody") else ""
    return payload["body"] + "\r\n\r\n" + header + "\r\n" + quoted


def build_html(payload):
    body_html = '<div dir="ltr">' + plain_to_html(payload["body"]) + "</div>"
    if not has_quote(payload):
        return "<html><body>" + body_html + "</body></html>"
    attribution = escape_html(build_attribution(payload))
    quoted_html = (plain_to_html(payload["originalBody"])
                   if payload.get("originalBody") else "")
    quote_block = (
        '<div class="gmail_quote gmail_quote_container">'
        '<div dir="ltr" class="gmail_attr">' + attribution + "<br></div>"
        '<blockquote class="gmail_quote" '
        'style="margin:0 0 0 .8ex;border-left:1px solid #ccc;padding-left:1ex">'
        + quoted_html +
        "</blockquote>"
        "</div>"
    )
    return "<html><body>" + body_html + "<br>" + quote_block + "</body></html>"


def build_rfc822(payload, boundary=None):
    """The full message. `boundary` is a parameter only so a test can pin the
    output; in use it is random per message, as a MIME boundary must be."""
    boundary = boundary or "BOUND_" + secrets.token_hex(12)
    headers = [
        f"To: {encode_address(payload['to'])}",
        f"Subject: {encode_header(payload['subject'])}",
        "MIME-Version: 1.0",
        f'Content-Type: multipart/alternative; boundary="{boundary}"',
    ]
    in_reply_to = message_ids(payload.get("inReplyTo"))
    if in_reply_to:
        headers.append(f"In-Reply-To: {in_reply_to}")
    references = message_ids(payload.get("references"))
    if references:
        headers.append(f"References: {references}")
    assert not any(CRLF.search(h) for h in headers), "a header carried a line break"

    plain_part = (
        f"--{boundary}\r\n"
        "Content-Type: text/plain; charset=UTF-8\r\n"
        "Content-Transfer-Encoding: 8bit\r\n\r\n"
        + build_plain(payload)
    )
    html_part = (
        f"--{boundary}\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Content-Transfer-Encoding: 8bit\r\n\r\n"
        + build_html(payload)
    )
    closer = f"--{boundary}--\r\n"
    return ("\r\n".join(headers) + "\r\n\r\n"
            + plain_part + "\r\n\r\n"
            + html_part + "\r\n\r\n"
            + closer)


def b64url(text):
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def submit(account, payload, draft_id=None):
    """Create a draft, or update one in place when draft_id is given. Returns
    the draft id, which is the same value on every update of one draft."""
    assert payload.get("to") and payload.get("subject") and payload.get("body"), (
        "a draft needs to, subject and body"
    )
    message = {"raw": b64url(build_rfc822(payload))}
    if payload.get("threadId"):
        message["threadId"] = payload["threadId"]
    drafts = gmail(account).users().drafts()
    if draft_id:
        result = drafts.update(userId="me", id=draft_id,
                               body={"message": message}).execute()
    else:
        result = drafts.create(userId="me", body={"message": message}).execute()
    created = result.get("id")
    assert created, "Gmail returned a draft with no id"
    return created
