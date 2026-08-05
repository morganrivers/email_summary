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
import re
import secrets

from backend.integrations.gmail_gcal.gmail_api import gmail

NON_ASCII = re.compile(r"[^\x20-\x7e]")


def encode_header(value):
    """RFC 2047 encoded-word for a header that is not plain ASCII."""
    value = value or ""
    if NON_ASCII.search(value):
        encoded = base64.b64encode(value.encode()).decode()
        return f"=?UTF-8?B?{encoded}?="
    return value


def escape_html(text):
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


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
        f"To: {encode_header(payload['to'])}",
        f"Subject: {encode_header(payload['subject'])}",
        "MIME-Version: 1.0",
        f'Content-Type: multipart/alternative; boundary="{boundary}"',
    ]
    if payload.get("inReplyTo"):
        headers.append(f"In-Reply-To: {payload['inReplyTo']}")
    if payload.get("references"):
        headers.append(f"References: {payload['references']}")

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
