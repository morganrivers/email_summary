"""Manual draft mode: triggered by forwarding an email to the account's bot alias.

A user forwards an email to their own plus-alias (user+bot@gmail.com) with
optional context typed at the top. Parser splits out the user context and the
original message metadata. Drafter generates a reply on the ORIGINAL thread
(looked up by from+subject) using the agentic drafter with calendar + email
tools.

The alias is derived per account rather than hardcoded. It used to be the box
owner's literal address, checked against every account's mail, so no other user
could trigger the path and the owner's alias could fire inside someone else's
mailbox.
"""

import html
import json
import re

from backend.drafting import agentic_drafter, draft_replies
from backend.integrations import llm_client
from backend.integrations.gmail_gcal import gmail_api

BOT_TAG = "bot"

FORWARD_MARKER = re.compile(r'-{3,}\s*Forwarded message\s*-{1,}', re.IGNORECASE)
HEADER_RE = re.compile(r'^([A-Za-z-]+):\s*(.+)$')
ADDRESS_RE = re.compile(r'<([^>]+)>')

DRAFTER_WITH_CONTEXT = (
    "\n\nWrite a reply email that follows the voice profile above. "
    "The account owner has supplied their own context for how to respond, so let that guide "
    "tone and content, while staying true to the voice profile. "
    "Output the email body only, including the greeting and sign-off as the profile dictates. "
    "No subject line. No commentary. No markdown fences. Plain text only."
)


def bot_alias(account):
    """The plus-alias this account forwards to. Single source of the derivation,
    used both to recognise a request and to explain the feature in the UI."""
    local, _, domain = account.primary_email.partition("@")
    assert local and domain, (
        f"account {account.id!r} has no mail address to derive a bot alias from"
    )
    return f"{local}+{BOT_TAG}@{domain}".lower()


def is_bot_request(email, account):
    return bot_alias(account) in (email.get("to") or "").lower()


def parse_forward(body):
    """Return dict with context + original_email metadata, or None if not parseable."""
    if not body:
        return None
    m = FORWARD_MARKER.search(body)
    if not m:
        return None

    context = body[:m.start()].strip()
    after_marker = body[m.end():].lstrip("\n")

    parts = after_marker.split("\n\n", 1)
    header_block = parts[0]
    original_body = parts[1].strip() if len(parts) > 1 else ""

    headers = {}
    for line in header_block.splitlines():
        hm = HEADER_RE.match(line.strip())
        if hm:
            headers[hm.group(1).lower()] = hm.group(2).strip()

    original_from_raw = headers.get("from", "")
    addr_m = ADDRESS_RE.search(original_from_raw)
    original_email = addr_m.group(1) if addr_m else original_from_raw.strip()

    return {
        "context": context,
        "original_email": original_email,
        "original_from": original_from_raw,
        "original_subject": headers.get("subject", ""),
        "original_date": headers.get("date", ""),
        "original_body": original_body,
    }


def find_thread(account, from_email, subject):
    return gmail_api.find_thread_by_from_subject(account, from_email, subject or "")


def get_thread(account, thread_id):
    return gmail_api.get_thread(account, thread_id)


def parse_from_thread(account, forwarded_email):
    """Fallback when body has no forward marker.

    Treats the +bot@ message as a reply within an existing thread: fetch the
    thread, pick the most recent message that isn't the user's bot-addressed one,
    and use that as the 'original'. The forwarded_email's body becomes context.
    """
    tid = forwarded_email.get("threadId")
    self_id = forwarded_email.get("id")
    if not tid:
        return None
    thread = get_thread(account, tid)
    messages = thread.get("messages") or []
    if len(messages) < 2:
        return None
    alias = bot_alias(account)
    prior = None
    for m in reversed(messages):
        if m.get("id") == self_id:
            continue
        if alias in (m.get("to") or "").lower():
            continue
        prior = m
        break
    if prior is None:
        return None
    addr_m = ADDRESS_RE.search(prior.get("from", ""))
    original_email = addr_m.group(1) if addr_m else (prior.get("from") or "").strip()
    return {
        "context": (forwarded_email.get("body") or "").strip(),
        "original_email": original_email,
        "original_from": prior.get("from", ""),
        "original_subject": prior.get("subject", ""),
        "original_date": prior.get("date", ""),
        "original_body": prior.get("body", ""),
    }


def build_references(thread_info):
    refs = (thread_info.get("referencesHeader") or "").strip()
    mid = (thread_info.get("messageIdHeader") or "").strip()
    parts = [refs, mid] if refs else [mid]
    return " ".join(p for p in parts if p)


def reply_subject(subj):
    s = gmail_api.strip_reply_prefixes(subj)
    return f"Re: {s}" if s else "Re:"


def draft_with_context(client, instructions, parsed, account, on_iteration=None):
    sys_prompt = instructions + DRAFTER_WITH_CONTEXT
    owner = account.display_name
    # The owner's own instructions are trusted; the forwarded email is not, so
    # only the latter is fenced. The fence is made here and handed to draft(),
    # which states its rule in the system message.
    fence = agentic_drafter.new_fence()
    context_section = (
        f"{owner}'s context for this reply:\n{parsed['context']}\n\n"
        if parsed["context"] else
        f"{owner} did not supply additional context, so use only the email content "
        "and the voice profile.\n\n"
    )
    user_prompt = (
        f"Original email {owner} received:\n"
        + fence.wrap(
            f"From: {parsed['original_from']}\n"
            f"Date: {parsed['original_date']}\n"
            f"Subject: {parsed['original_subject']}\n\n"
            f"{parsed['original_body']}"
        )
        + "\n\n"
        + context_section
        + "Draft the reply."
    )
    return agentic_drafter.draft(client, sys_prompt, user_prompt,
                                 on_iteration=on_iteration,
                                 account=account, fence=fence)


def render_progress_body(iter_num, msg, tool_history, final):
    lines = []
    if final:
        lines.append(f"⏳ Finalizing reply (iteration {iter_num})...")
    else:
        lines.append(f"⏳ Drafting — iteration {iter_num}")
    lines.append("")
    if tool_history:
        lines.append("Tools called so far:")
        for th in tool_history:
            args_str = json.dumps(th["args"])
            if len(args_str) > 120:
                args_str = args_str[:117] + "..."
            lines.append(f"• {th['name']}({args_str})")
            lines.append(f"    ↳ {th['result_summary']}")
        lines.append("")
    content_preview = (getattr(msg, "content", "") or "").strip()
    if content_preview:
        if len(content_preview) > 800:
            content_preview = content_preview[:797] + "..."
        lines.append("Model's current output:")
        lines.append(content_preview)
        lines.append("")
    pending_tools = getattr(msg, "tool_calls", None) or []
    if pending_tools:
        lines.append(f"Queued next: {len(pending_tools)} tool call(s)")
        for tc in pending_tools:
            lines.append(f"• {tc.function.name}")
        lines.append("")
    lines.append("(This draft will be replaced when the final reply is ready.)")
    return "\n".join(lines)


def process_draft_request(account, forwarded_email):
    parsed = parse_forward(forwarded_email.get("body", ""))
    if not parsed:
        parsed = parse_from_thread(account, forwarded_email)
    if not parsed:
        draft_replies.send_telegram(
            f"⚠️ Couldn't parse forwarded email: {html.escape(forwarded_email.get('subject', ''))}",
            account.telegram,
        )
        return None
    if not parsed["original_email"]:
        draft_replies.send_telegram(
            "⚠️ Forwarded email had no parseable 'From' header.",
            account.telegram,
        )
        return None

    instructions = draft_replies.drafting_instructions(account)

    thread_info = find_thread(account, parsed["original_email"], parsed["original_subject"])
    client = llm_client.make_client(account)
    found = thread_info.get("found")
    thread_id = thread_info.get("threadId") if found else None

    def make_payload(body_text):
        return draft_replies.build_draft_payload(
            to=parsed["original_email"],
            subject=reply_subject(parsed["original_subject"]),
            body=body_text,
            thread_id=thread_id,
            in_reply_to=thread_info.get("messageIdHeader", "") if found else "",
            references=build_references(thread_info) if found else "",
            original_from=parsed.get("original_from", ""),
            original_date=parsed.get("original_date", ""),
            original_body=parsed.get("original_body", ""),
        )

    placeholder = (
        "⏳ Drafting your reply, please wait...\n\n"
        "The AI is thinking. This draft will be overwritten as work progresses."
    )
    draft_id = draft_replies.submit_draft(account, make_payload(placeholder))

    def on_iteration(iter_num, msg, tool_history, final):
        body_text = render_progress_body(iter_num, msg, tool_history, final)
        draft_replies.submit_draft(account, make_payload(body_text), draft_id=draft_id)

    try:
        body = draft_with_context(
            client, instructions, parsed, account,
            on_iteration=on_iteration,
        )
    except AssertionError as err:
        err_body = f"⚠️ Drafter failed: {err}"
        draft_replies.submit_draft(account, make_payload(err_body), draft_id=draft_id)
        draft_replies.send_telegram(
            "⚠️ <b>Contextual draft failed</b>\n"
            + draft_replies.format_draft_line(
                parsed["original_from"], parsed["original_subject"],
                thread_id=thread_id,
                reason=str(err),
            ),
            account.telegram,
        )
        return None

    if agentic_drafter.dashes_banned(account) and agentic_drafter.contains_em_dash(body):
        rejection_body = f"🚫 Draft rejected (em-dash detected):\n\n{body}"
        draft_replies.submit_draft(account, make_payload(rejection_body), draft_id=draft_id)
        draft_replies.send_telegram(
            "🚫 <b>Contextual draft rejected (em-dash)</b>\n"
            + draft_replies.format_draft_line(
                parsed["original_from"], parsed["original_subject"],
                thread_id=thread_id,
            ),
            account.telegram,
        )
        return None

    draft_replies.submit_draft(account, make_payload(body), draft_id=draft_id)

    header = "📝 <b>Contextual draft created</b>" if found else \
        "📝 <b>Contextual draft created (no matching thread)</b>"
    draft_replies.send_telegram(
        header + "\n"
        + draft_replies.format_draft_line(
            parsed["original_from"], parsed["original_subject"],
            thread_id=thread_id,
        ),
        account.telegram,
    )
    return draft_id
