"""Manual draft mode: triggered by forwarding an email to BOT_ALIAS.

User forwards an email to danielmorganrivers+bot@gmail.com with optional context
typed at the top. Parser splits out the user context and the original message
metadata. Drafter generates a reply on the ORIGINAL thread (looked up by
from+subject) using the agentic drafter with calendar + email tools.
"""

import re
import json
import subprocess
import html
from pathlib import Path

import agentic_drafter
import draft_replies

SCRIPT_DIR = Path(__file__).parent
FIND_THREAD = SCRIPT_DIR / "find_thread.mjs"
GET_THREAD = SCRIPT_DIR / "get_thread.mjs"

BOT_ALIAS = "danielmorganrivers+bot@gmail.com"

FORWARD_MARKER = re.compile(r'-{3,}\s*Forwarded message\s*-{1,}', re.IGNORECASE)
HEADER_RE = re.compile(r'^([A-Za-z-]+):\s*(.+)$')
ADDRESS_RE = re.compile(r'<([^>]+)>')

DRAFTER_WITH_CONTEXT = (
    "\n\nWrite a reply email that follows the voice profile above. "
    "Morgan has supplied his own context for how to respond — let that guide tone and content, "
    "while staying true to the voice profile. "
    "Output the email body only, including the greeting and sign-off as the profile dictates. "
    "No subject line. No commentary. No markdown fences. Plain text only."
)


def is_bot_request(email):
    return BOT_ALIAS in (email.get("to") or "").lower()


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


def find_thread(from_email, subject):
    result = subprocess.run(
        ["node", str(FIND_THREAD), "--from", from_email, "--subject", subject or ""],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
    )
    assert result.returncode == 0, f"find_thread.mjs failed: {result.stderr.decode()}"
    return json.loads(result.stdout)


def get_thread(thread_id):
    result = subprocess.run(
        ["node", str(GET_THREAD), "--thread-id", thread_id],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
    )
    assert result.returncode == 0, f"get_thread.mjs failed: {result.stderr.decode()}"
    return json.loads(result.stdout)


def parse_from_thread(forwarded_email):
    """Fallback when body has no forward marker.

    Treats the +bot@ message as a reply within an existing thread: fetch the
    thread, pick the most recent message that isn't the user's bot-addressed one,
    and use that as the 'original'. The forwarded_email's body becomes context.
    """
    tid = forwarded_email.get("threadId")
    self_id = forwarded_email.get("id")
    if not tid:
        return None
    thread = get_thread(tid)
    messages = thread.get("messages") or []
    if len(messages) < 2:
        return None
    prior = None
    for m in reversed(messages):
        if m.get("id") == self_id:
            continue
        if BOT_ALIAS in (m.get("to") or "").lower():
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
    s = (subj or "").strip()
    s = re.sub(r'^(re:|fwd:|fw:)\s*', '', s, flags=re.IGNORECASE)
    return f"Re: {s}" if s else "Re:"


def draft_with_context(client, voice, parsed, thread_id=None):
    sys_prompt = voice + DRAFTER_WITH_CONTEXT
    context_section = (
        f"Morgan's context for this reply:\n{parsed['context']}\n\n"
        if parsed["context"] else
        "Morgan did not supply additional context — use only the email content + voice profile.\n\n"
    )
    user_prompt = (
        f"Original email Morgan received:\n"
        f"From: {parsed['original_from']}\n"
        f"Date: {parsed['original_date']}\n"
        f"Subject: {parsed['original_subject']}\n\n"
        f"{parsed['original_body']}\n\n"
        f"{context_section}"
        "Draft the reply."
    )
    return agentic_drafter.draft(client, sys_prompt, user_prompt, thread_id=thread_id)


def process_draft_request(forwarded_email):
    parsed = parse_forward(forwarded_email.get("body", ""))
    if not parsed:
        parsed = parse_from_thread(forwarded_email)
    if not parsed:
        draft_replies.send_telegram(
            f"⚠️ Couldn't parse forwarded email: {html.escape(forwarded_email.get('subject', ''))}"
        )
        return None
    if not parsed["original_email"]:
        draft_replies.send_telegram(
            "⚠️ Forwarded email had no parseable 'From' header."
        )
        return None

    assert draft_replies.VOICE_PROFILE.exists(), \
        f"Voice profile not found at {draft_replies.VOICE_PROFILE}"
    voice = draft_replies.VOICE_PROFILE.read_text()

    thread_info = find_thread(parsed["original_email"], parsed["original_subject"])
    client = agentic_drafter.make_client(draft_replies.DEEPSEEK_API_KEY)
    body, run_url = draft_with_context(
        client, voice, parsed,
        thread_id=f"manual-{forwarded_email.get('id', '')}",
    )

    trace_line = f"\n<a href=\"{html.escape(run_url)}\">trace</a>" if run_url else ""

    if agentic_drafter.contains_em_dash(body):
        draft_replies.send_telegram(
            f"🚫 Contextual draft rejected (em-dash)\n"
            f"→ <b>{html.escape(parsed['original_from'])}</b>\n"
            f"  {html.escape(parsed['original_subject'])}"
            f"{trace_line}"
        )
        return None

    payload = {
        "to": parsed["original_email"],
        "subject": reply_subject(parsed["original_subject"]),
        "body": body,
        "threadId": thread_info.get("threadId") if thread_info.get("found") else None,
        "inReplyTo": thread_info.get("messageIdHeader", "") if thread_info.get("found") else "",
        "references": build_references(thread_info) if thread_info.get("found") else "",
    }
    draft_id = draft_replies.submit_draft(payload)

    if thread_info.get("found"):
        msg = (
            f"📝 Contextual draft created\n"
            f"→ <b>{html.escape(parsed['original_from'])}</b>\n"
            f"  {html.escape(parsed['original_subject'])}"
            f"{trace_line}"
        )
    else:
        msg = (
            f"📝 Contextual draft created (no matching thread, sent as new email)\n"
            f"→ <b>{html.escape(parsed['original_from'])}</b>\n"
            f"  {html.escape(parsed['original_subject'])}"
            f"{trace_line}"
        )
    draft_replies.send_telegram(msg)
    return draft_id
