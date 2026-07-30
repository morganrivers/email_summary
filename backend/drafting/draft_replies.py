#!/usr/bin/env python3
"""
Generate Gmail drafts for incoming emails that likely warrant a personal reply.

Voice profile: ~/.system_files/voice-dna-email.md
Classifier: plain DeepSeek call.
Drafter: agentic_drafter — DeepSeek with calendar + email-search tools.
Drafts created via create_draft.mjs (sibling).
Telegram receives a single notification listing what was drafted.
"""

import os
import json
import re
import html
import subprocess
from pathlib import Path

from dotenv import load_dotenv

from backend import paths
from backend.drafting import agentic_drafter
from backend.integrations import llm_client
from backend.integrations.gmail_gcal.node_runner import node_env
from backend.integrations.telegram import send_telegram

FETCH_SCRIPT = paths.node_script("fetch_emails.mjs")
DRAFT_SCRIPT = paths.node_script("create_draft.mjs")
VOICE_PROFILE = Path.home() / ".system_files" / "voice-dna-email.md"

load_dotenv(paths.ENV_FILE)

DEEPSEEK_API_KEY = os.environ["DEEPSEEK_API_KEY"]

CLASSIFIER_PROMPT = (
    "Decide for each email whether the recipient should personally reply.\n\n"
    "Reply 'yes' when a specific human contact is personally writing to the recipient "
    "and clearly expects a direct personal response. The email should read like "
    "it was hand-written and sent to them individually (not as part of a list).\n\n"
    "Also reply 'yes' when the email is marked 'Thread: the recipient has written in "
    "this thread' AND it was hand-written by a specific human. A human continuing or "
    "closing a conversation the recipient took part in warrants a reply even when it "
    "asks no question: decisions, outcomes, rejections, and sign-offs on a personal "
    "back-and-forth all deserve an acknowledgement. This carve-out never applies to "
    "the categories below; an automated or bulk message stays 'no' however the thread "
    "is marked.\n\n"
    "Reply 'no' for ALL of the following, even if they contain a call to action, "
    "an interesting opportunity, or a deadline:\n"
    "- Newsletters, Substack posts, blog digests (even ones soliciting pitches or submissions)\n"
    "- Marketing, promotional, sales, or fundraising emails\n"
    "- Automated notifications, alerts, confirmations, and digests\n"
    "- Anything from no-reply, noreply, donotreply, jobalerts, notifications, marketing, or similar senders\n"
    "- Calendar invites without explicit personal questions directed at the recipient\n"
    "- Receipts, invoices, shipping updates, package notifications, order confirmations\n"
    "- Mass-mailed announcements, event invitations, conference CFPs\n"
    "- Job alerts and recruitment broadcasts (even from real recruiters using mass tools)\n"
    "- Security alerts, account notifications, system messages\n"
    "- Bulk emails identifiable by 'List-Unsubscribe' style cues, generic greetings, or 'view in browser' links\n\n"
    "When unsure, prefer 'no'. False positives create draft noise; missed emails are recoverable "
    "via the daily summary.\n\n"
    "Output JSON: {\"decisions\": [{\"index\": int, \"needs_reply\": bool, \"reason\": str}, ...]}. "
    "Include one entry per input email. Keep each reason to one short sentence."
)

DRAFTER_INSTRUCTION = (
    "\n\nWrite a reply email that follows the voice profile above. "
    "Output the email body only, including the greeting and sign-off as the profile dictates. "
    "No subject line. No commentary. No markdown fences. Plain text only."
)


def fetch_emails():
    result = subprocess.run(
        ["node", str(FETCH_SCRIPT)],
        stdout=subprocess.PIPE, stderr=None, timeout=120,
    )
    assert result.returncode == 0, f"fetch_emails.mjs exited {result.returncode}"
    return json.loads(result.stdout)


def thread_participation_line(email):
    """Render the deterministic participation signal fetch_emails.mjs attaches.
    Absent (older payloads, failed lookup) reads as 'not established' so the
    carve-out only fires on a positive signal from Gmail's own SENT label."""
    if email.get("userParticipated"):
        return "Thread: the recipient has written in this thread"
    return "Thread: no earlier message from the recipient in this thread"


def classify(client, emails, identity=None):
    listing = "\n\n".join(
        f"[{i}] From: {e['from']}\nSubject: {e['subject']}\n"
        f"{thread_participation_line(e)}\nBody: {e['body'][:1500]}"
        for i, e in enumerate(emails)
    )
    parsed = llm_client.complete_json(
        client,
        messages=[
            {"role": "system", "content": CLASSIFIER_PROMPT},
            {"role": "user", "content": listing},
        ],
        identity=identity,
    )
    return {d["index"]: d for d in parsed.get("decisions", [])}


def draft_body(client, voice, email, account):
    sys_prompt = voice + DRAFTER_INSTRUCTION
    user_prompt = (
        f"Original email:\n"
        f"From: {email['from']}\n"
        f"Date: {email['date']}\n"
        f"Subject: {email['subject']}\n\n"
        f"{email['body']}\n\n"
        "Draft a reply."
    )
    return agentic_drafter.draft(
        client, sys_prompt, user_prompt,
        thread_id=f"auto-{email['id']}",
        identity=account.identity, creds_dir=account.creds_dir,
    )  # returns (body, run_url)


def reply_subject(subject):
    s = subject.strip()
    if re.match(r'^re:\s', s, re.IGNORECASE):
        return s
    return f"Re: {s}"


def reply_to_address(from_header):
    m = re.search(r'<([^>]+)>', from_header)
    return m.group(1) if m else from_header.strip()


def reply_references(email):
    refs = email.get("referencesHeader", "").strip()
    mid = email.get("messageIdHeader", "").strip()
    parts = [refs, mid] if refs else [mid]
    return " ".join(p for p in parts if p)


def submit_draft(account, payload, draft_id=None):
    """Create or update a Gmail draft. If draft_id is given, updates in place.
    Sole subprocess boundary to create_draft.mjs; routes to account's mailbox."""
    if draft_id:
        payload = {**payload, "draftId": draft_id}
    result = subprocess.run(
        ["node", str(DRAFT_SCRIPT)],
        input=json.dumps(payload),
        capture_output=True, text=True, timeout=60,
        env=node_env(account.creds_dir),
    )
    assert result.returncode == 0, f"create_draft.mjs failed: {result.stderr}"
    return json.loads(result.stdout)["draftId"]


def gmail_thread_link(thread_id):
    """Single source of truth for Gmail thread deep-links."""
    return f"https://mail.google.com/mail/u/0/#all/{thread_id}" if thread_id else None


def format_draft_line(sender, subject, thread_id=None, trace_url=None,
                      reason=None, bullet=""):
    """One shared render for draft-notification line items across Telegram messages."""
    sender_e = html.escape(sender or "")
    subject_e = html.escape(subject or "")
    link = gmail_thread_link(thread_id)
    if link:
        head = f'<a href="{html.escape(link)}"><b>{sender_e}</b>: {subject_e}</a>'
    else:
        head = f'<b>{sender_e}</b>: {subject_e}'
    lines = [f"{bullet}{head}"] if bullet else [head]
    if reason:
        lines.append(f"  <i>{html.escape(reason)}</i>")
    if trace_url:
        lines.append(f'  <a href="{html.escape(trace_url)}">trace</a>')
    return "\n".join(lines)


def build_draft_payload(*, to, subject, body, thread_id, in_reply_to, references,
                        original_from, original_date, original_body):
    """Single source of truth for the create_draft.mjs payload shape."""
    assert to and subject and body, "to, subject, body are required"
    return {
        "to": to,
        "subject": subject,
        "body": body,
        "threadId": thread_id,
        "inReplyTo": in_reply_to or "",
        "references": references or "",
        "originalFrom": original_from or "",
        "originalDate": original_date or "",
        "originalBody": original_body or "",
    }


def create_draft(account, email, body_text):
    payload = build_draft_payload(
        to=reply_to_address(email["from"]),
        subject=reply_subject(email["subject"]),
        body=body_text,
        thread_id=email["threadId"],
        in_reply_to=email.get("messageIdHeader", ""),
        references=reply_references(email),
        original_from=email.get("from", ""),
        original_date=email.get("date", ""),
        original_body=email.get("body", ""),
    )
    return submit_draft(account, payload)


def render_telegram(drafted):
    lines = [f"📝 <b>{len(drafted)} draft(s) created</b>", ""]
    for d in drafted:
        lines.append(format_draft_line(
            d["from"], d["subject"],
            thread_id=d.get("thread_id"),
            trace_url=d.get("run_url"),
            reason=d.get("reason"),
            bullet="• ",
        ))
    return "\n".join(lines)


def render_rejected_telegram(rejected):
    lines = [f"🚫 <b>{len(rejected)} draft(s) rejected (em-dash)</b>", ""]
    for r in rejected:
        lines.append(format_draft_line(
            r["from"], r["subject"],
            thread_id=r.get("thread_id"),
            trace_url=r.get("run_url"),
            bullet="• ",
        ))
    return "\n".join(lines)


def process_emails(account, emails):
    assert isinstance(emails, list), "emails must be a list"
    if not emails:
        return []
    assert VOICE_PROFILE.exists(), f"Voice profile not found at {VOICE_PROFILE}"
    voice = VOICE_PROFILE.read_text()

    client = agentic_drafter.make_client(DEEPSEEK_API_KEY)
    decisions = classify(client, emails, account.identity)

    drafted = []
    rejected = []
    for i, email in enumerate(emails):
        d = decisions.get(i)
        if not d or not d.get("needs_reply"):
            continue
        body, run_url = draft_body(client, voice, email, account)
        if agentic_drafter.contains_em_dash(body):
            rejected.append({
                "from": email["from"],
                "subject": email["subject"],
                "run_url": run_url,
                "thread_id": email["threadId"],
            })
            continue
        draft_id = create_draft(account, email, body)
        drafted.append({
            "from": email["from"],
            "subject": email["subject"],
            "reason": d.get("reason", ""),
            "run_url": run_url,
            "draft_id": draft_id,
            "thread_id": email["threadId"],
        })

    if drafted:
        send_telegram(render_telegram(drafted), account.telegram)
    if rejected:
        send_telegram(render_rejected_telegram(rejected), account.telegram)
    return drafted


def main():
    from backend.accounts import account as account_mod
    acct = account_mod.default_account()
    emails = fetch_emails()
    process_emails(acct, emails)


if __name__ == "__main__":
    main()
