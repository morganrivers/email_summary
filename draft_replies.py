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
import requests

import agentic_drafter

SCRIPT_DIR = Path(__file__).parent
ENV_FILE = SCRIPT_DIR / ".env"
FETCH_SCRIPT = SCRIPT_DIR / "fetch_emails.mjs"
DRAFT_SCRIPT = SCRIPT_DIR / "create_draft.mjs"
VOICE_PROFILE = Path.home() / ".system_files" / "voice-dna-email.md"

load_dotenv(ENV_FILE)

TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
TELEGRAM_CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]
DEEPSEEK_API_KEY = os.environ["DEEPSEEK_API_KEY"]

CLASSIFIER_PROMPT = (
    "Decide for each email whether Morgan (the recipient) should personally reply.\n\n"
    "Reply 'yes' ONLY when a specific human contact is personally writing to Morgan "
    "and clearly expects a direct personal response from him. The email should read like "
    "it was hand-written and sent to him individually (not as part of a list).\n\n"
    "Reply 'no' for ALL of the following, even if they contain a call to action, "
    "an interesting opportunity, or a deadline:\n"
    "- Newsletters, Substack posts, blog digests (even ones soliciting pitches or submissions)\n"
    "- Marketing, promotional, sales, or fundraising emails\n"
    "- Automated notifications, alerts, confirmations, and digests\n"
    "- Anything from no-reply, noreply, donotreply, jobalerts, notifications, marketing, or similar senders\n"
    "- Calendar invites without explicit personal questions directed at Morgan\n"
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


def classify(client, emails):
    listing = "\n\n".join(
        f"[{i}] From: {e['from']}\nSubject: {e['subject']}\nBody: {e['body'][:1500]}"
        for i, e in enumerate(emails)
    )
    resp = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "system", "content": CLASSIFIER_PROMPT},
            {"role": "user", "content": listing},
        ],
        response_format={"type": "json_object"},
        max_tokens=2000,
    )
    parsed = json.loads(resp.choices[0].message.content)
    return {d["index"]: d for d in parsed.get("decisions", [])}


def draft_body(client, voice, email):
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


def submit_draft(payload):
    result = subprocess.run(
        ["node", str(DRAFT_SCRIPT)],
        input=json.dumps(payload),
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, f"create_draft.mjs failed: {result.stderr}"
    return json.loads(result.stdout)["draftId"]


def create_draft(email, body_text):
    payload = {
        "to": reply_to_address(email["from"]),
        "subject": reply_subject(email["subject"]),
        "body": body_text,
        "threadId": email["threadId"],
        "inReplyTo": email.get("messageIdHeader", ""),
        "references": reply_references(email),
    }
    return submit_draft(payload)


def send_telegram(message):
    resp = requests.post(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        json={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"},
        timeout=10,
    )
    resp.raise_for_status()


def render_telegram(drafted):
    lines = [f"📝 <b>{len(drafted)} draft(s) created</b>", ""]
    for d in drafted:
        lines.append(f"• <b>{html.escape(d['from'])}</b>: {html.escape(d['subject'])}")
        if d["reason"]:
            lines.append(f"  <i>{html.escape(d['reason'])}</i>")
        if d.get("run_url"):
            lines.append(f"  <a href=\"{html.escape(d['run_url'])}\">trace</a>")
    return "\n".join(lines)


def render_rejected_telegram(rejected):
    lines = [f"🚫 <b>{len(rejected)} draft(s) rejected (em-dash)</b>", ""]
    for r in rejected:
        lines.append(f"• <b>{html.escape(r['from'])}</b>: {html.escape(r['subject'])}")
        if r.get("run_url"):
            lines.append(f"  <a href=\"{html.escape(r['run_url'])}\">trace</a>")
    return "\n".join(lines)


def process_emails(emails):
    assert isinstance(emails, list), "emails must be a list"
    if not emails:
        return []
    assert VOICE_PROFILE.exists(), f"Voice profile not found at {VOICE_PROFILE}"
    voice = VOICE_PROFILE.read_text()

    client = agentic_drafter.make_client(DEEPSEEK_API_KEY)
    decisions = classify(client, emails)

    drafted = []
    rejected = []
    for i, email in enumerate(emails):
        d = decisions.get(i)
        if not d or not d.get("needs_reply"):
            continue
        body, run_url = draft_body(client, voice, email)
        if agentic_drafter.contains_em_dash(body):
            rejected.append({
                "from": email["from"],
                "subject": email["subject"],
                "run_url": run_url,
            })
            continue
        draft_id = create_draft(email, body)
        drafted.append({
            "from": email["from"],
            "subject": email["subject"],
            "reason": d.get("reason", ""),
            "run_url": run_url,
            "draft_id": draft_id,
        })

    if drafted:
        send_telegram(render_telegram(drafted))
    if rejected:
        send_telegram(render_rejected_telegram(rejected))
    return drafted


def main():
    emails = fetch_emails()
    process_emails(emails)


if __name__ == "__main__":
    main()
