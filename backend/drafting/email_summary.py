#!/usr/bin/env python3
"""Daily per-account summary: fetch today's mail + calendar, summarise, send.

Runs once a day from email-summary.timer and sweeps every active account. It
used to be single-tenant in a way that could not be noticed from the outside:
the Node fetch inherited the process environment (so it always read whichever
mailbox GMAIL_MCP_DIR pointed at) and the Telegram send carried no target (so it
always went to the operator's chat). Every account past the first got no summary
at all, and the operator got theirs.

Both boundaries are now per account, the same seams the drafting path uses:
node_env(account.creds_dir) for the mailbox, account.telegram for the delivery.
"""

import json
import subprocess
import datetime
import sys
import traceback

from backend import paths
from backend import secrets
from backend.accounts import account as account_mod
from backend.integrations import llm_client
from backend.integrations.gmail_gcal.node_runner import node_env
from backend.drafting.agentic_drafter import untrusted
from backend.drafting.draft_replies import gmail_thread_link
from backend.integrations.telegram import send_telegram, notify_error

FETCH_SCRIPT = paths.node_script("fetch_emails.mjs")
PROMPT_FILE = paths.config_file("prompt_for_email")

secrets.load()

DEFAULT_PROMPT = (
    "You write a short daily briefing from the account owner's unread email and "
    "calendar. Lead with anything time-critical. Group the rest by theme, one "
    "line each, and drop anything not worth their attention. Keep it under 200 "
    "words. Plain text with simple HTML tags only (<b>, <i>, <a>)."
)


def log(msg):
    sys.stderr.write(f"email-summary {msg}\n")
    sys.stderr.flush()


# ── Gmail (via Node.js helper) ────────────────────────────────────────────────

def fetch_todays_emails_and_events(account) -> dict:
    result = subprocess.run(
        ["node", str(FETCH_SCRIPT)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
        env=node_env(account.creds_dir),
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"fetch_emails.mjs exited {result.returncode} for {account.id}: "
            f"{result.stderr.decode(errors='replace').strip()}"
        )
    return json.loads(result.stdout)


# ── DeepSeek ─────────────────────────────────────────────────────────────────

def _prompt_text():
    """The operator's summary prompt when the box has one, else a built-in.
    A missing prompt file used to be an unhandled crash on the timer."""
    if PROMPT_FILE.exists():
        return PROMPT_FILE.read_text().strip()
    return DEFAULT_PROMPT


def _format_events(events: list[dict]) -> str:
    return "\n\n".join(
        f"Event: {e['summary']}\nStart: {e['start']}\nEnd: {e['end']}" +
        (f"\nLocation: {e['location']}" if e['location'] else "") +
        (f"\nDescription: {e['description']}" if e['description'] else "")
        for e in events
    )


def summarise(account, emails, events, community_events) -> str:
    prompt = _prompt_text()
    client = llm_client.make_client(account)

    email_text = "\n\n".join(
        untrusted(
            f"From: {e['from']}\nSubject: {e['subject']}\n"
            f"Link: {gmail_thread_link(e['threadId'])}\n"
            f"{e['body']}"
        )
        for e in emails
    )

    today_iso = datetime.date.today().isoformat()
    today_pretty = datetime.date.today().strftime("%A %d %b %Y")
    user_content = (
        f"Today's date: {today_iso} ({today_pretty}).\n\n"
        f"Here are today's emails:\n\n{email_text}"
    )
    if events:
        user_content += (
            "\n\nHere are your calendar events for the next 24 hours "
            "(may span today into tomorrow morning):\n\n"
            f"{_format_events(events)}"
        )
    if community_events:
        user_content += (
            "\n\nHere are community calendar events for the next 24 hours. \n\n"
            f"{_format_events(community_events)}"
        )

    resp = llm_client.complete(
        client,
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": user_content},
        ],
        max_tokens=16000,
        identity=account.identity,
    )
    msg = resp.choices[0].message
    content = (msg.content or "").strip()
    reasoning = getattr(msg, "reasoning_content", None) or ""
    log(
        f"{account.id}: model returned content_len={len(content)} "
        f"reasoning_len={len(reasoning)} "
        f"finish_reason={resp.choices[0].finish_reason}"
    )
    return content


# ── Per account ──────────────────────────────────────────────────────────────

def summarise_account(account):
    """Build and deliver one account's summary. Returns whether one was sent."""
    if account.telegram is None:
        log(f"{account.id}: no linked Telegram chat; skipping summary")
        return False

    data = fetch_todays_emails_and_events(account)
    emails = data.get("emails", [])
    events = data.get("events", [])
    community_events = data.get("community_events", [])

    if not emails and not events and not community_events:
        send_telegram(
            "No new emails or calendar events for the next 24 hours.",
            account.telegram,
        )
        log(f"{account.id}: nothing to summarise")
        return True

    log(f"{account.id}: {len(emails)} email(s), {len(events)} event(s), "
        f"{len(community_events)} community event(s)")
    summary = summarise(account, emails, events, community_events)

    if not summary:
        email_line = (
            "Nothing for today on email." if not emails
            else "Nothing worth surfacing for today on email."
        )
        event_line = (
            "Nothing for today on calendar." if not events
            else "See calendar for today's events."
        )
        summary = f"{email_line}\n{event_line}"
        log(f"{account.id}: empty model output; using fallback summary")

    today_str = datetime.date.today().strftime("%a %d %b")
    send_telegram(f"📬 <b>Daily summary for {today_str}</b>\n\n{summary}",
                  account.telegram)
    return True


def main():
    accounts = account_mod.load_accounts()
    log(f"summarising {len(accounts)} active account(s)")
    sent = failures = 0
    for acct in accounts:
        try:
            if summarise_account(acct):
                sent += 1
        except Exception as err:
            failures += 1
            log(f"{acct.id}: summary failed: {err}\n{traceback.format_exc()}")
            # The account's own chat first, the operator's as the backstop, so
            # one user's broken mailbox is visible without silencing the rest.
            notify_error(f"daily summary failed for {acct.id}", err, acct.telegram)
    log(f"sent={sent} failed={failures}")
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
