#!/usr/bin/env python3
"""Daily per-account summary: fetch today's mail + calendar, summarise, send.

Runs once a day from email-summary.timer and sweeps every active account. It
used to be single-tenant in a way that could not be noticed from the outside:
the fetch inherited the process environment (so it always read whichever mailbox
an environment variable pointed at) and the Telegram send carried no target (so
it always went to the operator's chat). Every account past the first got no
summary at all, and the operator got theirs.

Both boundaries are now per account, the same seams the drafting path uses: the
account itself for the mailbox, account.telegram for the delivery.
"""

import datetime
import sys
import traceback

from backend import paths, secrets
from backend.accounts import account as account_mod
from backend.drafting.agentic_drafter import new_fence
from backend.drafting.draft_replies import gmail_thread_link
from backend.integrations import llm_client
from backend.integrations.gmail_gcal import mailbox
from backend.integrations.telegram import notify_error, sanitize_model_html, send_telegram

PROMPT_FILE = paths.config_file("prompt_for_email")

secrets.load()

DEFAULT_PROMPT = (
    "You write a short daily briefing from the account owner's unread email and "
    "calendar. Lead with anything time-critical. Group the rest by theme, one "
    "line each, and drop anything not worth their attention. Keep it under 200 "
    "words. Plain text with simple HTML tags only (<b>, <i>). Write any link "
    "as a bare URL: anchor tags are removed before the message is sent."
)


def log(msg):
    sys.stderr.write(f"email-summary {msg}\n")
    sys.stderr.flush()


# ── Gmail ─────────────────────────────────────────────────────────────────────

def fetch_todays_emails_and_events(account) -> dict:
    return mailbox.fetch_daily(account)


# ── Inference Provider (Deepseek or Near AI) ─────────────────────────────────

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

    # The rule goes in the system message beside the operator's own prompt. The
    # mail was fenced here from the start but the rule never was, because the
    # system prompt is a file an operator edits: stating it here is what makes
    # the fence mean something without asking that file to carry it.
    fence = new_fence()
    email_text = "\n\n".join(
        fence.wrap(
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
            {"role": "system", "content": f"{prompt}\n\n{fence.rule}"},
            {"role": "user", "content": user_content},
        ],
        max_tokens=16000,
        identity=account.identity,
        protect=(fence.nonce,),
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

    # The summary is written from mail an outside sender composed, and it is
    # delivered with parse_mode=HTML, so the model's own output is markup: an
    # anchor here is a phishing link inside the user's daily briefing and one
    # unclosed tag is a 400 that call() swallows. Neither is the fence's job --
    # it decides what the model is told, not what it may write back.
    today_str = datetime.date.today().strftime("%a %d %b")
    delivered = send_telegram(
        f"📬 <b>Daily summary for {today_str}</b>\n\n"
        + sanitize_model_html(summary),
        account.telegram,
    )
    if not delivered:
        log(f"{account.id}: summary was built but not delivered")
    return delivered


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
