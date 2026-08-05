#!/usr/bin/env python3
"""Smoke test for agentic_drafter — feeds a contrived 'are you free?' email
so we can see whether DeepSeek calls the calendar tool."""

import sys
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path(__file__).parent / ".env")

from backend.drafting import agentic_drafter
from backend.accounts import account
from backend.drafting import draft_replies

acct = account.owner_account()
voice = draft_replies.voice_profile_for(acct)

DRAFTER_INSTRUCTION = (
    "\n\nWrite a reply email that follows the voice profile above. "
    "Output the email body only, including the greeting and sign-off as the profile dictates. "
    "No subject line. No commentary. No markdown fences. Plain text only."
)

fake_email = {
    "from": "Alice Example <alice@example.com>",
    "date": "Mon, Jun 30, 2026 at 10:00 AM",
    "subject": "Coffee this Thursday or Friday?",
    "body": "Hi Morgan, I'd love to grab coffee. Could you do Thursday afternoon (after 2pm) or Friday morning this week? Either works for me. Best, Alice",
}

sys_prompt = voice + DRAFTER_INSTRUCTION
user_prompt = (
    f"Original email:\n"
    f"From: {fake_email['from']}\n"
    f"Date: {fake_email['date']}\n"
    f"Subject: {fake_email['subject']}\n\n"
    f"{fake_email['body']}\n\n"
    "Draft a reply."
)

client = agentic_drafter.make_client(acct)
print("--- Calling agentic_drafter.draft ---", flush=True)
body, url = agentic_drafter.draft(client, sys_prompt, user_prompt, account=acct)
print("\n=== DRAFT BODY ===")
print(body)
print("\n=== RUN URL ===")
print(url)
print(f"\n=== em-dash present: {agentic_drafter.contains_em_dash(body)} ===")
