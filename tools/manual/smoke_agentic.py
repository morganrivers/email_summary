#!/usr/bin/env python3
"""Smoke test for agentic_drafter — feeds a contrived 'are you free?' email
so we can see whether DeepSeek calls the calendar tool."""

from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

from backend.accounts import account
from backend.drafting import agentic_drafter, draft_replies
from backend.integrations import llm_client

acct = account.owner_account()
instructions = draft_replies.drafting_instructions(acct)

fake_email = {
    "from": "Alice Example <alice@example.com>",
    "date": "Mon, Jun 30, 2026 at 10:00 AM",
    "subject": "Coffee this Thursday or Friday?",
    "body": f"Hi {acct.display_name}, I'd love to grab coffee. Could you do Thursday "
            f"afternoon (after 2pm) or Friday morning this week? Either works for me. "
            f"Best, Alice",
}

sys_prompt = instructions + draft_replies.DRAFTER_INSTRUCTION
fence = agentic_drafter.new_fence()
user_prompt = (
    "Original email:\n"
    + fence.wrap(
        f"From: {fake_email['from']}\n"
        f"Date: {fake_email['date']}\n"
        f"Subject: {fake_email['subject']}\n\n"
        f"{fake_email['body']}"
    )
    + "\n\nDraft a reply."
)

client = llm_client.make_client(acct)
print("--- Calling agentic_drafter.draft ---", flush=True)
body = agentic_drafter.draft(client, sys_prompt, user_prompt, account=acct,
                             fence=fence)
print("\n=== DRAFT BODY ===")
print(body)
print(f"\n=== em-dash present: {agentic_drafter.contains_em_dash(body)} ===")
