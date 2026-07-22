#!/usr/bin/env python3
"""Manual end-to-end test of the draft pipeline."""

import sys
from backend.accounts import account
from backend.drafting import draft_replies

acct = account.default_account()

print("=== Fetching emails ===", flush=True)
emails = draft_replies.fetch_emails()
print(f"Got {len(emails)} email(s)", flush=True)
for i, e in enumerate(emails):
    sender = e.get("from", "?")[:70]
    subj = e.get("subject", "?")[:70]
    print(f"  [{i}] {sender} | {subj}", flush=True)

if not emails:
    print("No emails to draft. Send yourself one and re-run.", flush=True)
    sys.exit(0)

print("\n=== Running process_emails (classify + draft + telegram) ===", flush=True)
drafted = draft_replies.process_emails(acct, emails)
print(f"\nDrafted {len(drafted)} reply/replies:", flush=True)
for d in drafted:
    print(f"  - to: {d['from']}", flush=True)
    print(f"    subject: {d['subject']}", flush=True)
    print(f"    reason: {d['reason']}", flush=True)
    print(f"    draft_id: {d['draft_id']}", flush=True)
