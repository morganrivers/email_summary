"""Re-run manual_draft on the failed bot email to verify thread fallback."""
from dotenv import load_dotenv
load_dotenv(".env")
import json

from backend.accounts import account
from backend.drafting import manual_draft
from backend.integrations.gmail_gcal import mailbox

acct = account.owner_account()
email_id = "19f198a5b20434e0"
data = mailbox.fetch_since_history(acct, "2854017")
target = next(e for e in data["emails"] if e["id"] == email_id)
print("Target email:")
print(f"  from={target['from']}")
print(f"  to={target['to']}")
print(f"  subject={target['subject']}")
print(f"  threadId={target['threadId']}")
print(f"  body={target['body']!r}")
print()

print("parse_forward result:", manual_draft.parse_forward(target.get("body", "")))
print()

parsed = manual_draft.parse_from_thread(acct, target)
print("parse_from_thread result:")
print(json.dumps(parsed, indent=2)[:1500])
