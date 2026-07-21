"""Single source of truth for per-account realtime processing.

Both the always-on daemon (daemon_loop) and the push-triggered entry
(process_push) call process_account, so the fetch + route + cursor-advance
logic lives in exactly one place. Each account carries its own state cursor,
identity, notification target, and Gmail creds; log and notify_err are injected
so the two entry points keep their own logging and notification behavior.
"""

import json
import subprocess
import traceback
from pathlib import Path

import draft_replies
import manual_draft
import schedule_from_sent
from node_runner import node_env

SCRIPT_DIR = Path(__file__).parent
FETCH_SCRIPT = SCRIPT_DIR / "fetch_emails.mjs"


def fetch_since(account, history_id):
    result = subprocess.run(
        ["node", str(FETCH_SCRIPT), "--since-history", str(history_id)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
        env=node_env(account.creds_dir),
    )
    assert result.returncode == 0, (
        f"fetch_emails.mjs exited {result.returncode}: {result.stderr.decode()}"
    )
    return json.loads(result.stdout)


def process_account(account, *, log, notify_err):
    assert account.identity.account_id == account.id, (
        f"account {account.id!r} carries identity for {account.identity.account_id!r}"
    )
    s = account.state.load()
    last = s.get("lastHistoryId")
    if not last:
        log("No lastHistoryId in state; run watch_register.mjs first.")
        return
    payload = fetch_since(account, last)
    emails = payload.get("emails", [])
    sent = payload.get("sent", [])
    new_history_id = payload.get("historyId")
    stale = payload.get("stale", False)
    log(f"fetched {len(emails)} email(s), {len(sent)} sent since historyId={last}")
    if stale:
        log(f"history.list 404 (startHistoryId={last} too old); bootstrapping to {new_history_id}")

    bot_requests = [e for e in emails if manual_draft.is_bot_request(e)]
    auto_emails = [e for e in emails if not manual_draft.is_bot_request(e)]

    for req in bot_requests:
        try:
            manual_draft.process_draft_request(account, req)
        except Exception as err:
            log(f"manual_draft failed for {req.get('id')}: {err}\n{traceback.format_exc()}")
            notify_err(f"manual_draft failed for email {req.get('id')}", err)
    if auto_emails:
        try:
            draft_replies.process_emails(account, auto_emails)
        except Exception as err:
            log(f"process_emails failed: {err}\n{traceback.format_exc()}")
            notify_err("process_emails failed", err)
    if sent:
        try:
            schedule_from_sent.run(account, sent)
        except Exception as err:
            log(f"schedule_from_sent failed: {err}\n{traceback.format_exc()}")
            notify_err("schedule_from_sent failed", err)
    if new_history_id:
        account.state.update(lastHistoryId=str(new_history_id))
