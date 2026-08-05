"""Single source of truth for per-account realtime processing.

Both the always-on daemon (daemon_loop) and the push-triggered entry
(process_push) call process_account, so the fetch + route + cursor-advance
logic lives in exactly one place. Each account carries its own state cursor,
identity, notification target, and token custody; log and notify_err are
injected so the two entry points keep their own logging and notification
behavior.
"""

import traceback

from backend.drafting import draft_replies
from backend.drafting import manual_draft
from backend.drafting import schedule_from_sent
from backend.integrations.gmail_gcal import mailbox


def process_account(account, *, log, notify_err):
    assert account.identity.account_id == account.id, (
        f"account {account.id!r} carries identity for {account.identity.account_id!r}"
    )
    s = account.state.load()
    last = s.get("lastHistoryId")
    if not last:
        log("No lastHistoryId in state; run `python -m backend.onboarding.watch_renew` first.")
        return
    payload = mailbox.fetch_since_history(account, last)
    emails = payload.get("emails", [])
    sent = payload.get("sent", [])
    new_history_id = payload.get("historyId")
    stale = payload.get("stale", False)
    log(f"fetched {len(emails)} email(s), {len(sent)} sent since historyId={last}")
    if stale:
        log(f"history.list 404 (startHistoryId={last} too old); bootstrapping to {new_history_id}")

    bot_requests = [e for e in emails if manual_draft.is_bot_request(e, account)]
    auto_emails = [e for e in emails if not manual_draft.is_bot_request(e, account)]

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
    # Writing to someone's calendar without being asked is a surprise, so it is
    # opt-in per account (the owner's seed turns it on). Off means the sent mail
    # is simply not inspected.
    if sent and account.auto_schedule:
        try:
            schedule_from_sent.run(account, sent)
        except Exception as err:
            log(f"schedule_from_sent failed: {err}\n{traceback.format_exc()}")
            notify_err("schedule_from_sent failed", err)
    if new_history_id:
        account.state.update(lastHistoryId=str(new_history_id))
