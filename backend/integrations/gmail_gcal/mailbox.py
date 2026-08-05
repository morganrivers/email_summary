"""What the daemon and the daily summary fetch. The Python replacement for
fetch_emails.mjs.

Two entry points, matching the two modes that script had: a history-cursor read
for realtime processing, and a "last 24 hours" sweep for the summary. Both are
per account.
"""

from __future__ import annotations

import datetime
import os
import sys

from googleapiclient.errors import HttpError

from backend.integrations.gmail_gcal import calendar_api, gmail_api

MAX_EMAILS = 40

# A community calendar the operator subscribes to, read alongside the account's
# own for the daily summary. Absent or unreadable, the summary is simply built
# without it: it is somebody else's calendar and never important enough to fail
# a fetch over.
COMMUNITY_CALENDAR_ID = os.environ.get(
    "LETTERLOCK_COMMUNITY_CALENDAR",
    "isdrlmn4d5jmagpmta3igf4g0l0pjn9i@import.calendar.google.com",
)


def log(msg):
    sys.stderr.write(f"mailbox {msg}\n")
    sys.stderr.flush()


def _fetch_ids(account, ids):
    out = []
    for message_id in list(ids)[:MAX_EMAILS]:
        try:
            out.append(gmail_api.fetch_message(account, message_id))
        except HttpError as err:
            log(f"fetch_message failed for {message_id}: {err}")
    return out


def fetch_since_history(account, since_history_id):
    """Everything added to the mailbox since a cursor.

    `stale` means Gmail no longer has that far back; the caller bootstraps to
    the returned historyId instead of processing a gap it cannot see."""
    result = gmail_api.history_list(account, since_history_id)
    if result["stale"]:
        return {"emails": [], "sent": [],
                "historyId": gmail_api.current_history_id(account), "stale": True}
    emails = gmail_api.annotate_thread_participation(
        account, _fetch_ids(account, result["addedMessageIds"]))
    sent = _fetch_ids(account, result["sentMessageIds"])
    return {"emails": emails, "sent": sent,
            "historyId": result["historyId"], "stale": False}


def fetch_unread_24h(account):
    after = int((datetime.datetime.now(datetime.timezone.utc)
                 - datetime.timedelta(days=1)).timestamp())
    service = gmail_api.gmail(account)
    listing = service.users().messages().list(
        userId="me", q=f"after:{after} in:inbox is:unread", maxResults=MAX_EMAILS,
    ).execute()
    emails = [gmail_api.fetch_message(account, m["id"])
              for m in listing.get("messages", [])]
    return gmail_api.annotate_thread_participation(account, emails)


def fetch_daily(account):
    """The daily summary's whole input: unread mail, the next 24 hours of the
    account's calendar, and the community calendar when it is readable."""
    now = datetime.datetime.now(datetime.timezone.utc)
    start_iso = now.isoformat().replace("+00:00", "Z")
    end_iso = (now + datetime.timedelta(days=1)).isoformat().replace("+00:00", "Z")
    emails = fetch_unread_24h(account)
    events = calendar_api.list_events(account, start_iso, end_iso, 50)
    community = []
    try:
        community = calendar_api.list_events(
            account, start_iso, end_iso, 50, COMMUNITY_CALENDAR_ID)
    except HttpError as err:
        log(f"community calendar fetch failed: {err}")
    return {"emails": emails, "events": events, "community_events": community}
