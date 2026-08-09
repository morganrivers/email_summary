#!/usr/bin/env python3
"""Turn sent emails into calendar events.

Fed by the realtime Gmail history path (pipeline.process_account) for accounts
that opted in (auto_schedule): every message such a user sends is routed here.
An email becomes a calendar event only when it commits to a concrete date AND
clock time. Events are created on the primary calendar with no attendees (no
invites are sent), in the account's own timezone. A single Telegram notice
lists what was scheduled.

Dedup is handled upstream by the history cursor (lastHistoryId), which delivers
each sent message exactly once — same guarantee the drafting path relies on.
"""

import datetime
import html
import sys

from backend import secrets, site
from backend.integrations import llm_client
from backend.integrations.gmail_gcal import calendar_api, oauth_app
from backend.integrations.telegram import notify_error, send_telegram

secrets.load()

# Per account: an event written at "3pm" means 3pm where the user is, and a
# module constant put every user in the operator's timezone.
DEFAULT_DURATION = datetime.timedelta(hours=1)

EXTRACT_PROMPT = (
    "You extract calendar events from an email the account owner has SENT.\n\n"
    "Extract an event ONLY when the email commits to a specific calendar item "
    "with a CONCRETE date AND clock time (e.g. 'Tuesday July 21 at 3pm', "
    "'tomorrow 10:00', 'the 20th at 14:30'). Resolve relative dates using the "
    "provided 'Today' date.\n\n"
    "Do NOT extract when:\n"
    "- the time is vague ('next week', 'sometime', 'soon', 'let me know when works')\n"
    "- only a date with no clock time is given\n"
    "- it merely references a past or already-scheduled event\n"
    "- it is a deadline or reminder rather than a meeting/appointment\n"
    "When unsure, extract nothing.\n\n"
    "Output JSON: {\"events\": [{\"summary\": str, "
    "\"start\": \"YYYY-MM-DDTHH:MM:SS\", \"end\": \"YYYY-MM-DDTHH:MM:SS\", "
    "\"location\": str, \"description\": str}]}.\n"
    "Use local wall-clock time with NO timezone offset. Omit 'end' if no end "
    "time is stated. 'location' and 'description' may be empty strings. "
    "Keep 'summary' short. If there are no concrete events, output "
    "{\"events\": []}."
)


def _log(msg):
    sys.stderr.write(f"[schedule_from_sent] {msg}\n")


def extract_events(client, email, identity, timezone="UTC"):
    today = datetime.date.today()
    user_content = (
        f"Today: {today.isoformat()} ({today.strftime('%A')}). "
        f"Timezone: {timezone}.\n\n"
        f"Sent email:\n"
        f"To: {email.get('to', '')}\n"
        f"Subject: {email.get('subject', '')}\n"
        f"Date: {email.get('date', '')}\n\n"
        f"{email.get('body', '')}"
    )
    parsed = llm_client.complete_json(
        client,
        messages=[
            {"role": "system", "content": EXTRACT_PROMPT},
            {"role": "user", "content": user_content},
        ],
        identity=identity,
    )
    return parsed.get("events", [])


def _normalize(event):
    """Validate + fill defaults. Returns a dict or None if not schedulable.

    This is the model boundary, so it truncates where calendar_api refuses. The
    limits are that module's, imported rather than restated: a model that quotes
    half an email into a description is a long description, not an incident, and
    an event nobody can read the whole of is still better than an alert per
    chatty draft. calendar_api keeps the refusal for the caller that has no such
    excuse."""
    summary = (event.get("summary") or "").strip()[:calendar_api.MAX_SUMMARY]
    start = (event.get("start") or "").strip()
    if not summary or not start:
        return None
    try:
        start_dt = datetime.datetime.fromisoformat(start)
    except ValueError:
        _log(f"unparseable start {start!r}; skipping")
        return None
    end = (event.get("end") or "").strip()
    if end:
        try:
            if datetime.datetime.fromisoformat(end) <= start_dt:
                _log(f"end {end!r} is not after start {start!r}; using default duration")
                end = ""
        except (ValueError, TypeError):
            # TypeError is the model offering one of the pair with a timezone
            # offset and the other without, which compares as naive vs aware.
            end = ""
    if not end:
        end = (start_dt + DEFAULT_DURATION).isoformat(timespec="seconds")
    return {
        "summary": summary,
        "start": start,
        "end": end,
        "location": (event.get("location") or "").strip()[:calendar_api.MAX_LOCATION],
        "description": (event.get("description") or "").strip()[:calendar_api.MAX_DESCRIPTION],
    }


def create_event(account, event):
    return calendar_api.create_event(
        account,
        summary=event["summary"],
        start_iso=event["start"],
        end_iso=event["end"],
        time_zone=account.timezone,
        location=event["location"],
        description=event["description"],
    )


def render_telegram(created):
    lines = [f"📅 <b>{len(created)} event(s) scheduled from your sent mail</b>", ""]
    for c in created:
        title = html.escape(c["summary"])
        when = html.escape(c["start"])
        link = c.get("htmlLink")
        head = (
            f'<a href="{html.escape(link)}"><b>{title}</b></a>'
            if link else f"<b>{title}</b>"
        )
        lines.append(f"• {head}\n  <i>{when}</i>")
    return "\n".join(lines)


def render_not_private(err):
    if isinstance(err, calendar_api.CalendarSharingUnknown):
        # Which remedy is the right one depends on how this deployment asks the
        # question. With the ACL scope the usual cause is a token minted before
        # it, which a new grant fixes; without it the check is an unauthenticated
        # fetch that no permission of the user's affects, and telling them to
        # sign in would send them somewhere that cannot help.
        if oauth_app.acl_scope_registered():
            remedy = (
                "Letterlock could not check who can read that calendar, so it "
                f"wrote nothing. Sign in again to refresh its permissions: "
                f"{site.app_url('/auth/login')}"
            )
        else:
            remedy = (
                "Letterlock could not check who can read that calendar, so it "
                "wrote nothing. Nothing on your side is broken and nothing is "
                "lost: the next run tries again."
            )
    else:
        remedy = (
            "Nothing was written, because an event built from your mail would be "
            "readable by everyone that calendar is shared with. Make it private "
            "in Google Calendar, or switch off scheduling from sent mail."
        )
    return (
        "📅 <b>Scheduling stopped: your calendar is not known to be private</b>\n\n"
        f"{html.escape(str(err))}\n\n{remedy}"
    )


def _schedule_all(account, sent_emails, client, created):
    """Every event this batch produces, appended to `created` as it is written.

    Written into a list the caller owns rather than returned, so a refusal
    partway through still reports what was already scheduled."""
    for email in sent_emails:
        try:
            events = extract_events(client, email, account.identity,
                                    timezone=account.timezone)
        except Exception as err:
            _log(f"extract failed for {email.get('id')}: {err}")
            notify_error(
                f"schedule_from_sent: event extraction failed for sent email {email.get('id')}",
                err, account.telegram)
            continue
        for raw in events:
            event = _normalize(raw)
            if not event:
                continue
            try:
                res = create_event(account, event)
            except calendar_api.CalendarNotPrivate:
                raise
            except Exception as err:
                _log(f"create failed for {event['summary']!r}: {err}")
                notify_error(
                    f"schedule_from_sent: calendar event creation failed for "
                    f"{event['summary']!r}", err, account.telegram)
                continue
            created.append({**event, "htmlLink": res.get("htmlLink")})


def run(account, sent_emails):
    assert isinstance(sent_emails, list), "sent_emails must be a list"
    if not sent_emails:
        return []
    client = llm_client.make_client(account)
    created = []
    try:
        _schedule_all(account, sent_emails, client, created)
    except calendar_api.CalendarNotPrivate as err:
        # A shared calendar is a property of the account, not of one event, so
        # every remaining event in the batch would be refused for the same
        # reason. Stopping here makes it one message rather than one per event.
        _log(f"calendar is not private: {err}")
        send_telegram(render_not_private(err), account.telegram)
    if created:
        send_telegram(render_telegram(created), account.telegram)
    return created
