#!/usr/bin/env python3
"""Turn sent emails into calendar events.

Fed by the realtime Gmail history path (pipeline.process_account): every
message the user sends is routed here. An email becomes a calendar event only
when it commits to a concrete date AND clock time. Events are created on the
primary calendar with no attendees (no invites are sent). A single Telegram
notice lists what was scheduled.

Dedup is handled upstream by the history cursor (lastHistoryId), which delivers
each sent message exactly once — same guarantee the drafting path relies on.
"""

import os
import json
import html
import datetime
import subprocess
import sys

from dotenv import load_dotenv

from backend import paths
from backend.integrations import llm_client
from backend.integrations.gmail_gcal.node_runner import node_env
from backend.integrations.telegram import send_telegram, notify_error

CREATE_EVENT_SCRIPT = paths.node_script("create_event.mjs")

load_dotenv(paths.ENV_FILE)

DEEPSEEK_API_KEY = os.environ["DEEPSEEK_API_KEY"]

TIMEZONE = "Europe/Berlin"
DEFAULT_DURATION = datetime.timedelta(hours=1)

EXTRACT_PROMPT = (
    "You extract calendar events from an email the user (Morgan) has SENT.\n\n"
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


def extract_events(client, email, identity=None):
    today = datetime.date.today()
    user_content = (
        f"Today: {today.isoformat()} ({today.strftime('%A')}). "
        f"Timezone: {TIMEZONE}.\n\n"
        f"Sent email:\n"
        f"To: {email.get('to', '')}\n"
        f"Subject: {email.get('subject', '')}\n"
        f"Date: {email.get('date', '')}\n\n"
        f"{email.get('body', '')}"
    )
    resp = llm_client.complete(
        client,
        messages=[
            {"role": "system", "content": EXTRACT_PROMPT},
            {"role": "user", "content": user_content},
        ],
        max_tokens=2000,
        response_format={"type": "json_object"},
        identity=identity,
    )
    parsed = json.loads(resp.choices[0].message.content)
    return parsed.get("events", [])


def _normalize(event):
    """Validate + fill defaults. Returns a dict or None if not schedulable."""
    summary = (event.get("summary") or "").strip()
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
            datetime.datetime.fromisoformat(end)
        except ValueError:
            end = ""
    if not end:
        end = (start_dt + DEFAULT_DURATION).isoformat(timespec="seconds")
    return {
        "summary": summary,
        "start": start,
        "end": end,
        "location": (event.get("location") or "").strip(),
        "description": (event.get("description") or "").strip(),
    }


def create_event(account, event):
    payload = {
        "summary": event["summary"],
        "startIso": event["start"],
        "endIso": event["end"],
        "timeZone": TIMEZONE,
        "location": event["location"],
        "description": event["description"],
    }
    result = subprocess.run(
        ["node", str(CREATE_EVENT_SCRIPT)],
        input=json.dumps(payload),
        capture_output=True, text=True, timeout=60,
        env=node_env(account.creds_dir),
    )
    assert result.returncode == 0, f"create_event.mjs failed: {result.stderr}"
    return json.loads(result.stdout)


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


def run(account, sent_emails):
    assert isinstance(sent_emails, list), "sent_emails must be a list"
    if not sent_emails:
        return []
    client = llm_client.make_client(DEEPSEEK_API_KEY)
    created = []
    for email in sent_emails:
        try:
            events = extract_events(client, email, account.identity)
        except Exception as err:
            _log(f"extract failed for {email.get('id')}: {err}")
            notify_error(f"schedule_from_sent: event extraction failed for sent email {email.get('id')}", err, account.telegram)
            continue
        for raw in events:
            event = _normalize(raw)
            if not event:
                continue
            try:
                res = create_event(account, event)
            except Exception as err:
                _log(f"create failed for {event['summary']!r}: {err}")
                notify_error(f"schedule_from_sent: calendar event creation failed for {event['summary']!r}", err, account.telegram)
                continue
            created.append({**event, "htmlLink": res.get("htmlLink")})
    if created:
        send_telegram(render_telegram(created), account.telegram)
    return created
