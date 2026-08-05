"""Google Calendar, in process. The Python replacement for the calendar half of
gmail_lib.mjs.

Same credentials as Gmail (one consent covers both), so the service comes from
gmail_api rather than being built a second way here.
"""

from __future__ import annotations

from backend.integrations.gmail_gcal.gmail_api import calendar

MAX_DESCRIPTION = 500
DEFAULT_TIMEZONE = "Europe/Berlin"


def list_events(account, start_iso, end_iso, max_results=50, calendar_id="primary"):
    assert start_iso and end_iso, "list_events needs an ISO 8601 range"
    res = calendar(account).events().list(
        calendarId=calendar_id, timeMin=start_iso, timeMax=end_iso,
        singleEvents=True, orderBy="startTime", maxResults=max_results,
    ).execute()
    events = []
    for e in res.get("items", []):
        start = e.get("start") or {}
        end = e.get("end") or {}
        events.append({
            "id": e.get("id"),
            "summary": e.get("summary") or "(no title)",
            "start": start.get("dateTime") or start.get("date") or "",
            "end": end.get("dateTime") or end.get("date") or "",
            "location": e.get("location") or "",
            "description": (e.get("description") or "")[:MAX_DESCRIPTION],
            "attendees": [a.get("email") for a in e.get("attendees", [])],
        })
    return events


def create_event(account, *, summary, start_iso, end_iso,
                 time_zone=DEFAULT_TIMEZONE, location="", description="",
                 calendar_id="primary"):
    assert summary and start_iso and end_iso, (
        "create_event requires summary, start_iso, end_iso"
    )
    body = {
        "summary": summary,
        "start": {"dateTime": start_iso, "timeZone": time_zone},
        "end": {"dateTime": end_iso, "timeZone": time_zone},
    }
    if location:
        body["location"] = location
    if description:
        body["description"] = description
    res = calendar(account).events().insert(
        calendarId=calendar_id, body=body, sendUpdates="none").execute()
    return {"id": res.get("id"), "htmlLink": res.get("htmlLink") or ""}
