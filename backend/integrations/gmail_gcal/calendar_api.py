"""Google Calendar, in process. The Python replacement for the calendar half of
gmail_lib.mjs.

Same credentials as Gmail (one consent covers both), so the service comes from
`google_client` rather than being built a second way here. This module knows
nothing about mail.
"""

from __future__ import annotations

from backend.integrations.gmail_gcal.google_client import service


MAX_SUMMARY = 200
MAX_LOCATION = 200
MAX_DESCRIPTION = 500
DEFAULT_TIMEZONE = "Europe/Berlin"

# The one calendar this app writes to. Reads take a calendar_id (the daily
# summary reads a community calendar too); writes do not take one, because the
# only thing that decides what gets written is a model reading mail an outside
# sender wrote. A parameter here would be a parameter a future caller could fill
# from that model, and the calendar it named could be a public one. Not being
# able to name a calendar is a stronger guarantee than being trusted not to.
WRITE_CALENDAR = "primary"


def calendar(account):
    return service(account, "calendar", "v3")


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
                 time_zone=DEFAULT_TIMEZONE, location="", description=""):
    """Write one event to the account's own calendar, and nowhere else.

    Three things are deliberately not parameters: the calendar (WRITE_CALENDAR),
    the attendee list, and whether invites go out (`sendUpdates="none"`). Every
    field that is a parameter is text, and the caps are asserted rather than
    truncated here: text this long did not come from an event, it came from
    something filling an event with a payload, and the caller that fed it is the
    one that should hear about it."""
    assert summary and start_iso and end_iso, (
        "create_event requires summary, start_iso, end_iso"
    )
    assert len(summary) <= MAX_SUMMARY, (
        f"event summary is {len(summary)} chars, limit {MAX_SUMMARY}"
    )
    assert len(location) <= MAX_LOCATION, (
        f"event location is {len(location)} chars, limit {MAX_LOCATION}"
    )
    assert len(description) <= MAX_DESCRIPTION, (
        f"event description is {len(description)} chars, limit {MAX_DESCRIPTION}"
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
        calendarId=WRITE_CALENDAR, body=body, sendUpdates="none").execute()
    return {"id": res.get("id"), "htmlLink": res.get("htmlLink") or ""}
