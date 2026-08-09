"""Google Calendar, in process. The Python replacement for the calendar half of
gmail_lib.mjs.

Same credentials as Gmail (one consent covers both), so the service comes from
`google_client` rather than being built a second way here. This module knows
nothing about mail.
"""

from __future__ import annotations

import threading
import time

from backend.integrations.gmail_gcal import calendar_public, oauth_app
from backend.integrations.gmail_gcal.google_client import CALENDAR, service

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

# Pinning the calendar answers "which calendar", not "who reads it": `primary`
# is the account's own, and an account can share its own calendar with the
# public. So the write is also checked against who can read that calendar.
#
# There are two ways to ask, and `oauth_app.acl_scope_registered()` is the one
# place that picks: the calendar's own ACL when the consent carries
# `calendar.acls.readonly`, and `calendar_public` -- an unauthenticated fetch of
# the public feed -- when it does not. Never both, and never a fallback from one
# to the other: falling back on an error is how a control that is supposed to
# refuse comes to approve.
#
# `default` is the ACL scope meaning anyone at all, `domain` means everyone in
# the account's Workspace. `freeBusyReader` is deliberately not a content role:
# it exposes that a span of time is busy and no field of the event, which the
# calendar already leaks for every event the user wrote by hand.
OPEN_SCOPES = ("default", "domain")
CONTENT_ROLES = ("reader", "writer", "owner")

# Sharing belongs to the calendar rather than to the credentials, so a
# re-consent does not change the answer and there is nothing to invalidate on
# one; the bound on how stale it can be is this TTL alone. Short, because it is
# the window in which a user who has just made their calendar public still gets
# events written to it.
SHARING_TTL = 600

_sharing_lock = threading.Lock()
_sharing_cache = {}


class CalendarNotPrivate(Exception):
    """The write calendar is shared with somebody other than its owner.

    An event body assembled from the account's mail is not written to it."""


class CalendarSharingUnknown(CalendarNotPrivate):
    """The sharing settings could not be read at all.

    A subclass because the decision is the same one and every caller that
    refuses on the parent must refuse on this. It is separate because the remedy
    is not: a shared calendar is fixed in Google Calendar, a token minted before
    `calendar.acls.readonly` was requested is fixed by signing in again, an
    unreachable public feed is fixed by waiting, and telling a user to do the
    wrong one of those is how a working feature looks broken."""


def calendar(account):
    return service(account, *CALENDAR)


def _acl_audience(rules):
    """The rules that hand event contents to somebody who is not the owner."""
    audience = set()
    for rule in rules:
        scope = rule.get("scope") or {}
        if scope.get("type") in OPEN_SCOPES and rule.get("role") in CONTENT_ROLES:
            audience.add(f"{scope['type']}={rule['role']}")
    return tuple(sorted(audience))


def _audience_from_acl(account):
    """The ACL read. Needs `calendar.acls.readonly` on the token."""
    res = calendar(account).acl().list(calendarId=WRITE_CALENDAR).execute()
    return _acl_audience(res.get("items", []))


def _audience_from_public_feed(account):
    """The unauthenticated probe, for a consent without the ACL scope.

    `WRITE_CALENDAR` is `primary`, and an account's primary calendar is named by
    its own address, so that address is what gets probed. It is asserted rather
    than defaulted: a blank one would build a URL for somebody else's calendar
    and 404, which reads as private."""
    address = (account.primary_email() or "").strip().lower()
    assert address and "@" in address, (
        f"account {account.id} has no mail address, so its primary calendar "
        f"cannot be named"
    )
    public = calendar_public.is_public(address)
    return (calendar_public.PUBLIC_AUDIENCE,) if public else ()


def write_calendar_audience(account):
    """Who can read WRITE_CALENDAR besides its owner, as short rule names.

    Empty means private. Takes no calendar argument on purpose: this answers a
    question about the one calendar this app writes to, and a parameter here
    would reintroduce the naming that `create_event` refuses to allow. Which of
    the two ways it asks is not the caller's business either, so both paths land
    in the one cache under the one TTL."""
    assert getattr(account, "id", None), "write_calendar_audience needs a loaded Account"
    now = time.monotonic()
    with _sharing_lock:
        cached = _sharing_cache.get(account.id)
        if cached and now - cached[0] < SHARING_TTL:
            return cached[1]
    if oauth_app.acl_scope_registered():
        audience = _audience_from_acl(account)
    else:
        audience = _audience_from_public_feed(account)
    with _sharing_lock:
        _sharing_cache[account.id] = (time.monotonic(), audience)
    return audience


def forget_sharing(account_id=None):
    """Drop what we know about a calendar's sharing, so the next write asks
    Google again."""
    with _sharing_lock:
        if account_id is None:
            _sharing_cache.clear()
        else:
            _sharing_cache.pop(account_id, None)


def _require_private_calendar(account):
    """Fail closed, including when the question cannot be asked.

    A token minted before `calendar.acls.readonly` was requested answers this
    with a 403, an outage answers with nothing at all, and the public feed
    answers with a status code that is neither 200 nor 404. All of them mean the
    same thing here: we do not know who reads that calendar, and the event body
    is somebody's mail."""
    try:
        audience = write_calendar_audience(account)
    except Exception as err:
        raise CalendarSharingUnknown(
            f"cannot read the sharing settings of the calendar ({err}); refusing "
            f"to write an event until it is known to be private"
        ) from err
    if audience:
        raise CalendarNotPrivate(
            f"the calendar is shared with {', '.join(audience)}; an event written "
            f"from your mail would be readable by everyone it is shared with"
        )


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
    """Write one event to the account's own private calendar, and nowhere else.

    Three things are deliberately not parameters: the calendar (WRITE_CALENDAR),
    the attendee list, and whether invites go out (`sendUpdates="none"`). Every
    field that is a parameter is text, and the caps are asserted rather than
    truncated here: text this long did not come from an event, it came from
    something filling an event with a payload, and the caller that fed it is the
    one that should hear about it.

    "Private" is checked rather than assumed, and checked here rather than by
    the caller, so there is one place a write can happen and one place it can be
    refused."""
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
    _require_private_calendar(account)
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
