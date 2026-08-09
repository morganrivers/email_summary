"""Whether a calendar is readable by the public, asked from outside.

The authenticated way to answer this is `calendar_api.write_calendar_audience`,
which reads the calendar's ACL and needs `calendar.acls.readonly` on the
consent. This module is the answer for a deployment whose OAuth app does not
carry that scope: it fetches the calendar's public iCal feed with no credentials
at all, exactly as a stranger would. Google serves that URL only for a calendar
its owner has made public and answers 404 otherwise, so a 200 is the strongest
possible evidence of the thing we are refusing on -- not a permission record
saying mail *would* be readable, but the feed being served to a client holding
nothing.

No credentials are involved anywhere here, which is the reason it is a separate
module from `calendar_api` rather than a branch inside it. Nothing in this file
imports the Google API client, so `backend.egress` can read `ICS_ROOT` off it
without pulling credentials, custody and a discovery client into the egress
proxy's process.

Two ways this is weaker than the ACL read, both of which the caller is choosing
when it turns the scope off:

- A Workspace calendar shared with the whole domain is not public, so the feed
  404s and this says private. The ACL read refuses that case (`domain` in
  `calendar_api.OPEN_SCOPES`). On a consumer Gmail account there is no domain
  and the two agree.
- Public sharing has a free/busy-only setting that the ACL read tolerates
  (`freeBusyReader` exposes no field of an event). Whatever that setting does to
  this feed, a 200 refuses. Stricter, and in the safe direction.

The request is a HEAD. The status code is the whole answer, and a GET would pull
the account's own event titles into this process to learn nothing further.
"""

from __future__ import annotations

from urllib.parse import quote

import requests

# Where Google serves public calendar feeds. `backend.egress` reads the host off
# this constant, so the allowlist cannot be left behind by an edit here.
ICS_ROOT = "https://calendar.google.com/calendar/ical/"

# Path suffix for the public feed. `basic` rather than `full`: both are gated
# the same way and the smaller one is enough to read a status code from.
ICS_SUFFIX = "/public/basic.ics"

TIMEOUT = 10

# The name this verdict goes by in a refusal message, in the shape
# `calendar_api` uses for ACL rule names.
PUBLIC_AUDIENCE = "public"


class PublicProbeFailed(Exception):
    """The feed answered something other than "served" or "not found".

    A redirect, a 5xx, a rate limit or a dead socket all land here. None of them
    is evidence that a calendar is private, and treating them as one would turn
    every outage into permission to write mail contents to a calendar nobody
    checked."""


def public_ics_url(calendar_id):
    """The public feed URL for one calendar id.

    The id is checked into the shape of an address before it becomes a path
    segment, with the same expression the manifest checks a user-typed calendar
    id against -- imported inside the function so this module stays free of the
    account layer's imports."""
    from backend.accounts.account import CALENDAR_ID_RE

    assert calendar_id and CALENDAR_ID_RE.fullmatch(calendar_id), (
        f"not a calendar id: {calendar_id!r}"
    )
    return f"{ICS_ROOT}{quote(calendar_id, safe='')}{ICS_SUFFIX}"


def is_public(calendar_id):
    """True when Google serves this calendar to a client holding no credentials.

    Redirects are not followed: a 302 to a sign-in page is a 200 to a client
    that follows it, and would read as public. Anything but 200 or 404 raises
    rather than returning False."""
    url = public_ics_url(calendar_id)
    try:
        response = requests.head(url, timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException as err:
        raise PublicProbeFailed(f"cannot reach the public calendar feed ({err})") from err
    if response.status_code == 200:
        return True
    if response.status_code == 404:
        return False
    raise PublicProbeFailed(
        f"the public calendar feed answered {response.status_code}, which says "
        f"neither that the calendar is public nor that it is not"
    )
