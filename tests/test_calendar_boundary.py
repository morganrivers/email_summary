"""Which calendar this app may write to.

An event body is text a model produced while reading someone's mail, so a write
to a calendar other than the account's own is a way to republish private mail
to whoever subscribes to that calendar. Reads take a `calendar_id` (the daily
summary reads a community calendar); writes must not be able to name one at
all, and that is a property of the tree rather than of any one run, so most of
this is read as an AST.
"""

import ast
import inspect
from types import SimpleNamespace

import pytest
from harness import attribute_chains, python_sources, relative

from backend.drafting import tool_executors
from backend.integrations.gmail_gcal import calendar_api, calendar_public, oauth_app

# Every Calendar API method that changes state. `move` is here because it takes
# a destination calendar, which is a write to that calendar by another name.
MUTATORS = ("insert", "update", "patch", "delete", "move", "import_")

# Collections that are not events. `acl` is read in exactly one place, to decide
# whether the write calendar is private; changing an ACL shares a calendar with
# other people and nothing here may do it, which is why the consent asks for
# `calendar.acls.readonly` and not `calendar.acls`. `calendars` and
# `calendarList` create and subscribe to calendars and are never touched.
FORBIDDEN_COLLECTIONS = ("acl", "calendars", "calendarList")

CALENDAR_API = "backend/integrations/gmail_gcal/calendar_api.py"


def calendar_chains(path):
    """Attribute chains that reach the Calendar service, builder calls flattened
    (`calendar(account).events().insert` reads as `calendar.events.insert`)."""
    for chain in attribute_chains(path, through_calls=True):
        parts = chain.split(".")
        if "events" in parts or set(parts) & set(FORBIDDEN_COLLECTIONS):
            yield chain


def test_the_write_calendar_is_the_accounts_own():
    assert calendar_api.WRITE_CALENDAR == "primary", (
        f"writes go to {calendar_api.WRITE_CALENDAR!r}; anything but 'primary' "
        f"is a calendar someone else can read, and event bodies are built from "
        f"the account's mail"
    )


def test_create_event_cannot_be_told_which_calendar():
    params = inspect.signature(calendar_api.create_event).parameters
    named = [p for p in params if "calendar" in p.lower()]
    assert not named, (
        f"create_event grew {named}; a caller that can name a calendar is a "
        f"caller a model can point at a public one"
    )


def test_no_write_reaches_calendar_outside_calendar_api():
    offenders = sorted({
        f"{relative(path)}: {chain}" for path in python_sources()
        if relative(path) != CALENDAR_API
        for chain in calendar_chains(path)
        if chain.rsplit(".", 1)[-1] in MUTATORS
    })
    assert not offenders, (
        f"{offenders} write to Calendar directly; go through "
        f"calendar_api.create_event, which is the only code that decides the "
        f"calendar"
    )


def test_nothing_shares_a_calendar_or_makes_one():
    """The ACL may be read, and only in `calendar_api`. Nothing may write one:
    the code that decides a calendar is too public to write to must not be able
    to make it less public and proceed."""
    def offends(path, chain):
        parts = chain.split(".")
        touched = set(parts) & set(FORBIDDEN_COLLECTIONS)
        if touched - {"acl"}:
            return True
        if "acl" not in touched:
            return False
        return relative(path) != CALENDAR_API or parts[-1] in MUTATORS

    offenders = sorted({
        f"{relative(path)}: {chain}" for path in python_sources()
        for chain in calendar_chains(path) if offends(path, chain)
    })
    assert not offenders, (
        f"{offenders} reach a calendar's ACL or calendar list; sharing a "
        f"calendar is how private events become public ones"
    )


def test_the_consent_asks_to_read_sharing_and_not_to_change_it(monkeypatch):
    from backend.integrations.gmail_gcal import oauth_app

    monkeypatch.setenv(oauth_app.ACL_SCOPE_ENV, "1")
    assert "https://www.googleapis.com/auth/calendar.acls.readonly" in oauth_app.scopes(), (
        "with the ACL scope switched on it has to be in the consent, or the "
        "token cannot answer the question create_event asks"
    )
    for setting in ("1", "0"):
        monkeypatch.setenv(oauth_app.ACL_SCOPE_ENV, setting)
        assert "https://www.googleapis.com/auth/calendar.acls" not in oauth_app.scopes(), (
            "the writable ACL scope would let a compromised process publish the "
            "calendar it is about to write to, and neither setting of the "
            "switch may ask for it"
        )


def test_every_write_in_calendar_api_names_the_one_constant():
    """Not just 'primary' spelled again: the constant, so the check above is
    the whole answer and a second literal cannot drift from it."""
    source = (calendar_api.__file__)
    tree = ast.parse(open(source).read())
    writes = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in MUTATORS:
            continue
        writes += 1
        target = {kw.arg: kw.value for kw in node.keywords}.get("calendarId")
        assert isinstance(target, ast.Name) and target.id == "WRITE_CALENDAR", (
            f"line {node.lineno}: {node.func.attr}() does not pass "
            f"calendarId=WRITE_CALENDAR"
        )
    assert writes == 1, f"expected one Calendar write, found {writes}"


def test_the_drafter_has_no_calendar_write_tool():
    """The tools the model may call, all of which read. A write tool here takes
    the whole question out of the code's hands: the model would be choosing the
    event, and only the argument schema would stand between mail content and a
    calendar."""
    assert set(tool_executors.TOOL_REGISTRY) == {
        "search_emails", "get_calendar_events", "get_email_thread",
    }, f"tool registry changed: {sorted(tool_executors.TOOL_REGISTRY)}"


def test_a_model_supplied_calendar_id_is_ignored_on_reads(monkeypatch):
    """`list_events` takes a calendar_id for the community calendar, so the tool
    that fronts it must not forward one out of the model's arguments."""
    seen = {}

    def fake_list_events(account, start_iso, end_iso, max_results=50,
                         calendar_id="primary"):
        seen.update(calendar_id=calendar_id)
        return []

    monkeypatch.setattr(calendar_api, "list_events", fake_list_events)
    tool_executors.get_calendar_events(
        {"start_iso": "2026-01-01T00:00:00", "end_iso": "2026-01-02T00:00:00",
         "calendar_id": "attacker@group.calendar.google.com",
         "calendarId": "attacker@group.calendar.google.com"},
        SimpleNamespace(id="acct"),
    )
    assert seen["calendar_id"] == "primary"


# The sharing states a real calendar can be in, named once.
OWNER_ONLY = {"scope": {"type": "user", "value": "owner@example.com"}, "role": "owner"}
ANYONE_READS = {"scope": {"type": "default"}, "role": "reader"}
ANYONE_WRITES = {"scope": {"type": "default"}, "role": "writer"}
ANYONE_SEES_BUSY = {"scope": {"type": "default"}, "role": "freeBusyReader"}
WHOLE_DOMAIN_READS = {"scope": {"type": "domain", "value": "example.com"}, "role": "reader"}
ONE_COLLEAGUE = {"scope": {"type": "user", "value": "colleague@example.com"}, "role": "reader"}


class FakeEvents:
    def __init__(self, calls):
        self._calls = calls

    def insert(self, **kwargs):
        self._calls.append(kwargs)
        return SimpleNamespace(execute=lambda: {"id": "e1", "htmlLink": "https://cal/e1"})


class FakeAcl:
    def __init__(self, rules, error, fetches):
        self._rules = rules
        self._error = error
        self._fetches = fetches

    def list(self, calendarId=None):
        def execute():
            self._fetches.append(calendarId)
            if self._error:
                raise self._error
            return {"items": self._rules}
        return SimpleNamespace(execute=execute)


@pytest.fixture
def calendar_of(monkeypatch):
    """A fake Calendar service whose sharing the test chooses.

    The ACL scope is switched on, because that is the path these tests are
    about; `public_calendar_of` is the same set of questions asked the other
    way. `arrange(*rules, error=...)` installs it and hands back an account;
    `written` collects the event inserts and `acl_fetches` the sharing reads."""
    monkeypatch.setenv(oauth_app.ACL_SCOPE_ENV, "1")
    fake = SimpleNamespace(written=[], acl_fetches=[])
    calendar_api.forget_sharing()

    def arrange(*rules, error=None):
        monkeypatch.setattr(calendar_api, "calendar", lambda account: SimpleNamespace(
            events=lambda: FakeEvents(fake.written),
            acl=lambda: FakeAcl(list(rules), error, fake.acl_fetches),
        ))
        return SimpleNamespace(id=f"acct-{len(rules)}-{error!r}",
                               timezone="Europe/Berlin", telegram=None,
                               identity=None,
                               primary_email=lambda: "owner@example.com")

    fake.arrange = arrange
    yield fake
    calendar_api.forget_sharing()


@pytest.fixture
def public_calendar_of(monkeypatch):
    """The same fake, asked the unauthenticated way.

    `arrange(public=..., error=...)` decides what the public feed says about
    the account's own calendar; `probed` collects the calendar ids it was asked
    about, so a test can show the question was asked once and about the right
    calendar."""
    monkeypatch.delenv(oauth_app.ACL_SCOPE_ENV, raising=False)
    fake = SimpleNamespace(written=[], probed=[])
    calendar_api.forget_sharing()

    def arrange(public=False, error=None, address="owner@example.com"):
        def is_public(calendar_id):
            fake.probed.append(calendar_id)
            if error:
                raise error
            return public

        monkeypatch.setattr(calendar_api.calendar_public, "is_public", is_public)
        monkeypatch.setattr(calendar_api, "calendar", lambda account: SimpleNamespace(
            events=lambda: FakeEvents(fake.written),
            acl=lambda: pytest.fail("the ACL was read without the scope for it"),
        ))
        return SimpleNamespace(id=f"acct-{public}-{error!r}",
                               timezone="Europe/Berlin", telegram=None,
                               identity=None, primary_email=lambda: address)

    fake.arrange = arrange
    yield fake
    calendar_api.forget_sharing()


def make_event(account):
    return calendar_api.create_event(
        account, summary="Coffee",
        start_iso="2026-01-01T10:00:00", end_iso="2026-01-01T11:00:00",
        description="the part of the email that says why",
    )


def test_an_event_goes_to_the_primary_calendar_and_invites_nobody(calendar_of):
    make_event(calendar_of.arrange(OWNER_ONLY, ONE_COLLEAGUE))
    assert len(calendar_of.written) == 1
    call = calendar_of.written[0]
    assert call["calendarId"] == "primary"
    assert call["sendUpdates"] == "none", (
        "an invite mails the event body to an address the model chose"
    )
    assert "attendees" not in call["body"]
    assert set(call["body"]) <= {"summary", "start", "end", "location", "description"}


@pytest.mark.parametrize("rule", [ANYONE_READS, ANYONE_WRITES, WHOLE_DOMAIN_READS])
def test_nothing_is_written_to_a_calendar_others_can_read(calendar_of, rule):
    with pytest.raises(calendar_api.CalendarNotPrivate):
        make_event(calendar_of.arrange(OWNER_ONLY, rule))
    assert calendar_of.written == [], "the event was written before the refusal"


def test_a_free_busy_share_is_not_a_content_share(calendar_of):
    """freeBusyReader exposes that a span of time is taken and no field of the
    event, which the calendar already leaked for everything the user wrote by
    hand. Refusing it would turn the check into one nobody can satisfy."""
    make_event(calendar_of.arrange(OWNER_ONLY, ANYONE_SEES_BUSY))
    assert len(calendar_of.written) == 1


def test_an_unreadable_acl_refuses_the_write(calendar_of):
    """What a token minted before the ACL scope existed answers, and what an
    outage answers. Neither says the calendar is private."""
    with pytest.raises(calendar_api.CalendarSharingUnknown):
        make_event(calendar_of.arrange(
            OWNER_ONLY, error=RuntimeError("403 insufficient scope")))
    assert calendar_of.written == []


def test_an_unreadable_acl_is_still_a_refusal_to_every_caller():
    assert issubclass(calendar_api.CalendarSharingUnknown,
                      calendar_api.CalendarNotPrivate), (
        "a caller that refuses on CalendarNotPrivate must also refuse when the "
        "sharing could not be read at all"
    )


def test_a_calendar_the_public_feed_serves_is_not_written_to(public_calendar_of):
    """The refusal without the ACL scope. A 200 from an unauthenticated fetch is
    not a permission record saying mail would be readable; it is the feed being
    served to a client holding nothing."""
    account = public_calendar_of.arrange(public=True)
    with pytest.raises(calendar_api.CalendarNotPrivate):
        make_event(account)
    assert public_calendar_of.written == []
    assert public_calendar_of.probed == ["owner@example.com"], (
        "the probe must name the account's own calendar and no other"
    )


def test_a_calendar_the_public_feed_does_not_serve_is_written_to(public_calendar_of):
    make_event(public_calendar_of.arrange(public=False))
    assert len(public_calendar_of.written) == 1


def test_a_probe_that_cannot_answer_refuses_the_write(public_calendar_of):
    """Same fail-closed rule as the ACL path: a redirect, a 5xx or a dead socket
    is not evidence that a calendar is private."""
    with pytest.raises(calendar_api.CalendarSharingUnknown):
        make_event(public_calendar_of.arrange(
            error=calendar_public.PublicProbeFailed("503")))
    assert public_calendar_of.written == []


def test_the_public_answer_is_cached_like_the_acl_one(public_calendar_of):
    account = public_calendar_of.arrange(public=False)
    for _ in range(3):
        make_event(account)
    assert len(public_calendar_of.written) == 3
    assert public_calendar_of.probed == ["owner@example.com"], (
        "the feed is fetched once per account per TTL, not once per event"
    )


def test_the_probe_url_is_the_public_feed_and_the_id_is_checked():
    url = calendar_public.public_ics_url("owner@example.com")
    assert url.startswith(calendar_public.ICS_ROOT)
    assert url.endswith(calendar_public.ICS_SUFFIX)
    assert "owner%40example.com" in url, (
        "the calendar id becomes a path segment, so it has to be escaped"
    )
    for bad in ("", "primary", "../../evil", "owner@example.com/../x"):
        with pytest.raises(AssertionError):
            calendar_public.public_ics_url(bad)


def test_the_probe_reads_a_status_code_and_never_a_body(monkeypatch):
    """A GET would pull the account's own event titles into this process to
    learn nothing a status code does not already say. Redirects are not
    followed, because a 302 to a sign-in page is a 200 to a client that
    follows one."""
    seen = {}

    def fake_head(url, timeout=None, allow_redirects=None):
        seen.update(url=url, timeout=timeout, allow_redirects=allow_redirects)
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(calendar_public.requests, "head", fake_head)
    monkeypatch.setattr(calendar_public.requests, "get", lambda *a, **k: pytest.fail(
        "the public probe fetched the feed's contents"))
    assert calendar_public.is_public("owner@example.com") is True
    assert seen["allow_redirects"] is False
    assert seen["timeout"] == calendar_public.TIMEOUT


@pytest.mark.parametrize("status", [301, 302, 401, 403, 429, 500, 503])
def test_only_404_means_not_public(monkeypatch, status):
    monkeypatch.setattr(calendar_public.requests, "head",
                        lambda *a, **k: SimpleNamespace(status_code=status))
    with pytest.raises(calendar_public.PublicProbeFailed):
        calendar_public.is_public("owner@example.com")

    monkeypatch.setattr(calendar_public.requests, "head",
                        lambda *a, **k: SimpleNamespace(status_code=404))
    assert calendar_public.is_public("owner@example.com") is False


def test_the_public_feed_host_is_in_the_egress_allowlist():
    """The probe is the one outbound call that is not to an API root, so a
    deployment with the allowlist on would refuse it and every write with it."""
    from urllib.parse import urlsplit

    from backend import egress

    assert urlsplit(calendar_public.ICS_ROOT).hostname in egress.hosts()


def test_each_refusal_names_the_remedy_that_fixes_it(monkeypatch):
    from backend.drafting import schedule_from_sent

    shared = schedule_from_sent.render_not_private(
        calendar_api.CalendarNotPrivate("shared with default=reader"))
    assert "Make it private" in shared
    assert "/auth/login" not in shared

    monkeypatch.setenv(oauth_app.ACL_SCOPE_ENV, "1")
    unknown = schedule_from_sent.render_not_private(
        calendar_api.CalendarSharingUnknown("403"))
    assert "/auth/login" in unknown, (
        "the ACL scope arrives with a new grant, so this one is fixed by "
        "signing in, not by editing a calendar"
    )

    monkeypatch.delenv(oauth_app.ACL_SCOPE_ENV, raising=False)
    unknown = schedule_from_sent.render_not_private(
        calendar_api.CalendarSharingUnknown("503"))
    assert "/auth/login" not in unknown, (
        "without the ACL scope the check is an unauthenticated fetch, so a new "
        "grant fixes nothing and sending the user for one wastes their time"
    )


def test_the_sharing_answer_is_asked_for_and_then_cached(calendar_of):
    account = calendar_of.arrange(OWNER_ONLY)
    for _ in range(3):
        make_event(account)
    assert len(calendar_of.written) == 3
    assert calendar_of.acl_fetches == ["primary"], (
        "the ACL is read once per account per TTL, not once per event"
    )


def test_the_scheduler_writes_through_the_pinned_boundary(calendar_of):
    from backend.drafting import schedule_from_sent

    schedule_from_sent.create_event(calendar_of.arrange(OWNER_ONLY), {
        "summary": "Call", "start": "2026-01-01T10:00:00",
        "end": "2026-01-01T11:00:00", "location": "", "description": "",
    })
    assert calendar_of.written[0]["calendarId"] == "primary"


def test_a_shared_calendar_stops_the_batch_and_is_reported_once(calendar_of, monkeypatch):
    """One notice for the account, not one per event: every remaining event in
    the batch would be refused for the same reason."""
    from backend.drafting import schedule_from_sent

    account = calendar_of.arrange(OWNER_ONLY, ANYONE_READS)
    sent = []
    monkeypatch.setattr(schedule_from_sent, "send_telegram",
                        lambda text, target=None: sent.append(text))
    monkeypatch.setattr(schedule_from_sent, "notify_error",
                        lambda *args, **kwargs: sent.append("ERROR"))
    monkeypatch.setattr(schedule_from_sent.llm_client, "make_client",
                        lambda account: object())
    monkeypatch.setattr(schedule_from_sent, "extract_events",
                        lambda *args, **kwargs: [
                            {"summary": "Coffee", "start": "2026-01-01T10:00:00"},
                        ])

    created = schedule_from_sent.run(account, [{"id": "m1"}, {"id": "m2"}])

    assert created == []
    assert calendar_of.written == []
    assert len(sent) == 1, f"expected one notice, got {sent}"
    assert "Scheduling stopped" in sent[0]
