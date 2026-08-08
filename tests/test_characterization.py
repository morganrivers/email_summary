"""Golden characterization tests: pin every outbound effect of each path.

Run/refresh goldens:  UPDATE_GOLDEN=1 pytest tests/
Verify (default):     pytest tests/

The `messages` recorded under llm_calls are already pseudonymized -- they are
exactly what would leave the box to the LLM / LangSmith. Any masking change
shows up as a golden diff.
"""

import json

from harness import assert_golden, NEUTRAL_IDENTITY
from identity_fixture import (
    OTHER_ALIASES, OTHER_EMAIL, OTHER_FIRST, OTHER_LAST,
    OWNER_ALT_EMAIL, OWNER_BOT_ALIAS, OWNER_FIRST, OWNER_FROM,
)


def record(rec, **extra):
    out = {
        "llm_calls": rec.llm_calls,
        "gmail_calls": rec.gmail_calls,
        "telegram": rec.telegram,
    }
    out.update(extra)
    return out


# --- fixtures -------------------------------------------------------------

def auto_email():
    return {
        "id": "e1", "threadId": "t1",
        "from": "Alice Adams <alice@contoso.com>",
        "to": OWNER_ALT_EMAIL,
        "date": "Mon, 20 Jul 2026 09:00:00 +0000",
        "subject": "Lunch next week?",
        "body": f"Hi {OWNER_FIRST}, want to grab lunch next week? Best, Alice Adams",
        "messageIdHeader": "<msg-e1@mail>",
        "referencesHeader": "",
    }


def bot_email():
    return {
        "id": "b1", "threadId": "t9",
        "to": OWNER_BOT_ALIAS,
        "from": OWNER_FROM,
        "subject": "Fwd: Project sync",
        "date": "Mon, 20 Jul 2026 10:00:00 +0000",
        "body": (
            "Please say yes and propose Friday.\n\n"
            "---------- Forwarded message ----------\n"
            "From: Bob Baker <bob@contoso.com>\n"
            "Subject: Project sync\n"
            "Date: Mon, 20 Jul 2026 08:00:00 +0000\n\n"
            f"Hi {OWNER_FIRST}, can we sync on the project this week?"
        ),
    }


def bot_email_no_marker():
    return {
        "id": "b2", "threadId": "t8",
        "to": OWNER_BOT_ALIAS,
        "from": OWNER_FROM,
        "subject": "Fwd: Budget",
        "date": "Mon, 20 Jul 2026 11:00:00 +0000",
        "body": "Can you reply to this thread for me?",
    }


def sent_email(body):
    return {
        "id": "s1",
        "to": "dave@contoso.com",
        "subject": "Confirming Tuesday",
        "date": "Tue, 21 Jul 2026 09:00:00 +0000",
        "body": body,
    }


def decisions(*entries):
    return json.dumps({"decisions": list(entries)})


DRAFT_OUT = {"submit": "draft-1"}


# --- auto-reply path ------------------------------------------------------

def test_auto_reply_no_tools(wire):
    from backend.drafting import draft_replies
    rec = wire.install(
        responses=[
            {"content": decisions({"index": 0, "needs_reply": True, "reason": "Personal lunch request"})},
            {"content": f"Hi Alice,\n\nLunch sounds great. How about Tuesday?\n\nBest,\n{OWNER_FIRST}"},
        ],
        gmail_outputs=DRAFT_OUT,
    )
    drafted = draft_replies.process_emails(wire.account, [auto_email()])
    assert_golden("auto_reply_no_tools", record(rec, returned=drafted))


def test_auto_reply_with_calendar_tool(wire):
    from backend.drafting import draft_replies
    rec = wire.install(
        responses=[
            {"content": decisions({"index": 0, "needs_reply": True, "reason": "Asks about meeting"})},
            {"tool_calls": [{"name": "get_calendar_events", "arguments": json.dumps(
                {"start_iso": "2026-07-23T00:00:00Z", "end_iso": "2026-07-24T00:00:00Z"})}]},
            {"content": f"Hi Alice,\n\nThursday afternoon works. Say 3pm?\n\nBest,\n{OWNER_FIRST}"},
        ],
        gmail_outputs={"list_events": [], **DRAFT_OUT},
    )
    drafted = draft_replies.process_emails(wire.account, [auto_email()])
    assert_golden("auto_reply_with_calendar_tool", record(rec, returned=drafted))


def test_auto_reply_declined(wire):
    from backend.drafting import draft_replies
    rec = wire.install(
        responses=[
            {"content": decisions({"index": 0, "needs_reply": False, "reason": "Newsletter"})},
        ],
        gmail_outputs={},
    )
    drafted = draft_replies.process_emails(wire.account, [auto_email()])
    assert_golden("auto_reply_declined", record(rec, returned=drafted))


def test_auto_reply_em_dash_rejected(wire):
    from backend.drafting import draft_replies
    dash_body = f"Hi Alice — lunch works.\n\nBest,\n{OWNER_FIRST}"
    rec = wire.install(
        responses=[
            {"content": decisions({"index": 0, "needs_reply": True, "reason": "Personal"})},
            {"content": dash_body}, {"content": dash_body}, {"content": dash_body},
            {"content": dash_body}, {"content": dash_body},
        ],
        gmail_outputs={},
    )
    drafted = draft_replies.process_emails(wire.account, [auto_email()])
    assert_golden("auto_reply_em_dash_rejected", record(rec, returned=drafted))


# --- manual (bot-request) path -------------------------------------------

def test_bot_request_forward_marker(wire):
    from backend.drafting import manual_draft
    rec = wire.install(
        responses=[
            {"tool_calls": [{"name": "get_calendar_events", "arguments": json.dumps(
                {"start_iso": "2026-07-24T00:00:00Z", "end_iso": "2026-07-25T00:00:00Z"})}]},
            {"content": f"Hi Bob,\n\nYes, Friday works. Say 2pm?\n\nBest,\n{OWNER_FIRST}"},
        ],
        gmail_outputs={
            "find_thread_by_from_subject": {"found": True, "threadId": "t9",
                                            "messageIdHeader": "<mid-t9@mail>",
                                            "referencesHeader": ""},
            "list_events": [],
            "submit": "draft-5",
        },
    )
    result = manual_draft.process_draft_request(wire.account, bot_email())
    assert_golden("bot_request_forward_marker", record(rec, returned=result))


def test_bot_request_thread_fallback(wire):
    from backend.drafting import manual_draft
    rec = wire.install(
        responses=[
            {"content": f"Hi Carol,\n\nThe budget looks good to me.\n\nBest,\n{OWNER_FIRST}"},
        ],
        gmail_outputs={
            "get_thread": {"messages": [
                {"id": "m1", "from": "Carol Clark <carol@contoso.com>",
                 "to": OWNER_ALT_EMAIL, "subject": "Budget",
                 "date": "Mon, 20 Jul 2026 07:00:00 +0000",
                 "body": f"Hi {OWNER_FIRST}, thoughts on the budget?"},
                {"id": "b2", "from": OWNER_FROM,
                 "to": OWNER_BOT_ALIAS, "subject": "Fwd: Budget",
                 "date": "Mon, 20 Jul 2026 11:00:00 +0000", "body": "Can you reply?"},
            ]},
            "find_thread_by_from_subject": {"found": True, "threadId": "t8",
                                            "messageIdHeader": "<mid-t8@mail>",
                                            "referencesHeader": ""},
            "submit": "draft-6",
        },
    )
    result = manual_draft.process_draft_request(wire.account, bot_email_no_marker())
    assert_golden("bot_request_thread_fallback", record(rec, returned=result))


# --- schedule-from-sent path ---------------------------------------------

def test_schedule_from_sent_concrete(wire):
    from backend.drafting import schedule_from_sent
    rec = wire.install(
        responses=[
            {"content": json.dumps({"events": [
                {"summary": "Meeting with Dave", "start": "2026-07-21T15:00:00",
                 "end": "", "location": "", "description": ""}]})},
        ],
        gmail_outputs={"create_event": {"htmlLink": "https://cal/evt1", "id": "evt1"}},
    )
    created = schedule_from_sent.run(wire.account, [sent_email(
        f"Hi Dave, confirming our meeting Tuesday July 21 at 3pm. {OWNER_FIRST}")])
    assert_golden("schedule_from_sent_concrete", record(rec, returned=created))


def test_schedule_from_sent_vague(wire):
    from backend.drafting import schedule_from_sent
    rec = wire.install(
        responses=[{"content": json.dumps({"events": []})}],
        gmail_outputs={},
    )
    created = schedule_from_sent.run(wire.account, [sent_email(
        f"Hi Dave, let's meet sometime next week. {OWNER_FIRST}")])
    assert_golden("schedule_from_sent_vague", record(rec, returned=created))


# --- masking core ---------------------------------------------------------

def test_pii_masking_leaving_payload(wire):
    from backend.drafting import draft_replies
    pii_email = {
        "id": "p1", "threadId": "tp",
        "from": "Nadia Fowler <nadia.fowler@acme.io>",
        "to": OWNER_ALT_EMAIL,
        "date": "Mon, 20 Jul 2026 09:00:00 +0000",
        "subject": "Access details",
        "body": (f"Hi {OWNER_FIRST}, my number is 415-555-0199 and the key is "
                 "sk-ant-abcd1234efgh5678ijklmnop. Reach Priya Sharma too. "
                 "Thanks, Nadia Fowler"),
        "messageIdHeader": "<msg-p1@mail>", "referencesHeader": "",
    }
    rec = wire.install(
        responses=[
            {"content": decisions({"index": 0, "needs_reply": True, "reason": "Personal"})},
            {"content": f"Hi Nadia,\n\nGot it, thanks.\n\nBest,\n{OWNER_FIRST}"},
        ],
        gmail_outputs=DRAFT_OUT,
    )
    draft_replies.process_emails(wire.account, [pii_email])

    leaving = json.dumps(rec.llm_calls)
    assert "nadia.fowler@acme.io" not in leaving
    assert "415-555-0199" not in leaving
    assert "sk-ant-abcd1234efgh5678ijklmnop" not in leaving
    assert "[EMAIL" in leaving
    assert "[PHONE_NUMBER" in leaving
    assert "[API_KEY" in leaving
    assert_golden("pii_masking_leaving_payload", record(rec))


def test_pseudonymize_roundtrip():
    from backend.masking import pseudonymizer
    original = "Email Priya Sharma at priya@acme.io or call 415-555-0199."
    st = pseudonymizer.new_state(NEUTRAL_IDENTITY)
    masked = pseudonymizer.pseudonymize(original, st)
    assert "priya@acme.io" not in masked
    assert "415-555-0199" not in masked
    assert "[EMAIL" in masked and "[PHONE_NUMBER" in masked
    restored = pseudonymizer.restore(masked, st)
    assert "priya@acme.io" in restored
    assert "415-555-0199" in restored
    assert "Priya" in restored and "Sharma" in restored


def test_literal_scrub_owner_phone_and_contacts():
    from backend.masking import pseudonymizer
    ident = pseudonymizer.UserIdentity(
        OTHER_FIRST, OTHER_LAST, OTHER_ALIASES, [OTHER_EMAIL],
        phones=["+1 (415) 555-0142"], contacts=["Priya Sharma", "Bob"],
    )
    st = pseudonymizer.new_state(ident)
    text = (f"{OTHER_FIRST} here. Cell 415.555.0142 or +14155550142. "
            "Ping priya sharma and Bob. Ref number 12.")
    masked = pseudonymizer.pseudonymize(text, st)
    for leak in ["415", "0142", "Priya", "Sharma", OTHER_FIRST, OTHER_LAST]:
        assert leak not in masked, leak
    assert masked.count("[USER_PHONE]") == 2
    assert "Ref number 12." in masked
    restored = pseudonymizer.restore(masked, st)
    assert "Priya Sharma" in restored and "Bob" in restored


# --- top-level integration -----------------------------------------------

def test_process_once_end_to_end(wire):
    from backend.accounts import state
    from backend.daemons import daemon_loop
    store = state.StateStore(state.DEFAULT_STATE_FILE)
    store.save({"lastHistoryId": "100", "watchExpiration": None})
    fetch_payload = {
        "emails": [auto_email(), bot_email()],
        "sent": [sent_email(f"Hi Dave, confirming Tuesday July 21 at 3pm. {OWNER_FIRST}")],
        "historyId": "200",
        "stale": False,
    }
    rec = wire.install(
        responses=[
            # bot request draft (no tools)
            {"content": f"Hi Bob,\n\nYes, Friday works. Say 2pm?\n\nBest,\n{OWNER_FIRST}"},
            # auto classify + draft
            {"content": decisions({"index": 0, "needs_reply": True, "reason": "Personal lunch request"})},
            {"content": f"Hi Alice,\n\nLunch sounds great. How about Tuesday?\n\nBest,\n{OWNER_FIRST}"},
            # schedule extract
            {"content": json.dumps({"events": [
                {"summary": "Meeting with Dave", "start": "2026-07-21T15:00:00",
                 "end": "", "location": "", "description": ""}]})},
        ],
        gmail_outputs={
            "fetch_since_history": fetch_payload,
            "find_thread_by_from_subject": {"found": True, "threadId": "t9",
                                            "messageIdHeader": "<mid-t9@mail>",
                                            "referencesHeader": ""},
            "submit": "draft-x",
            "create_event": {"htmlLink": "https://cal/evt1", "id": "evt1"},
        },
    )
    daemon_loop.process_all()
    assert_golden("process_once_end_to_end",
                  record(rec, final_state=store.load()))
