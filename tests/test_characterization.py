"""Golden characterization tests: pin every outbound effect of each path.

Run/refresh goldens:  UPDATE_GOLDEN=1 pytest tests/
Verify (default):     pytest tests/

The `messages` recorded under llm_calls are already pseudonymized -- they are
exactly what would leave the box to the LLM / LangSmith. Any masking change
shows up as a golden diff.
"""

import json

from harness import assert_golden


def record(rec, **extra):
    out = {
        "llm_calls": rec.llm_calls,
        "node_calls": rec.node_calls,
        "telegram": rec.telegram,
    }
    out.update(extra)
    return out


# --- fixtures -------------------------------------------------------------

def auto_email():
    return {
        "id": "e1", "threadId": "t1",
        "from": "Alice Adams <alice@contoso.com>",
        "to": "orgmanrivers@gmail.com",
        "date": "Mon, 20 Jul 2026 09:00:00 +0000",
        "subject": "Lunch next week?",
        "body": "Hi Morgan, want to grab lunch next week? Best, Alice Adams",
        "messageIdHeader": "<msg-e1@mail>",
        "referencesHeader": "",
    }


def bot_email():
    return {
        "id": "b1", "threadId": "t9",
        "to": "danielmorganrivers+bot@gmail.com",
        "from": "Morgan Rivers <orgmanrivers@gmail.com>",
        "subject": "Fwd: Project sync",
        "date": "Mon, 20 Jul 2026 10:00:00 +0000",
        "body": (
            "Please say yes and propose Friday.\n\n"
            "---------- Forwarded message ----------\n"
            "From: Bob Baker <bob@contoso.com>\n"
            "Subject: Project sync\n"
            "Date: Mon, 20 Jul 2026 08:00:00 +0000\n\n"
            "Hi Morgan, can we sync on the project this week?"
        ),
    }


def bot_email_no_marker():
    return {
        "id": "b2", "threadId": "t8",
        "to": "danielmorganrivers+bot@gmail.com",
        "from": "Morgan Rivers <orgmanrivers@gmail.com>",
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


DRAFT_OUT = {"create_draft.mjs": {"draftId": "draft-1"}}


# --- auto-reply path ------------------------------------------------------

def test_auto_reply_no_tools(wire):
    import draft_replies
    rec = wire.install(
        responses=[
            {"content": decisions({"index": 0, "needs_reply": True, "reason": "Personal lunch request"})},
            {"content": "Hi Alice,\n\nLunch sounds great. How about Tuesday?\n\nBest,\nMorgan"},
        ],
        node_outputs=DRAFT_OUT,
    )
    drafted = draft_replies.process_emails(wire.account, [auto_email()])
    assert_golden("auto_reply_no_tools", record(rec, returned=drafted))


def test_auto_reply_with_calendar_tool(wire):
    import draft_replies
    rec = wire.install(
        responses=[
            {"content": decisions({"index": 0, "needs_reply": True, "reason": "Asks about meeting"})},
            {"tool_calls": [{"name": "get_calendar_events", "arguments": json.dumps(
                {"start_iso": "2026-07-23T00:00:00Z", "end_iso": "2026-07-24T00:00:00Z"})}]},
            {"content": "Hi Alice,\n\nThursday afternoon works. Say 3pm?\n\nBest,\nMorgan"},
        ],
        node_outputs={"list_calendar.mjs": [], **DRAFT_OUT},
    )
    drafted = draft_replies.process_emails(wire.account, [auto_email()])
    assert_golden("auto_reply_with_calendar_tool", record(rec, returned=drafted))


def test_auto_reply_declined(wire):
    import draft_replies
    rec = wire.install(
        responses=[
            {"content": decisions({"index": 0, "needs_reply": False, "reason": "Newsletter"})},
        ],
        node_outputs={},
    )
    drafted = draft_replies.process_emails(wire.account, [auto_email()])
    assert_golden("auto_reply_declined", record(rec, returned=drafted))


def test_auto_reply_em_dash_rejected(wire):
    import draft_replies
    dash_body = "Hi Alice — lunch works.\n\nBest,\nMorgan"
    rec = wire.install(
        responses=[
            {"content": decisions({"index": 0, "needs_reply": True, "reason": "Personal"})},
            {"content": dash_body}, {"content": dash_body}, {"content": dash_body},
            {"content": dash_body}, {"content": dash_body},
        ],
        node_outputs={},
    )
    drafted = draft_replies.process_emails(wire.account, [auto_email()])
    assert_golden("auto_reply_em_dash_rejected", record(rec, returned=drafted))


# --- manual (bot-request) path -------------------------------------------

def test_bot_request_forward_marker(wire):
    import manual_draft
    rec = wire.install(
        responses=[
            {"tool_calls": [{"name": "get_calendar_events", "arguments": json.dumps(
                {"start_iso": "2026-07-24T00:00:00Z", "end_iso": "2026-07-25T00:00:00Z"})}]},
            {"content": "Hi Bob,\n\nYes, Friday works. Say 2pm?\n\nBest,\nMorgan"},
        ],
        node_outputs={
            "find_thread.mjs": {"found": True, "threadId": "t9",
                                "messageIdHeader": "<mid-t9@mail>", "referencesHeader": ""},
            "list_calendar.mjs": [],
            "create_draft.mjs": {"draftId": "draft-5"},
        },
    )
    result = manual_draft.process_draft_request(wire.account, bot_email())
    assert_golden("bot_request_forward_marker", record(rec, returned=result))


def test_bot_request_thread_fallback(wire):
    import manual_draft
    rec = wire.install(
        responses=[
            {"content": "Hi Carol,\n\nThe budget looks good to me.\n\nBest,\nMorgan"},
        ],
        node_outputs={
            "get_thread.mjs": {"messages": [
                {"id": "m1", "from": "Carol Clark <carol@contoso.com>",
                 "to": "orgmanrivers@gmail.com", "subject": "Budget",
                 "date": "Mon, 20 Jul 2026 07:00:00 +0000",
                 "body": "Hi Morgan, thoughts on the budget?"},
                {"id": "b2", "from": "Morgan Rivers <orgmanrivers@gmail.com>",
                 "to": "danielmorganrivers+bot@gmail.com", "subject": "Fwd: Budget",
                 "date": "Mon, 20 Jul 2026 11:00:00 +0000", "body": "Can you reply?"},
            ]},
            "find_thread.mjs": {"found": True, "threadId": "t8",
                                "messageIdHeader": "<mid-t8@mail>", "referencesHeader": ""},
            "create_draft.mjs": {"draftId": "draft-6"},
        },
    )
    result = manual_draft.process_draft_request(wire.account, bot_email_no_marker())
    assert_golden("bot_request_thread_fallback", record(rec, returned=result))


# --- schedule-from-sent path ---------------------------------------------

def test_schedule_from_sent_concrete(wire):
    import schedule_from_sent
    rec = wire.install(
        responses=[
            {"content": json.dumps({"events": [
                {"summary": "Meeting with Dave", "start": "2026-07-21T15:00:00",
                 "end": "", "location": "", "description": ""}]})},
        ],
        node_outputs={"create_event.mjs": {"htmlLink": "https://cal/evt1", "id": "evt1"}},
    )
    created = schedule_from_sent.run(wire.account, [sent_email(
        "Hi Dave, confirming our meeting Tuesday July 21 at 3pm. Morgan")])
    assert_golden("schedule_from_sent_concrete", record(rec, returned=created))


def test_schedule_from_sent_vague(wire):
    import schedule_from_sent
    rec = wire.install(
        responses=[{"content": json.dumps({"events": []})}],
        node_outputs={},
    )
    created = schedule_from_sent.run(wire.account, [sent_email(
        "Hi Dave, let's meet sometime next week. Morgan")])
    assert_golden("schedule_from_sent_vague", record(rec, returned=created))


# --- masking core ---------------------------------------------------------

def test_pii_masking_leaving_payload(wire):
    import draft_replies
    pii_email = {
        "id": "p1", "threadId": "tp",
        "from": "Nadia Fowler <nadia.fowler@acme.io>",
        "to": "orgmanrivers@gmail.com",
        "date": "Mon, 20 Jul 2026 09:00:00 +0000",
        "subject": "Access details",
        "body": ("Hi Morgan, my number is 415-555-0199 and the key is "
                 "sk-ant-abcd1234efgh5678ijklmnop. Reach Priya Sharma too. "
                 "Thanks, Nadia Fowler"),
        "messageIdHeader": "<msg-p1@mail>", "referencesHeader": "",
    }
    rec = wire.install(
        responses=[
            {"content": decisions({"index": 0, "needs_reply": True, "reason": "Personal"})},
            {"content": "Hi Nadia,\n\nGot it, thanks.\n\nBest,\nMorgan"},
        ],
        node_outputs=DRAFT_OUT,
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
    import pseudonymizer
    original = "Email Priya Sharma at priya@acme.io or call 415-555-0199."
    st = pseudonymizer.new_state()
    masked = pseudonymizer.pseudonymize(original, st)
    assert "priya@acme.io" not in masked
    assert "415-555-0199" not in masked
    assert "[EMAIL" in masked and "[PHONE_NUMBER" in masked
    restored = pseudonymizer.restore(masked, st)
    assert "priya@acme.io" in restored
    assert "415-555-0199" in restored
    assert "Priya" in restored and "Sharma" in restored


def test_literal_scrub_owner_phone_and_contacts():
    import pseudonymizer
    ident = pseudonymizer.UserIdentity(
        "Morgan", "Rivers", ["Daniel"], ["danielmorganrivers@gmail.com"],
        phones=["+1 (415) 555-0142"], contacts=["Priya Sharma", "Bob"],
    )
    st = pseudonymizer.new_state(ident)
    text = ("Morgan here. Cell 415.555.0142 or +14155550142. "
            "Ping priya sharma and Bob. Ref number 12.")
    masked = pseudonymizer.pseudonymize(text, st)
    for leak in ["415", "0142", "Priya", "Sharma", "Morgan", "Rivers"]:
        assert leak not in masked, leak
    assert masked.count("[USER_PHONE]") == 2
    assert "Ref number 12." in masked
    restored = pseudonymizer.restore(masked, st)
    assert "Priya Sharma" in restored and "Bob" in restored


# --- top-level integration -----------------------------------------------

def test_process_once_end_to_end(wire):
    import state
    import daemon_loop
    store = state.StateStore(state.DEFAULT_STATE_FILE)
    store.save({"lastHistoryId": "100", "watchExpiration": None})
    fetch_payload = {
        "emails": [auto_email(), bot_email()],
        "sent": [sent_email("Hi Dave, confirming Tuesday July 21 at 3pm. Morgan")],
        "historyId": "200",
        "stale": False,
    }
    rec = wire.install(
        responses=[
            # bot request draft (no tools)
            {"content": "Hi Bob,\n\nYes, Friday works. Say 2pm?\n\nBest,\nMorgan"},
            # auto classify + draft
            {"content": decisions({"index": 0, "needs_reply": True, "reason": "Personal lunch request"})},
            {"content": "Hi Alice,\n\nLunch sounds great. How about Tuesday?\n\nBest,\nMorgan"},
            # schedule extract
            {"content": json.dumps({"events": [
                {"summary": "Meeting with Dave", "start": "2026-07-21T15:00:00",
                 "end": "", "location": "", "description": ""}]})},
        ],
        node_outputs={
            "fetch_emails.mjs": fetch_payload,
            "find_thread.mjs": {"found": True, "threadId": "t9",
                                "messageIdHeader": "<mid-t9@mail>", "referencesHeader": ""},
            "create_draft.mjs": {"draftId": "draft-x"},
            "create_event.mjs": {"htmlLink": "https://cal/evt1", "id": "evt1"},
        },
    )
    daemon_loop.process_all()
    assert_golden("process_once_end_to_end",
                  record(rec, final_state=store.load()))
