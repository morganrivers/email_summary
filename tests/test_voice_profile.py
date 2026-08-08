"""The documents the drafter is given, and who decides each rule in them: the
voice document is what the box shows, the personal information document is the
owner's own facts, and the dash ban is a Settings switch rather than prose.

Unit-level (not golden) because these pin who decides a rule, not the outbound
payloads the golden tests already cover.
"""

from identity_fixture import OWNER_ALT_EMAIL, OWNER_FIRST

from backend.drafting import agentic_drafter
from backend.drafting import draft_replies
from backend.drafting import personal_context
from backend.drafting import voice_dna


def test_default_text_carries_the_constraints():
    text = voice_dna.default_text()
    assert voice_dna.CONSTRAINTS_HEADING in text


def test_resolve_adds_nothing_to_a_saved_profile(wire, monkeypatch, tmp_path):
    path = tmp_path / "own-voice.md"
    path.write_text("## Voice\n\nWrite like me.\n")
    monkeypatch.setattr(wire.account, "voice_file", str(path))
    assert voice_dna.resolve(wire.account) == "## Voice\n\nWrite like me."


def test_with_constraints_does_not_double_up():
    once = voice_dna.with_constraints("## Voice\n\nWrite like me.")
    assert once.count(voice_dna.CONSTRAINTS_HEADING) == 1
    assert voice_dna.with_constraints(once) == once


def test_dashes_banned_follows_the_setting_not_the_document(wire):
    assert agentic_drafter.dashes_banned(wire.account)
    wire.account.ban_dashes = False
    assert not agentic_drafter.dashes_banned(wire.account)
    wire.account.voice_file = None
    assert "em-dash" not in draft_replies.drafting_instructions(wire.account)


def test_personal_information_reaches_the_drafter_and_survives_clearing(wire):
    assert personal_context.section(wire.account) == ""
    personal_context.save(wire.account, "I take calls on Tuesdays.")
    instructions = draft_replies.drafting_instructions(wire.account)
    assert personal_context.CONTEXT_HEADING in instructions
    assert "I take calls on Tuesdays." in instructions
    personal_context.save(wire.account, "   ")
    assert personal_context.load(wire.account) == ""
    assert personal_context.CONTEXT_HEADING not in \
        draft_replies.drafting_instructions(wire.account)


def test_personal_information_over_the_limit_is_refused(wire):
    import pytest

    with pytest.raises(personal_context.ContextError):
        personal_context.save(wire.account,
                              "x" * (personal_context.MAX_CONTEXT_CHARS + 1))
    assert personal_context.load(wire.account) == ""


def test_draft_with_a_dash_is_kept_when_the_setting_is_off(wire, monkeypatch):
    wire.account.ban_dashes = False
    dash_body = f"Hi Alice — lunch works.\n\nBest,\n{OWNER_FIRST}"
    rec = wire.install(
        responses=[
            {"content": '{"decisions": [{"index": 0, "needs_reply": true, '
                        '"reason": "Personal"}]}'},
            {"content": dash_body},
        ],
        gmail_outputs={"submit": "draft-1"},
    )
    drafted = draft_replies.process_emails(wire.account, [_auto_email()])
    assert len(drafted) == 1, "a dashed draft was rejected by a rule the profile does not state"
    assert len(rec.llm_calls) == 2, "the drafter retried a dash it was never told to avoid"
    assert not any("rejected" in (msg or "") for msg in rec.telegram)
    system_prompt = rec.llm_calls[1]["messages"][0]["content"]
    assert "PUNCTUATION RULE" not in system_prompt


def _auto_email():
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
