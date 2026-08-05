"""The voice document is the whole instruction set: what the box shows is what
the drafter reads, and a rule the user deletes stops being enforced.

Unit-level (not golden) because these pin who decides a rule, not the outbound
payloads the golden tests already cover.
"""

from backend.drafting import agentic_drafter
from backend.drafting import voice_dna


def test_default_text_carries_the_constraints():
    text = voice_dna.default_text()
    assert voice_dna.CONSTRAINTS_HEADING in text
    assert agentic_drafter.dashes_banned(text)


def test_resolve_adds_nothing_to_a_saved_profile(wire, monkeypatch, tmp_path):
    path = tmp_path / "own-voice.md"
    path.write_text("## Voice\n\nWrite like me.\n")
    monkeypatch.setattr(wire.account, "voice_file", str(path))
    assert voice_dna.resolve(wire.account) == "## Voice\n\nWrite like me."


def test_with_constraints_does_not_double_up():
    once = voice_dna.with_constraints("## Voice\n\nWrite like me.")
    assert once.count(voice_dna.CONSTRAINTS_HEADING) == 1
    assert voice_dna.with_constraints(once) == once


def test_dashes_banned_follows_the_document():
    assert agentic_drafter.dashes_banned("- Do not use em-dashes or en-dashes.")
    assert agentic_drafter.dashes_banned("no em dash, please")
    assert not agentic_drafter.dashes_banned("## Voice\n\nWrite warmly.")


def test_draft_with_a_dash_is_kept_when_the_profile_allows_dashes(wire, monkeypatch):
    from backend.drafting import draft_replies

    monkeypatch.setattr(voice_dna, "DEFAULT_CONSTRAINTS",
                        "## Constraints\n\n- Never invent facts.")
    dash_body = "Hi Alice — lunch works.\n\nBest,\nMorgan"
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
        "to": "orgmanrivers@gmail.com",
        "date": "Mon, 20 Jul 2026 09:00:00 +0000",
        "subject": "Lunch next week?",
        "body": "Hi Morgan, want to grab lunch next week? Best, Alice Adams",
        "messageIdHeader": "<msg-e1@mail>",
        "referencesHeader": "",
    }
