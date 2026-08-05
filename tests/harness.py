"""Hermetic test harness: fakes for every external boundary + golden compare.

Boundaries mocked (single choke points):
- LLM: llm_client.OpenAI -> FakeOpenAI. Its .chat.completions.create records the
  (already-pseudonymized) messages it receives -- this recording IS the payload
  that would leave the box to the LLM / LangSmith -- and returns scripted responses.
- Google: the operation functions listed in GMAIL_OPS -> record (op, account,
  arguments) and return canned results. This is the same seam the Node
  subprocess fake used to stand at; the calls happen in process now, so the fake
  is applied to the functions rather than to subprocess.run.
- Telegram: requests.post -> records the message text.

Time is frozen so masked prompts carrying a timestamp stay stable.
"""

import datetime as _dt
import json
import os
from collections import deque
from pathlib import Path
from types import SimpleNamespace

GOLDEN_DIR = Path(__file__).parent / "golden"
FIXTURES_DIR = Path(__file__).parent / "fixtures"
VOICE_FIXTURE = FIXTURES_DIR / "voice.md"

FROZEN_UTC = _dt.datetime(2026, 7, 21, 12, 0, 0)
FROZEN_DATE = _dt.date(2026, 7, 21)


class Recorder:
    def __init__(self):
        self.llm_calls = []
        self.gmail_calls = []
        self.telegram = []


# --- LLM fake -------------------------------------------------------------

def _make_message(spec):
    tool_calls = None
    if spec.get("tool_calls"):
        tool_calls = []
        for i, tc in enumerate(spec["tool_calls"]):
            tool_calls.append(SimpleNamespace(
                id=tc.get("id", f"call_{i}"),
                type="function",
                function=SimpleNamespace(name=tc["name"], arguments=tc["arguments"]),
            ))
    return SimpleNamespace(
        content=spec.get("content", ""),
        tool_calls=tool_calls,
        reasoning_content=spec.get("reasoning_content"),
    )


def _make_response(spec):
    finish = "tool_calls" if spec.get("tool_calls") else "stop"
    return SimpleNamespace(choices=[SimpleNamespace(
        message=_make_message(spec),
        finish_reason=finish,
    )])


class _Completions:
    def __init__(self, rec, responses):
        self._rec = rec
        self._responses = responses

    def create(self, **kwargs):
        self._rec.llm_calls.append({
            "model": kwargs.get("model"),
            "max_tokens": kwargs.get("max_tokens"),
            "response_format": kwargs.get("response_format"),
            "has_tools": bool(kwargs.get("tools")),
            "tool_choice": kwargs.get("tool_choice"),
            "messages": kwargs.get("messages"),
        })
        assert self._responses, "no scripted LLM response left for create()"
        return _make_response(self._responses.popleft())


class FakeOpenAI:
    def __init__(self, rec, responses):
        self.chat = SimpleNamespace(completions=_Completions(rec, responses))


# --- Google fake ----------------------------------------------------------

# Every function in the app that reaches Google, named once. A new call into
# Gmail or Calendar that is not in this list is a call the tests cannot see, so
# adding one here is part of adding one there.
GMAIL_OPS = (
    ("backend.integrations.gmail_gcal.mailbox", "fetch_since_history"),
    ("backend.integrations.gmail_gcal.mailbox", "fetch_daily"),
    ("backend.integrations.gmail_gcal.drafts", "submit"),
    ("backend.integrations.gmail_gcal.gmail_api", "search_messages"),
    ("backend.integrations.gmail_gcal.gmail_api", "get_thread"),
    ("backend.integrations.gmail_gcal.gmail_api", "find_thread_by_from_subject"),
    ("backend.integrations.gmail_gcal.gmail_api", "register_watch"),
    ("backend.integrations.gmail_gcal.calendar_api", "list_events"),
    ("backend.integrations.gmail_gcal.calendar_api", "create_event"),
)


def _record_call(op, args, kwargs):
    """One Google call, in a form a golden file can hold. The account is
    recorded by id: which mailbox a call went to is exactly what the
    multi-tenant bugs were about, and an object repr would not survive a
    rerun."""
    call = {"op": op}
    if args and hasattr(args[0], "id"):
        call["account"] = args[0].id
        args = args[1:]
    if args:
        call["args"] = list(args)
    # A default-valued keyword (draft_id=None on a first draft) is the absence
    # of a choice, not a choice; recording it would make every golden carry the
    # signature rather than the call.
    named = {k: v for k, v in kwargs.items() if v is not None}
    if named:
        call["kwargs"] = named
    return call


def install_gmail_fakes(monkeypatch, rec, outputs):
    """Patch every Google boundary. `outputs` maps an op name to its result, or
    to a callable taking the recorded call."""
    import importlib

    for module_name, attr in GMAIL_OPS:
        module = importlib.import_module(module_name)

        def fake(*args, _op=attr, **kwargs):
            call = _record_call(_op, args, kwargs)
            rec.gmail_calls.append(call)
            out = outputs.get(_op)
            if callable(out):
                out = out(call)
            assert out is not None, f"no gmail output configured for {_op}"
            return out

        monkeypatch.setattr(module, attr, fake)


# --- telegram fake --------------------------------------------------------

def make_fake_post(rec):
    def _post(url, json=None, timeout=None, **kwargs):
        rec.telegram.append(json.get("text") if json else None)
        return SimpleNamespace(raise_for_status=lambda: None,
                               json=lambda: {"ok": True})
    return _post


# --- frozen time ----------------------------------------------------------

class FrozenDateTime(_dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(FROZEN_UTC.year, FROZEN_UTC.month, FROZEN_UTC.day,
                   FROZEN_UTC.hour, FROZEN_UTC.minute, FROZEN_UTC.second, tzinfo=tz)


class FrozenDate(_dt.date):
    @classmethod
    def today(cls):
        return cls(FROZEN_DATE.year, FROZEN_DATE.month, FROZEN_DATE.day)


def frozen_datetime_namespace():
    return SimpleNamespace(date=FrozenDate, datetime=_dt.datetime, timedelta=_dt.timedelta)


# --- golden compare -------------------------------------------------------

def assert_golden(name, record):
    GOLDEN_DIR.mkdir(exist_ok=True)
    path = GOLDEN_DIR / f"{name}.json"
    data = json.dumps(record, indent=2, ensure_ascii=False)
    if os.environ.get("UPDATE_GOLDEN"):
        path.write_text(data + "\n")
        return
    assert path.exists(), f"golden missing: {path.name} (run with UPDATE_GOLDEN=1)"
    expected = path.read_text().rstrip("\n")
    assert data == expected, (
        f"golden mismatch for {name}\n--- expected ---\n{expected}\n--- got ---\n{data}"
    )
