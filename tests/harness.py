"""Hermetic test harness: fakes for every external boundary + golden compare.

Boundaries mocked (single choke points):
- LLM: llm_client.OpenAI -> FakeOpenAI. Its .chat.completions.create records the
  (already-pseudonymized) messages it receives -- this recording IS the payload
  that would leave the box to the LLM / LangSmith -- and returns scripted responses.
- Node: subprocess.run -> records (script, args, stdin) and returns canned JSON.
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
        self.node_calls = []
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


# --- subprocess fake ------------------------------------------------------

def _decode_stdin(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode()
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


def make_fake_run(rec, node_outputs, real_run):
    def _run(cmd, *args, input=None, stdout=None, stderr=None,
             capture_output=False, text=False, timeout=None, **kwargs):
        if not cmd or cmd[0] != "node":
            return real_run(cmd, *args, input=input, stdout=stdout, stderr=stderr,
                            capture_output=capture_output, text=text,
                            timeout=timeout, **kwargs)
        script = Path(cmd[1]).name
        rec.node_calls.append({
            "script": script,
            "args": list(cmd[2:]),
            "stdin": _decode_stdin(input),
        })
        out = node_outputs.get(script)
        if callable(out):
            out = out(list(cmd[2:]), _decode_stdin(input))
        assert out is not None, f"no node_output configured for {script}"
        payload = json.dumps(out)
        want_text = bool(capture_output or text)
        return SimpleNamespace(
            returncode=0,
            stdout=payload if want_text else payload.encode(),
            stderr="" if want_text else b"",
        )
    return _run


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
