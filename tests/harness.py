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

import contextlib
import datetime as _dt
import json
import os
import threading
from collections import deque
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

from backend.masking import pseudonymizer

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


# --- the co-signer, actually running --------------------------------------

@contextlib.contextmanager
def running_cosigner(tmp_path, monkeypatch):
    """The real co-signer on a real loopback socket: fresh keys, fresh audit
    log, attestation off, operator alerts collected instead of sent.

    One arrangement of the second box, used both by its own tests and by the
    split-custody integration test. Two arrangements is how this design already
    failed once: each half faked the other above the wire, both suites passed,
    and the halves could not talk to each other in production
    (docs/plan_token_custody.md §J8)."""
    from cosigner import attest
    from cosigner import audit
    from cosigner import keys
    from cosigner import policy
    from cosigner import server

    monkeypatch.setenv("COSIGNER_ATTESTATION", attest.DEV_INSECURE)
    monkeypatch.delenv("TEE_REQUIRED", raising=False)
    monkeypatch.delenv("COSIGNER_DISABLED", raising=False)
    monkeypatch.setenv("COSIGNER_STATE_DIR", str(tmp_path / "state"))
    keys.reset_for_test(keys.write_dev_credentials(tmp_path / "creds"))
    audit.reset_for_test(tmp_path / "state")
    attest.reset_for_test()
    monkeypatch.setattr(policy, "_LAST_ALERT", {})
    alerts = []
    monkeypatch.setattr(policy.alerts, "notify_operator", lambda text: alerts.append(text))

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield SimpleNamespace(
            base=f"http://127.0.0.1:{httpd.server_address[1]}", alerts=alerts,
        )
    finally:
        httpd.shutdown()
        audit.reset_for_test()


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


# --- masking mode ---------------------------------------------------------

def without_analyzer(identity):
    """The same identity with the Presidio/spaCy path switched off.

    The goldens pin one masking mode, and it is this one, because it is the
    mode that ships: the analyzer pins are commented out of requirements.txt
    and the enclave image inherits that default. Left to `analyzer_available()`
    the recorded prompts would depend on which packages happen to be installed
    on the machine running pytest -- a developer with the model downloaded got
    [PERSON1_FIRST], a clean checkout got the name in the clear, and the same
    commit failed ten characterization tests on one box and passed on another.

    What the two modes each catch is asserted in test_masking_recall.py, which
    evaluates both paths against the corpus. That is the single place the
    question belongs; here it would only make the goldens unstable."""
    return pseudonymizer.UserIdentity(
        identity.first,
        identity.last,
        first_aliases=identity.first_aliases,
        emails=identity.emails,
        phones=identity.phones,
        contacts=identity.contacts,
        account_id=identity.account_id,
        analyzer=False,
    )


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
