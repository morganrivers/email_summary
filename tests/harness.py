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

import ast
import contextlib
import datetime as _dt
import hashlib
import json
import os
import re
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import identity_fixture

from backend.drafting import agentic_drafter
from backend.masking import pseudonymizer

REPO_ROOT = Path(__file__).parent.parent
SOURCE_PACKAGES = ("backend", "frontend", "cosigner", "tools")

GOLDEN_DIR = Path(__file__).parent / "golden"
FIXTURES_DIR = Path(__file__).parent / "fixtures"
VOICE_FIXTURE = FIXTURES_DIR / "voice.md"

# The identity of nobody the fixtures mention, for tests that mask text without
# going through an account. Anything it does not name is third party PII and must
# come back tagged, which is the property those tests assert.
NEUTRAL_IDENTITY = pseudonymizer.UserIdentity(
    first=identity_fixture.OTHER_FIRST,
    last=identity_fixture.OTHER_LAST,
    first_aliases=identity_fixture.OTHER_ALIASES,
    emails=[identity_fixture.OTHER_EMAIL],
    account_id="neutral",
    analyzer=False,
)

FROZEN_UTC = _dt.datetime(2026, 7, 21, 12, 0, 0)
FROZEN_DATE = _dt.date(2026, 7, 21)


class Recorder:
    def __init__(self):
        self.llm_calls = []
        self.gmail_calls = []
        self.telegram = []


# --- reading the tree instead of running it -------------------------------

# Some invariants are about what the code may not contain rather than about
# what it does, and a test that greps text fails on the prose describing the
# rule. These read the AST, and they live here because more than one boundary
# is guarded this way (the LLM endpoint, the calendar writes).

def python_sources(packages=SOURCE_PACKAGES):
    for top in packages:
        for path in sorted((REPO_ROOT / top).rglob("*.py")):
            if "__pycache__" not in path.parts:
                yield path


def attribute_chains(path, through_calls=False):
    """Every dotted attribute access in a file, as `a.b.c` strings.

    `through_calls` descends through an intervening call, so the builder style
    Google's client uses (`calendar(account).events().insert`) flattens to
    `calendar.events.insert` and can be matched as one chain."""
    for node in ast.walk(ast.parse(path.read_text())):
        if not isinstance(node, ast.Attribute):
            continue
        parts = [node.attr]
        current = node.value
        while True:
            if isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            elif through_calls and isinstance(current, ast.Call):
                current = current.func
            else:
                break
        if isinstance(current, ast.Name):
            parts.append(current.id)
        yield ".".join(reversed(parts))


def relative(path):
    return str(path.relative_to(REPO_ROOT))


# --- the account manifest -------------------------------------------------

def handle_for(email):
    """A stable fixture handle for an address.

    Real handles are random and stored (`account.new_handle`). These are derived
    so a test can name one without reading the manifest back, which is a
    property of the fixture and not of the product: derive them in `backend/`
    and the co-signer's log becomes invertible by anyone who guesses the
    scheme."""
    digest = hashlib.sha256(f"fixture-handle|{email}".encode()).hexdigest()
    return digest[:32]


def account_entry(email, status="active", polar_customer_id=None, emails=None,
                  telegram=True, **extra):
    """One manifest row, named by address and carrying nobody's real identity.

    `telegram=False` is the account with no linked chat, which is a state the
    manifest genuinely holds (a user who signed up and never ran /link) and the
    one the summary sweep has to skip rather than crash on."""
    entry = {
        "id": email,
        # Every registered account has one, so every fixture row does too. A row
        # without a handle is an account whose data key cannot be named and
        # whose own documents therefore cannot be opened; deriving it from the
        # address keeps these rows readable while still being a value the
        # co-signer cannot invert.
        "handle": handle_for(email),
        "identity": {"first": "A", "last": "B",
                     "emails": emails if emails is not None else [email]},
        "plan_status": status,
    }
    if telegram:
        entry["telegram"] = {"chat_id": f"chat-{email}", "token": "t"}
    if polar_customer_id:
        entry["polar_customer_id"] = polar_customer_id
    entry.update(extra)
    return entry


def write_manifest(tmp_path, entries):
    """Write a manifest and return its path. Callers point account.MANIFEST at
    it; the tests that also write into it point ACCOUNTS_DIR at its parent."""
    path = tmp_path / "accounts.json"
    path.write_text(json.dumps({"accounts": entries}))
    return path


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
    ("backend.integrations.gmail_gcal.calendar_api", "write_calendar_audience"),
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


# --- custody, for tests that only need it to work -------------------------

@contextlib.contextmanager
def custody_available(tmp_path, monkeypatch):
    """An enclave key and a co-signer that answers, in process.

    For the suites whose subject is something else. Since Track G every
    per-account document is encrypted under that account's data key, so a test
    that saves a voice profile or a personal context now needs both halves of
    custody present -- which is the point of the change, and a poor thing to
    restate in four fixtures.

    Not a substitute for the real thing: `running_cosigner` is what the custody
    suites use, because a fake above the wire is exactly what let the two halves
    disagree about base64 while both suites passed."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from backend.custody import client as cosigner
    from backend.custody import keyring, wrapping
    from cosigner import protocol

    monkeypatch.setenv(wrapping.DEV_SECRET_ENV, "harness-app-secret-0123456789")
    monkeypatch.delenv("TEE_REQUIRED", raising=False)
    monkeypatch.setattr(wrapping, "_app_secret_cache", None)

    key = b"\x22" * 32
    wrapped = set()

    def serve(method, path, body=None):
        body = body or {}
        handle = body.get(protocol.F_UID)
        if path == protocol.WRAP_PATH:
            assert handle not in wrapped, "a second wrap for one handle must be refused"
            wrapped.add(handle)
            inner = protocol.unb64(body[protocol.F_INNER])
            nonce = os.urandom(12)
            return {protocol.F_OUTER: protocol.b64(
                nonce + AESGCM(key).encrypt(nonce, inner, handle.encode()))}
        if path in (protocol.UNWRAP_PATH, protocol.UNWRAP_AND_SIGN_PATH):
            outer = protocol.unb64(body[protocol.F_OUTER])
            inner = AESGCM(key).decrypt(
                bytes(outer[:12]), bytes(outer[12:]), handle.encode())
            answer = {protocol.F_INNER: protocol.b64(inner)}
            if path == protocol.UNWRAP_AND_SIGN_PATH:
                answer[protocol.F_PROOF] = "proof.harness"
            return answer
        raise AssertionError(f"harness co-signer has no route for {path}")

    monkeypatch.setattr(cosigner, "_request", serve)
    keyring.forget()
    try:
        yield
    finally:
        keyring.forget()
        monkeypatch.setattr(wrapping, "_app_secret_cache", None)


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
    from cosigner import attest, audit, keys, policy, server

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

_FENCE_NONCE = re.compile(
    re.escape(agentic_drafter.FENCE_PREFIX) + r"([A-Z][A-Z0-9]{15})"
)


def stable_fence_nonces(text):
    """Each fence nonce replaced by a stable placeholder.

    A nonce is fresh randomness per model conversation, which is the whole point
    of it: nothing an attacker reads in the source predicts it. It also means a
    recorded prompt can never equal a file, so the goldens pin the fence's shape
    rather than its value.

    Distinct nonces keep distinct placeholders, and only a nonce found behind an
    opening marker is renamed at all. A rule that named a nonce the content did
    not carry would keep its random value here and fail the compare, which is
    the property worth keeping: the pairing is what the fence is."""
    seen = {}
    for nonce in _FENCE_NONCE.findall(text):
        seen.setdefault(nonce, f"FENCENONCE{len(seen) + 1:04d}")
    for nonce, label in seen.items():
        text = text.replace(nonce, label)
    return text


def assert_golden(name, record):
    GOLDEN_DIR.mkdir(exist_ok=True)
    path = GOLDEN_DIR / f"{name}.json"
    data = stable_fence_nonces(json.dumps(record, indent=2, ensure_ascii=False))
    if os.environ.get("UPDATE_GOLDEN"):
        path.write_text(data + "\n")
        return
    assert path.exists(), f"golden missing: {path.name} (run with UPDATE_GOLDEN=1)"
    expected = path.read_text().rstrip("\n")
    assert data == expected, (
        f"golden mismatch for {name}\n--- expected ---\n{expected}\n--- got ---\n{data}"
    )
