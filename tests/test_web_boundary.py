"""What the web tier may do, now that it is not the mail units' uid.

`frontend/web_server.py` parses HTTP from the open internet. While it ran as
`letterlock` it could read every account's `database/<id>/` and ask the
co-signer to unwrap any of them, so a parsing bug there was every mailbox.

Two things make the split more than a change of file owner, and both are easy
to undo by accident:

  * `token.bin` is the one file written mail-uid-only, because the data key the
    web tier legitimately holds to render a document would open it. A second
    caller passing `shared=False`, or `take_custody` losing it, puts the token
    back within reach with nothing failing.
  * The code exchange and the consent URL happen over `custody.handoff`. A
    future handler that calls `provisioning` directly from a request path is a
    web process holding a refresh token again, and it would work perfectly.

So both are read out of the tree rather than trusted to review, in the style of
`tests/test_calendar_boundary.py` and `tests/test_handle_boundary.py`.
"""

import ast
import socket
import threading
import time

import pytest
from harness import python_sources, relative

from backend import paths
from backend.custody import handoff, handoff_server
from backend.onboarding import provisioning

# Nothing under frontend/ may reach the modules that open key material. The web
# tier gets a data key through the document helpers (`voice_dna.load`,
# `personal_context.load`), which is the metered path; it has no business
# holding one itself.
#
# `chat_link` is here for a different reason and belongs on the same list. It
# holds no key, but it decides who may move an account's Telegram target, and
# `force_unlink` performs that change with no proof at all. A web tier that
# imports it can call the bypass in-process, which is the whole rule undone.
FORBIDDEN_MODULES = ("keyring", "tokens", "wrapping", "chat_link")

# Named functions it may not call whatever module they arrive from. `provision`,
# `exchange_code` and `handle_callback` are the code exchange; `build_auth_url`
# reads the OAuth client secret's file; `generate` and `start` read sent mail;
# `set_telegram` and `force_unlink` write the delivery target that carries mail.
FORBIDDEN_CALLS = (
    "take_custody", "release_for_refresh", "open_key", "dek_for",
    "handle_callback", "exchange_code", "provision", "build_auth_url",
    "set_telegram", "force_unlink",
)

WEB_SOURCES = [p for p in python_sources() if p.parts[-2] == "frontend"]


def test_the_web_tier_has_sources_to_check():
    assert WEB_SOURCES, "found no frontend/ sources; the scan below proves nothing"


def _imported_names(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                yield alias.asname or alias.name, node.lineno
        elif isinstance(node, ast.Import):
            for alias in node.names:
                yield (alias.asname or alias.name).split(".")[0], node.lineno


def test_the_web_tier_imports_no_custody_module():
    offenders = []
    for path in WEB_SOURCES:
        tree = ast.parse(path.read_text())
        for name, line in _imported_names(tree):
            if name in FORBIDDEN_MODULES:
                offenders.append(f"{relative(path)}:{line} imports {name}")
    assert not offenders, (
        "the web tier may not import key material modules; go through "
        "backend/custody/handoff.py:\n" + "\n".join(offenders)
    )


def test_the_web_tier_calls_nothing_that_needs_a_mailbox_token():
    offenders = []
    for path in WEB_SOURCES:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name in FORBIDDEN_CALLS:
                offenders.append(f"{relative(path)}:{node.lineno} calls {name}()")
    assert not offenders, (
        "these run in the daemon over the handoff socket, not in the process "
        "parsing HTTP:\n" + "\n".join(offenders)
    )


def _private_writes(path):
    """Calls passing `shared=False`, which is the mail-uid-only file mode."""
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg == "shared" and isinstance(kw.value, ast.Constant) \
                    and kw.value.value is False:
                yield node.lineno


def test_the_refresh_token_is_the_only_file_the_web_tier_cannot_read():
    """One caller, and it is the token.

    Not a style rule. Every file written `shared=True` is one the web tier can
    read, and it holds the account's data key while a page renders, so the set
    of files it cannot open is exactly the set written by this branch."""
    writers = {relative(p): sorted(_private_writes(p)) for p in python_sources()}
    writers = {k: v for k, v in writers.items() if v}
    assert set(writers) == {"backend/custody/tokens.py"}, (
        f"unexpected mail-uid-only writes: {writers}"
    )


def test_take_custody_still_asks_for_the_private_mode():
    """The property above is worth nothing if the one call stops passing it."""
    source = (paths.REPO_ROOT / "backend/custody/tokens.py").read_text()
    assert "shared=False" in source, (
        "tokens.take_custody must write token.bin mail-uid-only; without it the "
        "web tier reads the wrapped token and opens it with the data key it "
        "already has"
    )


def test_file_mode_falls_back_to_owner_only(monkeypatch):
    """No shared group means no widening, which is what lets this code land
    before the deploy that creates the group."""
    monkeypatch.setattr(paths, "data_gid", lambda: None)
    assert paths.file_mode() == paths.FILE_MODE_PRIVATE
    assert paths.file_mode(shared=False) == paths.FILE_MODE_PRIVATE
    monkeypatch.setattr(paths, "data_gid", lambda: 4242)
    assert paths.file_mode() == paths.FILE_MODE_SHARED
    assert paths.file_mode(shared=False) == paths.FILE_MODE_PRIVATE


def test_every_operation_has_exactly_one_handler():
    assert set(handoff_server.HANDLERS) == set(handoff.OPS)


# --- the channel itself ---------------------------------------------------

@pytest.fixture
def listening(tmp_path, monkeypatch):
    """A handoff server on a socket of its own, torn down with the test."""
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path / "state")
    lines = []
    srv = handoff_server.bind(lines.append)

    def accept_loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            handoff_server._serve_one(conn, lines.append)

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    yield lines
    srv.close()


def test_round_trip(listening, monkeypatch):
    monkeypatch.setitem(handoff_server.HANDLERS, handoff.OP_VOICE_STATUS,
                        lambda account_id: {"state": "done", "who": account_id})
    assert handoff.voice_status("a@example.com") == {"state": "done", "who": "a@example.com"}


def test_a_refusal_keeps_its_status_code(listening, monkeypatch):
    def refuse(account_id):
        raise provisioning.ProvisionError(403, "consent denied")

    monkeypatch.setitem(handoff_server.HANDLERS, handoff.OP_VOICE_STATUS, refuse)
    with pytest.raises(handoff.RemoteRefusal) as err:
        handoff.voice_status("a@example.com")
    assert err.value.code == 403
    assert err.value.msg == "consent denied"


def test_an_unexpected_failure_does_not_leak_its_detail(listening, monkeypatch):
    def explode(account_id):
        raise RuntimeError("refresh token abc123 could not be written")

    monkeypatch.setitem(handoff_server.HANDLERS, handoff.OP_VOICE_STATUS, explode)
    with pytest.raises(handoff.RemoteRefusal) as err:
        handoff.voice_status("a@example.com")
    assert err.value.code == 500
    assert "abc123" not in err.value.msg


def test_no_listener_is_unavailable_and_not_a_refusal(tmp_path, monkeypatch):
    """The distinction the web tier renders: an outage is not a denied consent,
    and neither one may become a local fallback that does the work here."""
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path / "state")
    with pytest.raises(handoff.HandoffUnavailable):
        handoff.voice_status("a@example.com")


def test_a_stale_socket_file_is_replaced(tmp_path, monkeypatch):
    """A killed daemon leaves the path behind, and connect on it fails
    ECONNREFUSED rather than ENOENT, so bind has to unlink first."""
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path / "state")
    paths.ensure_run_dir()
    handoff.socket_path().write_bytes(b"")
    srv = handoff_server.bind(lambda _msg: None)
    try:
        assert handoff.socket_path().exists()
    finally:
        srv.close()


def test_the_socket_is_not_world_reachable(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path / "state")
    srv = handoff_server.bind(lambda _msg: None)
    try:
        mode = handoff.socket_path().stat().st_mode & 0o777
        assert mode in (paths.FILE_MODE_PRIVATE, paths.FILE_MODE_SHARED), oct(mode)
        assert not mode & 0o007, f"the handoff socket is reachable by others: {oct(mode)}"
    finally:
        srv.close()


def test_an_oversized_request_is_refused_rather_than_allocated(listening):
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(5)
    conn.connect(str(handoff.socket_path()))
    try:
        # No newline, so the reader never frames a message and must stop on the
        # bound instead of growing until the peer gives up.
        payload = b"x" * (handoff.MAX_BODY + 4096)
        try:
            conn.sendall(payload)
        except OSError:
            pass
        deadline = time.time() + 5
        while time.time() < deadline and conn.recv(1):
            pass
    finally:
        conn.close()
