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
from harness import account_entry, python_sources, relative, write_manifest

from backend import paths
from backend.accounts import account as account_mod
from backend.accounts import chat_link
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
#
# The last four are the billing surface. `PolarBilling` holds an
# organization-wide API token that reads every customer in the org and mints a
# portal session for any customer id, so it is a wider credential than anything
# else the web tier ever touched -- wider than the residual this split leaves it
# (its own settings, its own plan). The three calls that needed it cross over
# the handoff socket to the role that already writes `plan_status`.
FORBIDDEN_CALLS = (
    "take_custody", "release_for_refresh", "open_key", "dek_for",
    "handle_callback", "exchange_code", "provision", "build_auth_url",
    "set_telegram", "force_unlink",
    "PolarBilling", "checkout_redirect", "confirm_checkout", "portal_url",
)

# The handoff client deliberately names its functions after the operations they
# stand in for, so `handoff.confirm_checkout(...)` reads as the same operation
# the daemon performs. That is the point of the module and not a violation of
# the rule above, so a call reached through it is exempt -- and only through it,
# by the attribute's own name, so an alias binding `handoff = billing` would not
# pass.
HANDOFF = "handoff"

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
            if isinstance(func, ast.Attribute):
                name = func.attr
                if isinstance(func.value, ast.Name) and func.value.id == HANDOFF:
                    continue
            else:
                name = getattr(func, "id", None)
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


def test_the_callee_checks_the_type_of_the_browser_answer():
    """`state_ok` becomes `if not state_ok(state)` in `handle_callback`, so any
    truthy JSON value passes the browser check -- the string "false" among them.
    The client asserts it too, but the callee must not trust the caller's type
    discipline: that is the wrong side of the boundary."""
    for bad in ("false", 1, {}, None):
        reply = handoff_server.dispatch(
            {handoff.F_OP: handoff.OP_SIGN_IN,
             handoff.F_ARGS: {"query": {"code": "c", "state": "s"},
                              "state_ok": bad, "redirect_uri": "https://x/cb"}},
            lambda _msg: None,
        )
        assert reply[handoff.F_ERROR][handoff.F_CODE] == 500, bad
        assert "state_ok" not in reply[handoff.F_ERROR][handoff.F_MSG]


def test_only_a_vetted_refusal_reaches_the_browser_unaltered(listening, monkeypatch):
    """`handoff.RENDERABLE_CODE` is the one status whose message the web tier
    renders as it stands. Everything else was written for the daemon's journal:
    a `ProvisionError` carries whatever Google put in the callback's `error`
    parameter, a plain refusal names the account."""
    from frontend import web_server

    vetted = handoff.RemoteRefusal(handoff.RENDERABLE_CODE,
                                   chat_link.CODE_EXPIRED)
    assert web_server._refusal(vetted) == chat_link.CODE_EXPIRED

    leaky = handoff.RemoteRefusal(403, "consent denied for victim@example.com")
    assert "victim@example.com" not in web_server._refusal(leaky)


class _FakePolar:
    """Stands in for the client holding the organization-wide Polar token,
    which the web tier no longer has and this process now does."""

    def __init__(self):
        self.seen = []

    def confirm_checkout(self, checkout_id, acct):
        self.seen.append((checkout_id, acct.id))
        return True, f"account={acct.id} inactive->active"

    def portal_url(self, acct):
        self.seen.append(acct.id)
        return f"https://polar.example/portal/{acct.id}"


@pytest.fixture
def one_lapsed_account(tmp_path, monkeypatch):
    monkeypatch.setattr(account_mod, "MANIFEST", write_manifest(
        tmp_path, [account_entry("dan@x.com", status="inactive")]))


def test_the_billing_operations_serve_an_account_that_is_not_active(
        listening, one_lapsed_account, monkeypatch):
    """Everyone reaching checkout is inactive by definition, and a lapsed
    subscriber returning to the portal is the other half of the same case, so
    these three do not go through the active-only lookup the rest use."""
    polar = _FakePolar()
    monkeypatch.setattr(handoff_server, "_polar", lambda: polar)
    monkeypatch.setattr(handoff_server.billing, "checkout_url",
                        lambda email, fallback: (f"https://polar.example/buy/{email}",
                                                 "co_new"))

    assert handoff.checkout_url("dan@x.com", fallback="") == \
        ("https://polar.example/buy/dan@x.com", "co_new")
    assert handoff.confirm_checkout("dan@x.com", "co_1") == \
        (True, "account=dan@x.com inactive->active")
    assert handoff.portal_url("dan@x.com") == "https://polar.example/portal/dan@x.com"
    assert polar.seen == [("co_1", "dan@x.com"), "dan@x.com"]


@pytest.mark.parametrize("ask", [
    lambda: handoff.checkout_url("nobody@x.com", fallback=""),
    lambda: handoff.confirm_checkout("nobody@x.com", "co_1"),
    lambda: handoff.portal_url("nobody@x.com"),
])
def test_a_billing_operation_names_an_account_or_is_refused(
        listening, one_lapsed_account, monkeypatch, ask):
    """This socket does not authenticate the end user -- the web tier is what
    decides who is signed in -- so the account id is taken as an argument. What
    it does not do is act on a name that is not an account, which is what would
    otherwise mint a checkout against an arbitrary string."""
    monkeypatch.setattr(handoff_server, "_polar", lambda: _FakePolar())
    with pytest.raises(handoff.RemoteRefusal) as err:
        ask()
    assert err.value.code == 404


def test_an_unconfigured_polar_is_an_outage_and_not_a_crash(
        listening, one_lapsed_account, monkeypatch):
    """A box with no Polar token renders "billing is unavailable right now",
    the same page a daemon that is down produces."""
    monkeypatch.setattr(handoff_server, "_polar_client", None)
    monkeypatch.delenv("POLAR_API_TOKEN", raising=False)
    monkeypatch.delenv("POLAR_ORGANIZATION_ID", raising=False)

    with pytest.raises(handoff.RemoteRefusal) as err:
        handoff.portal_url("dan@x.com")
    assert err.value.code == 503


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


def test_a_peer_that_is_neither_account_is_refused(listening, monkeypatch):
    """The socket's mode is the grant and this is a second check of it.

    Every way the mode can widen is silent: `paths.file_mode()` reads a group
    that may not exist, the group itself comes from a setgid bit on `state/`
    that a future change could drop, and `chmod_if_owned` does nothing at all
    when the file belongs to somebody else. The operations behind this socket
    mint consent URLs and exchange authorization codes, so the listener asks
    the kernel who is actually connected rather than inferring it from a mode
    it cannot re-check."""
    monkeypatch.setattr(paths, "web_uid", lambda: 4242)
    monkeypatch.setattr(handoff_server.os, "getuid", lambda: 4243)

    with pytest.raises(handoff.HandoffUnavailable):
        handoff.voice_status("a@example.com")

    assert any("refused connection" in line for line in listening), listening


def test_the_web_uid_is_admitted(listening, monkeypatch):
    """The other direction, so the check cannot pass by refusing everyone.

    The real uid is read before `getuid` is patched, so the peer is admitted by
    the `web_uid()` branch rather than by matching our own."""
    real = handoff_server.os.getuid()
    monkeypatch.setattr(handoff_server.os, "getuid", lambda: real + 1)
    monkeypatch.setattr(paths, "web_uid", lambda: real)
    monkeypatch.setitem(handoff_server.HANDLERS, handoff.OP_VOICE_STATUS,
                        lambda account_id: {"state": "done"})

    assert handoff.voice_status("a@example.com") == {"state": "done"}


def test_an_unreadable_peer_is_refused_rather_than_assumed(listening, monkeypatch):
    """SO_PEERCRED failing is not an unknown to be resolved generously."""
    monkeypatch.setattr(handoff_server, "_peer", lambda conn: (-1, -1, -1))

    with pytest.raises(handoff.HandoffUnavailable):
        handoff.voice_status("a@example.com")


def test_providers_crosses_as_names_and_never_as_a_key(listening, monkeypatch):
    """The web tier held two live inference keys to answer one yes/no question.

    What comes back is catalog keys, which are public strings; the labels are
    rendered from the web tier's own copy of the catalog, so nothing derived
    from an API key is on this wire."""
    from backend.integrations import llm_client

    monkeypatch.setattr(llm_client, "available_provider_names",
                        lambda: ["deepseek", "nearai-glm"])
    handoff._providers_cache = None
    try:
        assert handoff.providers() == ("deepseek", "nearai-glm")
    finally:
        handoff._providers_cache = None


def test_providers_is_cached_for_the_process(listening, monkeypatch):
    """A key arrives as injected environment or in .env and neither changes
    under a running process, so the answer can only move across a restart. The
    settings page is loaded by every signed-in user; one round trip per render
    would be a round trip that cannot return anything new."""
    calls = []

    def once():
        calls.append(1)
        return ["deepseek"]

    from backend.integrations import llm_client
    monkeypatch.setattr(llm_client, "available_provider_names", once)
    handoff._providers_cache = None
    try:
        handoff.providers()
        handoff.providers()
        assert calls == [1]
    finally:
        handoff._providers_cache = None


def test_an_unavailable_daemon_is_not_cached_as_an_empty_answer(tmp_path, monkeypatch):
    """Caching an outage would render the settings page as though this
    deployment had no provider configured, and keep doing so after the daemon
    came back."""
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path / "state")
    handoff._providers_cache = None
    try:
        with pytest.raises(handoff.HandoffUnavailable):
            handoff.providers()
        assert handoff._providers_cache is None
    finally:
        handoff._providers_cache = None
