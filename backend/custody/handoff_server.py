"""The listening half of `handoff`, running inside the mail daemon.

Started on a thread by `daemon_loop.main()` rather than as a unit of its own.
The property being bought is that the process which writes `token.bin` and reads
a mailbox is not the process parsing HTTP from the internet, and a thread in the
daemon satisfies that: it is the mail uid. A separate unit would buy a third
account and a third hard dependency for nothing this change needs.

It is a thread and not the daemon's own loop because that loop is serial on
purpose -- `process_accounts()` runs a full drafting pass before returning -- and
a user waiting on a sign-in must not wait for an LLM.

Each connection is answered on its own thread, so two sign-ins do not queue
behind one another, and one handler raising cannot take the listener down.
"""

from __future__ import annotations

import os
import socket
import struct
import sys
import threading
import traceback

from backend import paths
from backend.accounts import account as account_mod
from backend.accounts import chat_link
from backend.custody import handoff, tokens
from backend.drafting import voice_dna
from backend.integrations import llm_client
from backend.integrations.gmail_gcal import gmail_api, google_client
from backend.onboarding import provisioning

BACKLOG = 16


def _log(msg):
    """The listener and `dispatch` are handed a `log` per connection; a handler
    is not. The one that releases an account writes several lines and none of
    them belongs in the caller's reply, so it writes here. Underscored to stay
    distinct from that parameter."""
    sys.stderr.write(f"handoff_server {msg}\n")
    sys.stderr.flush()


def _peer(conn):
    """(pid, uid, gid) of the process at the other end.

    (-1, -1, -1) when the kernel will not say, which `_may_connect` reads as a
    refusal rather than as an unknown."""
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                              struct.calcsize("3i"))
        return struct.unpack("3i", raw)
    except OSError:
        return (-1, -1, -1)


def _may_connect(uid):
    """Whether a peer at `uid` is one of the two accounts this socket is for.

    The socket's mode is still the grant, and this is deliberately a second
    check of the same fact rather than a replacement for it. The mode is set by
    `bind()` from `paths.file_mode()`, which reads a group that may not exist
    and a setgid bit that a future change to `state/` could drop; every one of
    those failures widens the socket silently, and the operations behind it mint
    consent URLs and exchange authorization codes. Asking the kernel who is
    actually on the other end costs one getsockopt and turns that class of
    mistake into a refused connection.

    Two uids pass: our own, which is the mail account and also the laptop where
    one person runs both halves, and `paths.web_uid()`. Anything else, including
    root and including a kernel that declines to answer, is refused. Root being
    refused is not a security claim -- root can read this process's memory --
    it is that no correct caller is root."""
    if uid < 0:
        return False
    if uid == os.getuid():
        return True
    web = paths.web_uid()
    return web is not None and uid == web


def _account(account_id):
    acct = account_mod.get_account(account_id)
    if acct is None:
        raise handoff.RemoteRefusal(404, f"{account_id} is not an active account")
    return acct


def _auth_url(state, redirect_uri):
    return provisioning.build_auth_url(state, redirect_uri)


def _sign_in(query, state_ok, redirect_uri, fallback="/dashboard"):
    """The OAuth callback, whole. `handle_callback` stays the single decision
    path; what changed is which uid runs it.

    The browser check arrives as an answer because the cookie that produces it
    is the web tier's. Wrapping it in a predicate keeps `handle_callback`'s
    signature the one the tests already drive.

    The types are asserted on this side of the socket and not only on the
    client's. `state_ok` becomes `if not state_ok(state)` in `handle_callback`,
    so any truthy JSON value passes the browser check -- the string "false"
    among them. The web tier is the only permitted peer, so this is hardening
    rather than a live hole, but a callee that trusts its caller's type
    discipline is trusting the wrong side of a boundary."""
    assert isinstance(state_ok, bool), (
        f"state_ok crossed the socket as {type(state_ok).__name__}; anything "
        "but a bool is truthy and would pass the browser check"
    )
    assert isinstance(query, dict), (
        f"query crossed the socket as {type(query).__name__}, not an object"
    )
    acct, location = provisioning.handle_callback(
        query, lambda _state: state_ok, redirect_uri, fallback)
    return {"account_id": acct.id, "location": location}


def _voice_start(account_id):
    return voice_dna.start(_account(account_id))


def _voice_status(account_id):
    return voice_dna.status(account_id)


def _voice_clear(account_id):
    voice_dna.clear_status(account_id)
    return None


def _chat_begin(account_id):
    action, code, username = chat_link.begin(account_id)
    return {"action": action, "code": code, "username": username or ""}


def _chat_finish(account_id):
    acct = chat_link.finish(account_id)
    return acct.telegram.chat_id if acct.telegram else None


def _chat_forget(account_id):
    chat_link.forget(account_id)
    return None


def _account_forget(account_id):
    """Release everything this process holds for an account, and withdraw the
    Google grant while the key that reads it still exists.

    Ordered, and the order is the whole of it:

      1. wait out a running voice generation. `clear_status` refuses to drop a
         running job, and `_run_job` ends in `write_encrypted`, which mints a
         data key and recreates `database/<id>/` if it has to. A deletion racing
         one puts the directory back after the user asked to be erased.
      2. revoke at Google and stop the mailbox watch, both of which need the
         refresh token and so must happen before the shred.
      3. drop the caches. `tokens.forget` fans out to `keyring.forget`, and the
         per-thread Google service objects go with them.

    Every step is best effort and reports what it managed: the caller is about
    to delete the account either way, and a user asking to be erased must not be
    held up by an outage at Google. Returns a dict the web tier logs.

    Runs in the daemon because the web process cannot read `token.bin` and,
    more to the point, because these are the daemon's own caches -- the web
    tier's `keyring.destroy` clears only its own."""
    result = {"voice": voice_dna.await_job(account_id),
              "revoked": False, "watch_stopped": False}
    acct = account_mod.account_for_email(account_id, include_inactive=True)
    if acct is None:
        # Already gone from the manifest: there is nothing to read a token with
        # and nothing to name at Google. Still worth dropping the caches, which
        # is exactly the race this operation exists to lose gracefully.
        tokens.forget_id(account_id)
        google_client.forget_services(account_id)
        return result
    for name, action in (("watch_stopped", lambda: gmail_api.stop_watch(acct)),
                         ("revoked", lambda: tokens.revoke(acct))):
        try:
            result[name] = bool(action())
        except Exception as err:
            _log(f"account-forget {account_id}: {name} failed: "
                 f"{type(err).__name__}: {err}")
    tokens.forget(acct)
    google_client.forget_services(account_id)
    _log(f"account-forget {account_id}: {result}")
    return result


def _providers():
    """Which inference providers this deployment holds a key for.

    Names only. The web tier renders the labels from its own copy of the
    catalog, so nothing derived from a key crosses the socket, and no argument
    is taken: the answer is a property of the deployment and not of an
    account."""
    return llm_client.available_provider_names()


HANDLERS = {
    handoff.OP_AUTH_URL: _auth_url,
    handoff.OP_SIGN_IN: _sign_in,
    handoff.OP_VOICE_START: _voice_start,
    handoff.OP_VOICE_STATUS: _voice_status,
    handoff.OP_VOICE_CLEAR: _voice_clear,
    handoff.OP_CHAT_BEGIN: _chat_begin,
    handoff.OP_CHAT_FINISH: _chat_finish,
    handoff.OP_CHAT_FORGET: _chat_forget,
    handoff.OP_PROVIDERS: _providers,
    handoff.OP_ACCOUNT_FORGET: _account_forget,
}

assert set(HANDLERS) == set(handoff.OPS), (
    "every operation the contract names needs a handler, and nothing else may "
    "answer on this socket"
)


def dispatch(request, log):
    """One request to one reply dict. Never raises: an unhandled exception here
    is a 500 the web tier renders, and the detail stays in this process."""
    op = request.get(handoff.F_OP)
    args = request.get(handoff.F_ARGS) or {}
    handler = HANDLERS.get(op)
    if handler is None:
        return {handoff.F_ERROR: {handoff.F_CODE: 400, handoff.F_MSG: f"unknown operation {op!r}"}}
    try:
        return {handoff.F_RESULT: handler(**args)}
    except provisioning.ProvisionError as err:
        log(f"{op} refused: {err.msg}")
        return {handoff.F_ERROR: {handoff.F_CODE: err.code, handoff.F_MSG: err.msg}}
    except handoff.RemoteRefusal as err:
        log(f"{op} refused: {err.msg}")
        return {handoff.F_ERROR: {handoff.F_CODE: err.code, handoff.F_MSG: err.msg}}
    except chat_link.ChangeRefused as err:
        # 409 rather than 400: the request was well formed and this process
        # declined it, and the message is written for the user to read. It is
        # also the one code whose message the web tier renders unaltered, so the
        # text is checked here as well as at the raise site -- the assert costs
        # a set lookup and stands between a future refusal that interpolates an
        # id and a browser being shown it.
        log(f"{op} refused: {err}")
        assert str(err) in chat_link.USER_MESSAGES, (
            f"{op} refused with text nothing vetted: {err!r}"
        )
        return {handoff.F_ERROR: {handoff.F_CODE: handoff.RENDERABLE_CODE,
                                  handoff.F_MSG: str(err)}}
    except TypeError as err:
        log(f"{op} called with arguments it does not take: {err}")
        return {handoff.F_ERROR: {handoff.F_CODE: 400, handoff.F_MSG: "malformed request"}}
    except Exception as err:
        log(f"{op} failed: {type(err).__name__}: {err}\n{traceback.format_exc()}")
        return {handoff.F_ERROR: {handoff.F_CODE: 500, handoff.F_MSG: "the operation failed"}}


def _serve_one(conn, log):
    try:
        conn.settimeout(handoff.TIMEOUT)
        pid, uid, _gid = _peer(conn)
        if not _may_connect(uid):
            log(f"handoff refused connection from pid={pid} uid={uid}")
            return
        request = handoff.read_line(conn)
        if request is None:
            return
        log(f"handoff {request.get(handoff.F_OP)!r} from pid={pid} uid={uid}")
        conn.sendall(handoff.encode(dispatch(request, log)))
    except (OSError, ValueError) as err:
        log(f"handoff connection failed: {err}")
    finally:
        conn.close()


def bind(log):
    """The listening socket, replacing a stale one from a previous run.

    A unix socket keeps its file after the process holding it dies, and connect
    on that file fails ECONNREFUSED rather than ENOENT, so a daemon that was
    killed leaves a path that looks bindable and is not."""
    run_dir = paths.ensure_run_dir()
    path = handoff.socket_path()
    assert path.parent == run_dir, f"the handoff socket belongs under {run_dir}"
    if path.exists():
        path.unlink()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))
    # The group comes from the setgid bit on state/, which every inode created
    # in there inherits, sockets included. Only the mode is this function's to
    # set, and it is the shared one: a socket the web tier cannot open is a
    # sign-in that cannot complete.
    path.chmod(paths.file_mode())
    srv.listen(BACKLOG)
    log(f"custody handoff listening on {path}")
    return srv


def serve(log):
    srv = bind(log)
    while True:
        try:
            conn, _ = srv.accept()
        except OSError as err:
            log(f"handoff accept failed: {err}")
            continue
        threading.Thread(target=_serve_one, args=(conn, log),
                         daemon=True, name="handoff").start()


def start(log):
    """Run the listener for the lifetime of the process.

    Daemon thread: the mail loop owns the process lifetime, and a sign-in in
    flight must not keep a restarting daemon alive."""
    thread = threading.Thread(target=serve, args=(log,), daemon=True,
                              name="handoff-listener")
    thread.start()
    return thread
