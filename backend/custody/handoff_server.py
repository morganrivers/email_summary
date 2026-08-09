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

import socket
import struct
import threading
import traceback

from backend import paths
from backend.accounts import account as account_mod
from backend.accounts import chat_link
from backend.custody import handoff
from backend.drafting import voice_dna
from backend.onboarding import provisioning

BACKLOG = 16


def _peer(conn):
    """(pid, uid, gid) of the process at the other end, for the log line.

    The grant itself is the socket's mode: it lives in a directory the shared
    group owns and carries that group, so the only accounts that can connect are
    the web uid and this one. This is who did it, not whether they may."""
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                              struct.calcsize("3i"))
        return struct.unpack("3i", raw)
    except OSError:
        return (-1, -1, -1)


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
    signature the one the tests already drive."""
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


HANDLERS = {
    handoff.OP_AUTH_URL: _auth_url,
    handoff.OP_SIGN_IN: _sign_in,
    handoff.OP_VOICE_START: _voice_start,
    handoff.OP_VOICE_STATUS: _voice_status,
    handoff.OP_VOICE_CLEAR: _voice_clear,
    handoff.OP_CHAT_BEGIN: _chat_begin,
    handoff.OP_CHAT_FINISH: _chat_finish,
    handoff.OP_CHAT_FORGET: _chat_forget,
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
        # declined it, and the message is written for the user to read.
        log(f"{op} refused: {err}")
        return {handoff.F_ERROR: {handoff.F_CODE: 409, handoff.F_MSG: str(err)}}
    except TypeError as err:
        log(f"{op} called with arguments it does not take: {err}")
        return {handoff.F_ERROR: {handoff.F_CODE: 400, handoff.F_MSG: "malformed request"}}
    except Exception as err:
        log(f"{op} failed: {type(err).__name__}: {err}\n{traceback.format_exc()}")
        return {handoff.F_ERROR: {handoff.F_CODE: 500, handoff.F_MSG: "the operation failed"}}


def _serve_one(conn, log):
    try:
        conn.settimeout(handoff.TIMEOUT)
        request = handoff.read_line(conn)
        if request is None:
            return
        pid, uid, _gid = _peer(conn)
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
