"""The web tier's channel to the one process allowed to hold a refresh token.

Track G/I put the outer wrapping key on a second machine. This is the smaller
boundary inside the first one: the web UI runs as its own uid and cannot read
`token.bin`, so the two operations that need a Google token stop happening in
that process and happen here instead, over a socket, in the mail uid.

Three things cross, and the first two are the only ones the web tier ever had
that needed a token:

  * the consent URL and the OAuth callback, the second of which exchanges an
    authorization code and is the moment a plaintext refresh token exists at
    all,
  * voice profile generation, which reads the account's own sent mail,
  * changing an account's Telegram target.

The third is here for a different reason and the difference is worth keeping
straight. It needs no Google token. It crosses because the *decision* is not the
web tier's to make: the summary carries mail content, so the chat id it is sent
to is the one setting a compromised web tier could turn into somebody else's
mail. `backend.accounts.chat_link` states the rule and holds the codes. This
side asks; it does not get to say yes.

Everything else the web UI does with an account -- rendering the two documents,
saving them, changing settings -- needs the account's data key and not a token,
and the data key it gets from the co-signer directly.

Why this and not the wake spool: the spool is one way, so a synchronous sign-in
would have to poll for a result file, and that result file would carry a live
authorization code and a PKCE verifier at rest. A socket answers in the same
call, times out on its own, and leaves nothing behind. It costs a listener.

Why not the wake FIFO's own daemon loop: `daemon_loop.main()` is serial by
design -- one wake runs a full drafting pass before the next is read -- so a
sign-in queued behind a draft would wait for an LLM. The server runs on its own
thread inside that process (`handoff_server.start`), which is what makes the
writer of `token.bin` the mail uid without making sign-in wait for mail.

The contract lives here rather than beside the server for the same reason
`cosigner/protocol.py` does not live in `backend/`: one file both sides read, so
a field name or a framing rule cannot be spelled two ways. The client lives here
too, because unlike the co-signer this callee is not going anywhere -- it is the
same repository and the same deployment, and a second module would be ceremony.
"""

from __future__ import annotations

import json
import socket

from backend import paths

SOCKET_NAME = "custody.sock"

# One JSON object per line, request then response, then the connection closes.
# Line framing rather than a length prefix because both sides are Python and
# neither payload is binary: everything crossing here is a query string Google
# put in a redirect, or an account id.
ENCODING = "utf-8"
LINE_END = b"\n"

# A callback query with every parameter Google sends is a few hundred bytes.
# Reading an attacker-declared length unbounded is a free allocation, the same
# reasoning as `protocol.MAX_BODY`.
MAX_BODY = 64 * 1024

# The sign-in path talks to Google twice and the co-signer twice, so it is
# seconds rather than milliseconds. Long enough that a slow consent completes,
# short enough that a browser does not sit on a dead socket: the daemon being
# down has to surface as an error page, not as a hang.
TIMEOUT = 90

OP_AUTH_URL = "auth-url"
OP_SIGN_IN = "sign-in"
OP_VOICE_START = "voice-start"
OP_VOICE_STATUS = "voice-status"
OP_VOICE_CLEAR = "voice-clear"
OP_CHAT_BEGIN = "chat-begin"
OP_CHAT_FINISH = "chat-finish"
OP_CHAT_FORGET = "chat-forget"

# Which inference providers this deployment can actually reach. It crosses for
# a third reason, neither a Google token nor a decision withheld from the web
# tier: the answer is a function of the inference API keys, and holding two live
# keys to answer a yes/no question is the whole of why the web tier had them.
# The names that come back are catalogue keys, never a key or any part of one.
OP_PROVIDERS = "providers"

# Everything the mail role has to let go of before an account is deleted, and
# the two things only it can still do while the account's data key exists.
#
# It crosses for the original reason -- a Google token, and the credential that
# obtains one -- but the pressing half is that deletion runs in the *web*
# process. `keyring.destroy` clears that process's cache and unlinks the record;
# the daemon is a different process and goes on holding this account's data key
# for up to `DEK_TTL`, its access token for up to an hour, a Google service
# object per thread, and a voice job that `clear_status` will not remove while
# it runs. A deletion racing a running generation ends with `write_encrypted`
# recreating `database/<id>/` and writing a file into it after the user asked to
# be erased -- unreadable, since the record is gone, but the directory, its name
# and its timestamps are back.
#
# The two outbound calls are here because ordering forces them: revoking the
# Google grant and stopping the mailbox watch both need the refresh token, and
# the refresh token is unreadable the moment the key is destroyed. Neither is
# allowed to fail the deletion.
OP_ACCOUNT_FORGET = "account-forget"

OPS = (OP_AUTH_URL, OP_SIGN_IN, OP_VOICE_START, OP_VOICE_STATUS, OP_VOICE_CLEAR,
       OP_CHAT_BEGIN, OP_CHAT_FINISH, OP_CHAT_FORGET, OP_PROVIDERS,
       OP_ACCOUNT_FORGET)

# Which Telegram change is pending. Named here rather than beside the rule that
# decides it, because the deciding is `chat_link`'s and this is only what the
# answer is called on the wire. The asking side needs the value to render two
# sets of instructions, and it must be able to read it without importing the
# module that could perform the change without asking.
CHAT_LINK = "link"
CHAT_UNLINK = "unlink"

# The subject of the message the daemon puts in the account's inbox when it
# withholds a link code. Here for the same reason as the two names above: the
# page has to tell the user what to look for, and it must be able to say so
# without importing the module holding `force_unlink`. `chat_link` sends what
# this names, so the page and the mail cannot drift apart.
CHAT_CODE_SUBJECT = "Your Letterlock Telegram code"

F_OP = "op"
F_ARGS = "args"
F_RESULT = "result"
F_ERROR = "error"
F_CODE = "code"
F_MSG = "msg"

# The one status whose `msg` the web tier may put on a page as it stands.
#
# Everything else the daemon refuses with is written for a log: a
# `ProvisionError` carries whatever Google put in the callback's `error`
# parameter, and a `RemoteRefusal` names the account. Those render as a generic
# sentence and the detail stays in the daemon's journal. 409 is the exception,
# and it is one on purpose -- it is the code `handoff_server` gives a
# `chat_link.ChangeRefused`, whose whole content is an instruction the user has
# to read to finish what they started, and whose text is a fixed string checked
# against `chat_link.USER_MESSAGES`.
#
# Stated here rather than at the two call sites because the rule is about the
# wire and the asking side must be able to read it without importing the module
# that holds the bypass.
RENDERABLE_CODE = 409


def socket_path():
    return paths.RUN_DIR / SOCKET_NAME


class HandoffUnavailable(Exception):
    """The daemon is not listening, or did not answer in time.

    Never caught into a fallback that does the work locally. Doing it locally is
    precisely what this module exists to stop: a web process that falls back to
    exchanging the code itself is a web process that holds a refresh token, and
    the uid split around it becomes decoration."""


class RemoteRefusal(Exception):
    """The operation ran and was refused, carrying the callee's own status code
    and message so the web tier renders the page it always did. Distinct from
    `HandoffUnavailable` because one is the user's problem (a denied scope) and
    the other is the operator's (a daemon that is down)."""

    def __init__(self, code, msg):
        super().__init__(f"{code}: {msg}")
        self.code = code
        self.msg = msg


def encode(payload):
    """One framed message. Raises ValueError on a payload over the limit.

    A refusal and not an assert even though this is the outbound side: the
    `sign-in` payload carries the OAuth callback's query string, which a browser
    supplies and which the request line lets run to about this limit on its own.
    So an over-long payload is an input to refuse rather than a bug in the
    caller. The inbound limit is separate and already enforced by
    `read_line(conn, limit=MAX_BODY)`."""
    line = json.dumps(payload).encode(ENCODING)
    if len(line) > MAX_BODY:
        raise ValueError(
            f"handoff payload is {len(line)} bytes, over the {MAX_BODY} limit"
        )
    return line + LINE_END


def read_line(conn, limit=MAX_BODY):
    """One framed message, or None when the peer closed without sending one.

    Bounded by `limit` so a peer that never sends a newline cannot make the
    reader allocate without end."""
    chunks = bytearray()
    while LINE_END not in chunks:
        if len(chunks) > limit:
            raise ValueError(f"handoff message exceeded {limit} bytes")
        block = conn.recv(4096)
        if not block:
            return None
        chunks.extend(block)
    return json.loads(bytes(chunks.split(LINE_END, 1)[0]).decode(ENCODING))


def call(op, **args):
    """One request, one response. Raises `HandoffUnavailable` or `RemoteRefusal`."""
    assert op in OPS, f"{op!r} is not a handoff operation"
    # Framed before the socket exists, so an over-long payload is reported as
    # what it is rather than as a daemon that could not be reached.
    line = encode({F_OP: op, F_ARGS: args})
    path = str(socket_path())
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(TIMEOUT)
    try:
        conn.connect(path)
        conn.sendall(line)
        reply = read_line(conn)
    except (OSError, ValueError) as err:
        raise HandoffUnavailable(f"{op} could not reach {path}: {err}") from err
    finally:
        conn.close()
    if reply is None:
        raise HandoffUnavailable(f"{op}: the daemon closed without answering")
    if F_ERROR in reply:
        raise RemoteRefusal(reply[F_ERROR][F_CODE], reply[F_ERROR][F_MSG])
    return reply.get(F_RESULT)


def auth_url(state, redirect_uri):
    """Google's consent URL for this sign-in.

    Here rather than in the web tier because building it reads the OAuth app's
    client_id, and the file holding that also holds the client secret. A web
    process with the secret, the authorization code it receives on the redirect,
    and the PKCE verifier it can derive from `state` could exchange the code
    itself -- which is the one thing moving `sign_in` across was for."""
    return call(OP_AUTH_URL, state=state, redirect_uri=redirect_uri)


def sign_in(query, state_ok, redirect_uri, fallback="/dashboard"):
    """Run the OAuth callback in the mail uid. Returns (account_id, location).

    `state_ok` is the browser check already performed by the caller, because the
    cookie proving this consent started in this browser is the web tier's to
    hold and nothing here can see it. It protects the browser from a third party
    forcing a sign-in; it was never a check on the web tier itself, which is the
    process receiving the code either way."""
    assert isinstance(state_ok, bool), "state_ok is the answer, not the predicate"
    result = call(OP_SIGN_IN, query=dict(query), state_ok=state_ok,
                  redirect_uri=redirect_uri, fallback=fallback)
    return result["account_id"], result["location"]


def voice_start(account_id):
    return bool(call(OP_VOICE_START, account_id=account_id))


def voice_status(account_id):
    return call(OP_VOICE_STATUS, account_id=account_id)


def voice_clear_status(account_id):
    call(OP_VOICE_CLEAR, account_id=account_id)


def chat_begin(account_id):
    """Start a Telegram change. Returns (action, code, bot username), where
    `code` is None when the daemon put it in the account's inbox rather than
    answering with it.

    The code is minted over there and never here. It is the proof the daemon
    will check, and a proof the checker accepts from the caller is not one --
    see `backend.accounts.chat_link` for the replay that permits.

    None is not an error and not something to work around: it is the daemon
    declining to tell this process something, because this process is the one
    the rule is aimed at. Render the instructions and let the user read their
    own mail.

    The bot's @name comes back with it so this side can render the instructions
    without holding the bot token."""
    result = call(OP_CHAT_BEGIN, account_id=account_id)
    return result["action"], result["code"], result["username"]


def chat_finish(account_id):
    """Complete a Telegram change. Returns the chat id now linked, or None when
    the account was unlinked. `RemoteRefusal` carries the reason, which includes
    the ordinary "we have not seen the code yet"."""
    return call(OP_CHAT_FINISH, account_id=account_id)


def chat_forget(account_id):
    call(OP_CHAT_FORGET, account_id=account_id)


def account_forget(account_id):
    """Ask the daemon to release everything it holds for an account, and to
    withdraw the Google grant while that is still possible. Returns the daemon's
    report as a dict of what it managed.

    Called *before* `account.delete_account`, never after: once the data key is
    destroyed the refresh token is bytes nobody can read, so revocation and
    `users.stop` stop being available at all. A user who deletes their account
    would otherwise have Letterlock listed on their Google security page
    indefinitely with a live grant we cannot withdraw.

    The caller does not abort a deletion because this failed. Deleting is the
    thing the user asked for; the rest is best effort and the daemon says which
    parts it managed."""
    return call(OP_ACCOUNT_FORGET, account_id=account_id)


_providers_cache = None


def providers():
    """Names of the inference providers whose key this deployment holds.

    Cached for the process lifetime rather than per request. A key arrives as
    injected environment or in `.env`, and neither changes under a running
    process: the answer can only move across a restart, so re-asking is a round
    trip that cannot return anything new. It also keeps a page every signed-in
    user loads from being a call per render.

    `HandoffUnavailable` is left to the caller and deliberately not cached, so a
    daemon that comes back is answered the next time somebody asks."""
    global _providers_cache
    if _providers_cache is None:
        names = call(OP_PROVIDERS)
        if not isinstance(names, list):
            raise HandoffUnavailable(
                f"the daemon answered {OP_PROVIDERS} with "
                f"{type(names).__name__}, not a list of catalog names"
            )
        _providers_cache = tuple(names)
    return _providers_cache
