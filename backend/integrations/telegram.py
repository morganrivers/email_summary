"""Single source of truth for Telegram notifications.

A TelegramTarget (bot token + chat id) routes a message to one account's chat.
The target is per account and always explicit: there is no environment fallback
on the notification path. A fallback there delivers one user's mail metadata to
whoever the box owner is, which is exactly the bug this module used to have.
An account with no target simply gets no notifications.

operator_target() is the separate, deliberate exception. Box-level failures (the
daemon crashed, someone used the contact form) belong to the operator, and it
reads the operator's own chat from the environment.

Linking a chat is a verification, not a text field. new_link_code() and
posts_of() are the halves of it: the UI shows a one-time code, the user sends
that code to the bot, and we read it back off getUpdates. The chat id we store
is one we have seen the user post from, so nobody can point their notifications
at a stranger's chat by typing its number.

Who is allowed to make that change is not decided here -- it is
backend.accounts.chat_link, which owns the codes and the rule. This module only
answers which chats posted a code and when.

Every send here is `parse_mode=HTML`, so what a caller interpolates is markup.
A caller holding a value from outside the account escapes it (`html.escape`);
a caller holding text a model wrote passes it through sanitize_model_html,
which is the one place the permitted tag set is written down.
"""

import html
import os
import re
import secrets
import sys
import threading
import time
import traceback

import requests

API_ROOT = "https://api.telegram.org"
TIMEOUT = 10

LINK_CODE_RE = re.compile(r"\bLL-[A-Z0-9]{8}\b")

MODEL_TAGS = ("b", "strong", "i", "em", "u", "s", "code", "pre")
MODEL_TAG_RE = re.compile(r"&lt;(/?)(" + "|".join(MODEL_TAGS) + r")&gt;")
FORBIDDEN_TAG_RE = re.compile(r"<(?!/?(?:" + "|".join(MODEL_TAGS) + r")>)")
MAX_NESTING = 8
TELEGRAM_MAX_CHARS = 4096
MAX_MODEL_CHARS = 3800
TRUNCATED = "\n[truncated]"


class TelegramTarget:
    def __init__(self, token, chat_id):
        assert token and chat_id, "telegram target needs token and chat_id"
        self.token = token
        self.chat_id = str(chat_id)


def log(msg):
    sys.stderr.write(f"telegram {msg}\n")
    sys.stderr.flush()


def bot_token():
    """The shared bot's token. One bot serves every account; only the chat id
    varies per user, so this is the one place the token is read."""
    return os.environ.get("TELEGRAM_BOT_TOKEN") or None


def call(method, payload, token=None):
    """One Bot API call. Returns the parsed `result`, or None on any failure:
    notification plumbing must never raise into a caller's happy path."""
    token = token or bot_token()
    if not token:
        log(f"{method} skipped: no TELEGRAM_BOT_TOKEN configured")
        return None
    try:
        resp = requests.post(
            f"{API_ROOT}/bot{token}/{method}", json=payload, timeout=TIMEOUT,
        )
        body = resp.json()
    except Exception as err:
        log(f"{method} failed: {err}")
        return None
    if not body.get("ok"):
        log(f"{method} rejected: {body.get('description')}")
        return None
    # Some methods carry no useful result; None must still read as success, so
    # callers can test "did this work" without testing "did it return data".
    result = body.get("result")
    return True if result is None else result


def operator_target():
    """The box owner's chat, for failures that belong to the operator rather
    than to any one user. None when the box has no operator chat configured."""
    token = bot_token()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return None
    return TelegramTarget(token, chat_id)


def _truncate_escaped(escaped, limit):
    """Cut escaped text to `limit` without splitting an entity in half. A cut
    inside `&amp;` leaves a bare `&`, which Telegram refuses the same way it
    refuses an unbalanced tag."""
    if len(escaped) <= limit:
        return escaped
    cut = escaped[:limit]
    last = cut.rfind("&")
    if last != -1 and ";" not in cut[last:]:
        cut = cut[:last]
    return cut + TRUNCATED


def sanitize_model_html(text):
    """Make model-written text safe to send under `parse_mode=HTML`.

    Model output is a function of the mail it read, so a sender who gets a
    sentence of their own into a summary is choosing markup in a message the
    user reads as their own bot's. Escaping everything and permitting a fixed
    list back is the only direction that is safe by default: a stripper has to
    recognise every tag in order to remove it, this has to recognise one in
    order to keep it.

    `<a>` is deliberately not permitted. An anchor is the one Telegram tag
    whose visible text can disagree with where it goes, which is a phishing
    link inside the daily briefing. A bare URL left as text costs nothing:
    Telegram links it anyway, with the destination in view.

    Balancing on the way out is the other half. Telegram answers unbalanced
    entities with a 400 and `call()` swallows it, so one unclosed tag is a
    summary that silently never arrives -- which a sender can ask for as
    easily as they can ask for the link."""
    escaped = html.escape(text or "", quote=False)
    escaped = _truncate_escaped(escaped, MAX_MODEL_CHARS)
    out, open_tags, pos = [], [], 0
    for match in MODEL_TAG_RE.finditer(escaped):
        out.append(escaped[pos:match.start()])
        pos = match.end()
        closing, tag = match.group(1), match.group(2)
        if closing and open_tags and open_tags[-1] == tag:
            open_tags.pop()
            out.append(f"</{tag}>")
        elif not closing and len(open_tags) < MAX_NESTING:
            open_tags.append(tag)
            out.append(f"<{tag}>")
        else:
            out.append(match.group(0))
    out.append(escaped[pos:])
    out.extend(f"</{tag}>" for tag in reversed(open_tags))
    result = "".join(out)
    assert not FORBIDDEN_TAG_RE.search(result), "sanitizing left a tag we do not permit"
    return result


def send_telegram(message, target):
    """Send to one account's chat. `target` is required and may be None, which
    means the account has not linked a chat: that is a normal state, not an
    error, so we skip quietly and report it. Returns whether it was sent."""
    if target is None:
        return False
    result = call(
        "sendMessage",
        {"chat_id": target.chat_id, "text": message, "parse_mode": "HTML"},
        token=target.token,
    )
    return result is not None


def notify_error(context, err=None, target=None):
    """Surface a failure to Telegram. Never raises: a broken notification must
    not crash the caller's except block. Falls back to the operator's chat, so
    an account-level failure with no linked chat still reaches somebody.

    For a condition that repeats on a timer -- a wake loop, a poll -- use
    `notify_once` instead. A traceback every five minutes is how a channel gets
    muted, and a muted channel reports nothing at all."""
    try:
        text = f"⚠️ <b>{html.escape(context)}</b>"
        if err is not None:
            detail = "".join(
                traceback.format_exception(type(err), err, err.__traceback__)
            )
            text += f"\n<pre>{html.escape(detail[-3000:])}</pre>"
        if not send_telegram(text, target):
            send_telegram(text, operator_target())
    except Exception as notify_err:
        log(f"notify_error failed to send: {notify_err}")


_ONCE_LOCK = threading.Lock()
_ONCE_SENT = {}


def notify_once(key, text, cooldown, target=None):
    """Send `text` at most once per `key` per `cooldown` seconds.

    The one implementation of "tell somebody, but not on every cycle". A daemon
    that wakes every five minutes, a provider that is out of credit for every
    email in the queue and an account that has not signed in all produce the
    same condition over and over, and the useful message is the first one.

    Returns whether it sent. Never raises, for the same reason notify_error
    does not: an undelivered alert must not replace the condition it describes.
    In-process state, so a restart re-announces -- deliberately, because a
    restart is also when an operator is watching."""
    assert key, "notify_once needs a key to rate-limit on"
    assert cooldown > 0, f"cooldown must be positive, got {cooldown}"
    now = time.monotonic()
    with _ONCE_LOCK:
        last = _ONCE_SENT.get(key)
        if last is not None and now - last < cooldown:
            return False
        _ONCE_SENT[key] = now
    try:
        if not send_telegram(text, target):
            return send_telegram(text, operator_target())
        return True
    except Exception as err:
        log(f"notify_once failed to send: {err}")
        return False


def reset_once_for_test():
    with _ONCE_LOCK:
        _ONCE_SENT.clear()


# --- chat linking ---------------------------------------------------------

_BOT_USERNAME = None


def bot_username():
    """The @name a user has to open to link their chat. Fetched once via getMe
    so the UI never hardcodes it (and cannot drift from the token in .env)."""
    global _BOT_USERNAME
    if _BOT_USERNAME is None:
        result = call("getMe", {}) or {}
        _BOT_USERNAME = result.get("username") or ""
    return _BOT_USERNAME or None


def new_link_code():
    """A one-time code the user sends to the bot to prove they own the chat."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "LL-" + "".join(secrets.choice(alphabet) for _ in range(8))


def posts_of(code):
    """[(chat id, unix seconds)] for every message carrying `code`, newest first.

    The one read of the bot's inbox, so linking a chat and confirming a change
    to one cannot disagree about what counts as having sent a code.

    Reads getUpdates without advancing the offset, so several users can be
    mid-change at once and each still finds their own code. Telegram keeps
    unconfirmed updates for 24h, which is far longer than a link takes and is
    also why the timestamp comes back with the chat id: a caller deciding on the
    strength of a message has to be able to refuse one sent before it asked.
    """
    assert code, "posts_of needs a code"
    updates = call("getUpdates", {"limit": 100, "timeout": 0})
    if not isinstance(updates, list):
        return []
    found = []
    for update in reversed(updates):
        message = update.get("message") or update.get("channel_post") or {}
        if code not in (message.get("text") or ""):
            continue
        chat_id = (message.get("chat") or {}).get("id")
        if chat_id is None:
            continue
        found.append((str(chat_id), int(message.get("date") or 0)))
    return found
