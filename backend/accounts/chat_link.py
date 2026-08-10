"""Who may change an account's Telegram target, and the proof it takes.

The daily summary carries mail content. The daemon builds it, because the daemon
is the only process that can open an account's Gmail token, and then delivers it
to the chat id in the manifest. So that one field converts a compromise of any
process that can write the manifest into a standing subscription to somebody
else's mail, with no unusual co-signer traffic to notice: the daemon goes on
making exactly the requests it makes every morning.

Moving the write behind `custody.handoff` does not close it. The daemon cannot
tell a genuine request from a forged one, because the web tier is the process
that decides who is signed in; taken over, it asks for any account it likes and
this process has no basis to refuse. Nor can a file mode close it, since the
request arrives through the channel that is supposed to exist, in the shape it
is supposed to have.

What closes it is asking the chat that is being replaced:

  * no chat linked -- allow it. Nothing is being delivered, so there is nothing
    to take, and requiring a proof nobody can give would mean nobody can link.
  * a chat linked -- unlinking requires a code posted from *that* chat.

Changing a target is therefore unlink then link, two steps for the user and one
rule here. Offering a direct change would need proof of the old chat and proof
of the new one in a single step, which is two codes and two waits to save a
click.

Unlink needs the proof for the same reason link does not: without it an attacker
unlinks first and the account falls into the case that asks for nothing.

The proof cannot be faked by a process holding the bot token. The token sends as
the bot and reads the bot's inbox; it does not put a message into the inbox from
somebody else's chat, and Telegram is the one deciding which chat a message came
from. What such a process can do is read updates, so codes are treated as public
and the binding is the chat id, not knowledge of the code.

Two things follow from that and both are here rather than in the caller:

  * this process mints the code. A caller-supplied one is a replay -- the code
    from the user's own legitimate link is still in the bot's 24h inbox, posted
    from the very chat the rule wants to hear from, so handing that string back
    later passes a check that has learned nothing.
  * the message has to be newer than the request. Same window, same reason, and
    it is what makes a code single use in practice rather than by bookkeeping.

State is a dict in this process and deliberately not a file. A pending change is
meaningful for the minutes between rendering a page and pressing a button; a
restart means starting again, which is the correct behaviour rather than a
limitation, and a spool file would be one more thing on disk naming who is
mid-change.
"""

from __future__ import annotations

import threading
import time

from backend.accounts import account as account_store
from backend.custody.handoff import CHAT_LINK, CHAT_UNLINK
from backend.integrations import telegram

# How long a pending change stays answerable. The user has to open Telegram,
# find the bot and send a code, which is a couple of minutes at an unhurried
# pace; a quarter hour is generous without leaving a half-finished change
# answerable for a working day.
PENDING_TTL = 900

_lock = threading.Lock()
_pending = {}


# Every refusal this module can give, spelled out.
#
# The web tier renders these verbatim, which is the only place a message from
# the daemon reaches a browser unaltered. That is safe exactly as long as the
# set is fixed and written for users: a future refusal interpolating a Polar id,
# a chat id or an exception string would be rendered the same way, and nothing
# would have refused it. So the strings live here, `ChangeRefused` asserts its
# message is one of them, and `handoff_server.dispatch` asserts it again on the
# way out.
NO_SUCH_ACCOUNT = "That account no longer exists."
NOT_CONFIGURED = "Telegram is not configured on this server yet."
CODE_EXPIRED = "That code expired. Start again."
CHANGED_MEANWHILE = "Your Telegram settings changed in the meantime. Start again."
CODE_NOT_SEEN = ("We have not seen that code yet. Send it to the bot, then press "
                 "the button again.")
CODE_NOT_SEEN_FROM_CHAT = (
    "We have not seen that code arrive from the linked chat yet. Send it "
    "from the chat that currently receives your summary, then press the "
    "button again.")

USER_MESSAGES = frozenset({
    NO_SUCH_ACCOUNT, NOT_CONFIGURED, CODE_EXPIRED, CHANGED_MEANWHILE,
    CODE_NOT_SEEN, CODE_NOT_SEEN_FROM_CHAT,
})


class ChangeRefused(Exception):
    """The change was asked for and this module said no.

    Carries a message the web tier renders as it stands, because every refusal
    here is something the user can act on: send the code, send it from the right
    chat, or start again. Which is why the message must be one of
    `USER_MESSAGES` and not a string built at the raise site."""

    def __init__(self, msg):
        assert msg in USER_MESSAGES, (
            f"{msg!r} is not one of chat_link.USER_MESSAGES; the web tier "
            "renders this text unaltered, so a refusal it does not name is a "
            "refusal nothing checked"
        )
        super().__init__(msg)


def _now():
    return int(time.time())


def _prune(now):
    for key in [k for k, v in _pending.items() if v["expires"] <= now]:
        del _pending[key]


def action_for(acct):
    """Which change this account can ask for, from what it has now.

    Derived rather than taken as a parameter: a caller naming the action could
    name `link` for an account that already has a target, which is exactly the
    replacement the rule refuses to perform in one step."""
    return CHAT_UNLINK if acct.telegram else CHAT_LINK


def _account(account_id):
    """The account this change is about.

    `account_for_email` rather than `get_account`, so a lapsed plan is still
    allowed to unlink: the summary keeps arriving in a chat the user can no
    longer detach would be a worse answer than letting them detach it."""
    acct = account_store.account_for_email(account_id)
    if acct is None:
        raise ChangeRefused(NO_SUCH_ACCOUNT)
    return acct


def _forget(account_id):
    with _lock:
        _pending.pop(account_id, None)


def begin(account_id):
    """Mint the code for this account's pending change. Returns
    (action, code, bot username).

    Restarting an unfinished change replaces it, so a user who leaves the page
    and comes back gets a code that works rather than one that expired quietly.
    """
    acct = _account(account_id)
    if not telegram.bot_token():
        raise ChangeRefused(NOT_CONFIGURED)
    action = action_for(acct)
    code = telegram.new_link_code()
    now = _now()
    with _lock:
        _prune(now)
        _pending[acct.id] = {
            "action": action,
            "code": code,
            "since": now,
            "expires": now + PENDING_TTL,
            # The target as it was when the code was minted. The rule asks the
            # chat that is being replaced, so it has to be the one that was
            # there when the user asked, not whatever the manifest says by the
            # time they press the button.
            "chat_id": acct.telegram.chat_id if acct.telegram else None,
        }
    return action, code, telegram.bot_username()


def _claim(account_id):
    with _lock:
        _prune(_now())
        entry = _pending.get(account_id)
        if entry is None:
            raise ChangeRefused(CODE_EXPIRED)
        return dict(entry)


def _posted_since(code, since, chat_id=None):
    """The chat that posted `code` after `since`, or None.

    `chat_id` pins which chat is allowed to answer. Left open it means any, and
    that is only ever right for an account with nothing linked."""
    for posted_chat, when in telegram.posts_of(code):
        if when < since:
            continue
        if chat_id is not None and posted_chat != str(chat_id):
            continue
        return posted_chat
    return None


def finish(account_id):
    """Complete a pending change, or say what is still missing. Returns the
    Account as it now stands.

    Raises `ChangeRefused` while the code has not been seen, so the caller
    renders the same waiting page it rendered before rather than having to tell
    a refusal from a not-yet."""
    entry = _claim(account_id)
    acct = _account(account_id)
    # Re-read rather than trusting what begin() saw: two tabs, or a change that
    # completed while this one waited, and the account is no longer in the state
    # the pending entry describes.
    #
    # The target and not only the derived action. `action_for` distinguishes
    # linked from unlinked and nothing else, so a target moved from chat A to
    # chat B inside one window -- unlink A, link B, both completed -- leaves the
    # action still CHAT_UNLINK while the pending entry still names A. A code
    # posted from A would then unlink B, which is the one path where the chat
    # asked is not the chat replaced. The whole content of the rule is that
    # those are the same chat.
    current_chat = acct.telegram.chat_id if acct.telegram else None
    if action_for(acct) != entry["action"] or current_chat != entry["chat_id"]:
        _forget(account_id)
        raise ChangeRefused(CHANGED_MEANWHILE)

    if entry["action"] == CHAT_LINK:
        chat_id = _posted_since(entry["code"], entry["since"])
        if chat_id is None:
            raise ChangeRefused(CODE_NOT_SEEN)
        _forget(account_id)
        acct = account_store.set_telegram(acct.id, chat_id=chat_id)
        telegram.send_telegram(
            "✅ <b>Letterlock is linked to this chat.</b>\n"
            "You will get a message when a draft is ready, plus your daily summary.",
            acct.telegram,
        )
        return acct

    assert entry["chat_id"], "an unlink was pending for an account with no chat"
    if _posted_since(entry["code"], entry["since"], entry["chat_id"]) is None:
        raise ChangeRefused(CODE_NOT_SEEN_FROM_CHAT)
    _forget(account_id)
    return account_store.set_telegram(acct.id, clear=True)


def forget(account_id):
    """Drop any pending change. Called when the account is deleted, and by
    tests."""
    _forget(account_id)


def force_unlink(account_id):
    """Unlink without the proof. The operator path, for a user who has lost the
    Telegram account itself and therefore cannot post from it.

    Reachable only from `backend.accounts.unlink_telegram`, a command run by a
    human on the box. Deliberately not a route: a route restores exactly the
    bypass the rule removes, and would be reachable from the internet by the
    process the rule is aimed at."""
    _forget(account_id)
    return account_store.set_telegram(account_id, clear=True)
