"""The rule guarding an account's Telegram target.

The target is the one manifest field that turns a compromise of the web tier
into somebody else's mail: the daemon reads the mailbox and delivers a summary
to whatever chat id it finds. Moving the write behind the handoff socket does
not help, because the daemon cannot tell a forged request from a real one. What
helps is asking the chat being detached, over a channel the web tier is not on.

So the tests here are mostly refusals, and the one that matters most is the
replay: a code the user posted from their own chat during a legitimate link is
still in the bot's inbox for a day afterwards.
"""

import ast

import pytest
from harness import python_sources, relative

from backend.accounts import account, chat_link
from backend.custody import handoff, handoff_server

CHAT = "4242"
OTHER = "9999"


@pytest.fixture
def acct(tmp_path, monkeypatch):
    monkeypatch.setattr(account, "ACCOUNTS_DIR", tmp_path)
    monkeypatch.setattr(account, "MANIFEST", tmp_path / "accounts.json")
    return account.register_account("dana@x.com", "Dana", "R")


@pytest.fixture(autouse=True)
def _no_pending():
    chat_link._pending.clear()
    yield
    chat_link._pending.clear()


class Bot:
    """The bot's inbox, as `telegram.posts_of` reports it."""

    def __init__(self, monkeypatch, now):
        self.posts = []
        self.sent = []
        self.now = now
        monkeypatch.setattr(chat_link.telegram, "bot_token", lambda: "t")
        monkeypatch.setattr(chat_link.telegram, "bot_username", lambda: "bot")
        monkeypatch.setattr(chat_link.telegram, "posts_of",
                            lambda code: [(c, w) for c, w, k in self.posts if k == code])
        monkeypatch.setattr(chat_link.telegram, "send_telegram",
                            lambda msg, target: self.sent.append((msg, target)))
        monkeypatch.setattr(chat_link, "_now", lambda: self.now)

    def post(self, chat_id, code, when=None):
        self.posts.append((str(chat_id), self.now if when is None else when, code))


@pytest.fixture
def bot(monkeypatch):
    return Bot(monkeypatch, now=1_000_000)


def _link(acct, bot, chat_id=CHAT):
    action, code, _ = chat_link.begin(acct.id)
    assert action == handoff.CHAT_LINK
    bot.post(chat_id, code)
    return chat_link.finish(acct.id)


def test_a_first_link_needs_only_the_new_chat(acct, bot):
    """Nothing is being delivered yet, so there is nothing to take. Requiring a
    proof here would mean nobody can ever link."""
    linked = _link(acct, bot)
    assert linked.telegram.chat_id == CHAT
    assert bot.sent, "linking sends the chat a message so the user sees it worked"


def test_the_code_has_to_arrive_before_anything_is_written(acct, bot):
    chat_link.begin(acct.id)
    with pytest.raises(chat_link.ChangeRefused):
        chat_link.finish(acct.id)
    assert account.account_for_email(acct.id).telegram is None


def test_unlinking_needs_the_linked_chat_to_ask(acct, bot):
    """The rule, in one test. A request to unlink is not enough; the chat losing
    the summary has to say so."""
    _link(acct, bot)
    action, code, _ = chat_link.begin(acct.id)
    assert action == handoff.CHAT_UNLINK

    bot.post(OTHER, code)
    with pytest.raises(chat_link.ChangeRefused):
        chat_link.finish(acct.id)
    assert account.account_for_email(acct.id).telegram.chat_id == CHAT

    bot.post(CHAT, code)
    assert chat_link.finish(acct.id).telegram is None


def test_a_code_from_an_earlier_link_does_not_authorize_an_unlink(acct, bot):
    """The replay this module mints its own codes to stop.

    Telegram keeps the update for 24h, so the code the user posted from their
    own chat to link it is still there, posted from exactly the chat an unlink
    has to hear from. Accepting a caller-supplied code would mean handing that
    string back is a proof of nothing that passes."""
    action, old_code, _ = chat_link.begin(acct.id)
    assert action == handoff.CHAT_LINK
    bot.post(CHAT, old_code)
    chat_link.finish(acct.id)

    # An attacker replays it: same chat, same code, but posted before the unlink
    # was ever requested.
    bot.now += 60
    chat_link.begin(acct.id)
    with pytest.raises(chat_link.ChangeRefused):
        chat_link.finish(acct.id)
    assert account.account_for_email(acct.id).telegram.chat_id == CHAT


def test_a_message_older_than_the_request_is_not_an_answer(acct, bot):
    _link(acct, bot)
    _action, code, _ = chat_link.begin(acct.id)
    bot.post(CHAT, code, when=bot.now - 1)
    with pytest.raises(chat_link.ChangeRefused):
        chat_link.finish(acct.id)


def test_an_expired_change_is_refused_rather_than_answered(acct, bot):
    _link(acct, bot)
    _action, code, _ = chat_link.begin(acct.id)
    bot.now += chat_link.PENDING_TTL + 1
    bot.post(CHAT, code)
    with pytest.raises(chat_link.ChangeRefused):
        chat_link.finish(acct.id)
    assert account.account_for_email(acct.id).telegram.chat_id == CHAT


def test_the_action_is_derived_and_not_asked_for(acct, bot):
    """A caller naming the action could name `link` for an account that already
    has a target, which is the one-step replacement the rule declines."""
    assert chat_link.action_for(acct) == handoff.CHAT_LINK
    linked = _link(acct, bot)
    assert chat_link.action_for(linked) == handoff.CHAT_UNLINK


def test_a_change_that_completed_elsewhere_invalidates_this_one(acct, bot):
    """Two tabs, or a second request. The pending entry describes a state the
    account is no longer in, and acting on it would apply an unlink the user
    asked for against a chat that is no longer the one linked."""
    _link(acct, bot)
    _action, code, _ = chat_link.begin(acct.id)
    account.set_telegram(acct.id, clear=True)
    bot.post(CHAT, code)
    with pytest.raises(chat_link.ChangeRefused):
        chat_link.finish(acct.id)


def test_the_chat_asked_is_the_chat_replaced(acct, bot):
    """`action_for` distinguishes linked from unlinked and nothing else, so a
    target moved from one chat to another inside one window leaves the action
    still CHAT_UNLINK while the pending entry names the old chat. A code posted
    from the old chat would then unlink the new one -- the single path where the
    chat asked is not the chat replaced, which is the whole content of the
    rule."""
    _link(acct, bot)                                   # linked to CHAT
    _action, stale_code, _ = chat_link.begin(acct.id)  # unlink of CHAT pending
    # The owner completes a full unlink-then-link cycle in the meantime.
    chat_link._forget(acct.id)
    account.set_telegram(acct.id, clear=True)
    _link(acct, bot, chat_id=OTHER)
    chat_link._pending[acct.id] = {
        "action": handoff.CHAT_UNLINK, "code": stale_code,
        "since": bot.now, "expires": bot.now + chat_link.PENDING_TTL,
        "chat_id": CHAT,
    }

    bot.post(CHAT, stale_code)
    with pytest.raises(chat_link.ChangeRefused, match="changed in the meantime"):
        chat_link.finish(acct.id)
    assert account.account_for_email(acct.id).telegram.chat_id == OTHER


def test_every_refusal_is_a_sentence_somebody_vetted(acct, bot):
    """The web tier renders these unaltered, which is safe exactly as long as
    the set is fixed. A refusal interpolating a chat id or an exception string
    would be rendered the same way and nothing would have refused it."""
    with pytest.raises(AssertionError, match="USER_MESSAGES"):
        raise chat_link.ChangeRefused(f"chat {CHAT} said no")


def test_the_operator_path_needs_no_proof(acct, bot):
    """The way out for a user who has lost the Telegram account itself. It has
    to exist, and it has to stay a command."""
    _link(acct, bot)
    assert chat_link.force_unlink(acct.id).telegram is None


def test_nothing_reachable_from_the_web_calls_force_unlink():
    """`force_unlink` is the bypass, so its callers are the whole of its
    security. One command module, and no route."""
    callers = set()
    for path in python_sources():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name == "force_unlink":
                callers.add(relative(path))
    assert callers == {"backend/accounts/unlink_telegram.py"}, (
        f"force_unlink skips the confirmation; unexpected callers: {sorted(callers)}"
    )


def test_set_telegram_has_one_caller():
    """The rule is only a rule while every write goes through it."""
    callers = set()
    for path in python_sources():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name == "set_telegram":
                callers.add(relative(path))
    assert callers == {"backend/accounts/chat_link.py"}, (
        "every telegram target write goes through the confirmation rule; "
        f"unexpected callers: {sorted(callers)}"
    )


def test_a_refusal_reaches_the_asking_side_as_one(acct, bot):
    """A refusal here is a sentence written for the user, so it has to survive
    the socket rather than becoming the generic 500 an unhandled exception
    would. 409, because the request was well formed and this side said no."""
    chat_link.begin(acct.id)
    reply = handoff_server.dispatch(
        {handoff.F_OP: handoff.OP_CHAT_FINISH, handoff.F_ARGS: {"account_id": acct.id}},
        lambda _msg: None,
    )
    assert reply[handoff.F_ERROR][handoff.F_CODE] == 409
    assert "have not seen that code" in reply[handoff.F_ERROR][handoff.F_MSG]


def test_the_asking_side_never_learns_the_pending_state(acct, bot):
    """`chat-begin` hands back the code and the action and nothing else. The
    chat id it is measured against stays here, so a caller cannot present the
    value the check is about to compare."""
    reply = handoff_server.dispatch(
        {handoff.F_OP: handoff.OP_CHAT_BEGIN, handoff.F_ARGS: {"account_id": acct.id}},
        lambda _msg: None,
    )
    assert set(reply[handoff.F_RESULT]) == {"action", "code", "username"}
