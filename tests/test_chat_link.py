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
import time

import pytest
from harness import python_sources, relative

from backend.accounts import account, auth_recency, chat_link
from backend.custody import handoff, handoff_server
from backend.integrations import telegram

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
    """The bot's inbox, as `telegram.posts_of` reports it, and the account's own
    inbox, as `notices.insert_notice` writes it.

    Both are faked here because the link flow spans them: the code leaves
    through the mailbox and comes back through Telegram, and a test faking only
    one half would be asserting against a code it had handed itself."""

    def __init__(self, monkeypatch, now):
        self.posts = []
        self.sent = []
        self.inbox = []
        self.insert_fails = False
        self.now = now
        monkeypatch.setattr(chat_link.notices, "insert_notice", self._insert)
        monkeypatch.setattr(chat_link.telegram, "bot_token", lambda: "t")
        monkeypatch.setattr(chat_link.telegram, "bot_username", lambda: "bot")
        monkeypatch.setattr(chat_link.telegram, "posts_of",
                            lambda code: [(c, w) for c, w, k in self.posts if k == code])
        monkeypatch.setattr(chat_link.telegram, "send_telegram",
                            lambda msg, target: self.sent.append((msg, target)))
        monkeypatch.setattr(chat_link, "_now", lambda: self.now)

    def _insert(self, account, subject, body):
        if self.insert_fails:
            raise RuntimeError("gmail said no")
        self.inbox.append((account.id, subject, body))
        return "msg-1"

    def post(self, chat_id, code, when=None):
        self.posts.append((str(chat_id), self.now if when is None else when, code))

    def emailed_code(self):
        """The code out of the last message we put in the mailbox."""
        assert self.inbox, "nothing was delivered to the inbox"
        found = telegram.LINK_CODE_RE.search(self.inbox[-1][2])
        assert found, "the delivered notice carried no code"
        return found.group(0)


@pytest.fixture
def bot(monkeypatch):
    return Bot(monkeypatch, now=1_000_000)


@pytest.fixture(autouse=True)
def _stale_auth():
    """No test here is a freshly signed-in user unless it says so.

    The default matters: `begin` skips the mailbox when the daemon saw a
    sign-in, so a leaked note from another test would quietly put every case
    back on the old path and the rule would go untested."""
    auth_recency._proven.clear()
    yield
    auth_recency._proven.clear()


def _begin(acct, bot):
    """begin(), plus the code wherever it went.

    Whether the code comes back or goes to the inbox is the subject of its own
    tests below; every other test here is about the rule that consumes it."""
    action, code, username = chat_link.begin(acct.id)
    return action, code if code is not None else bot.emailed_code(), username


def _link(acct, bot, chat_id=CHAT):
    action, code, _ = _begin(acct, bot)
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
    _begin(acct, bot)
    with pytest.raises(chat_link.ChangeRefused):
        chat_link.finish(acct.id)
    assert account.account_for_email(acct.id).telegram is None


def test_unlinking_needs_the_linked_chat_to_ask(acct, bot):
    """The rule, in one test. A request to unlink is not enough; the chat losing
    the summary has to say so."""
    _link(acct, bot)
    action, code, _ = _begin(acct, bot)
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
    action, old_code, _ = _begin(acct, bot)
    assert action == handoff.CHAT_LINK
    bot.post(CHAT, old_code)
    chat_link.finish(acct.id)

    # An attacker replays it: same chat, same code, but posted before the unlink
    # was ever requested.
    bot.now += 60
    _begin(acct, bot)
    with pytest.raises(chat_link.ChangeRefused):
        chat_link.finish(acct.id)
    assert account.account_for_email(acct.id).telegram.chat_id == CHAT


def test_a_message_older_than_the_request_is_not_an_answer(acct, bot):
    _link(acct, bot)
    _action, code, _ = _begin(acct, bot)
    bot.post(CHAT, code, when=bot.now - 1)
    with pytest.raises(chat_link.ChangeRefused):
        chat_link.finish(acct.id)


def test_an_expired_change_is_refused_rather_than_answered(acct, bot):
    _link(acct, bot)
    _action, code, _ = _begin(acct, bot)
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
    _action, code, _ = _begin(acct, bot)
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
    _action, stale_code, _ = _begin(acct, bot)  # unlink of CHAT pending
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


# ── Where the link code goes ─────────────────────────────────────────────────
#
# The first link has no chat to ask, so it asks the mailbox instead. What makes
# that worth the round trip is that the web tier never holds the code: a
# compromised one cannot post a code and have us bind the chat it posted from.

def test_a_first_link_puts_the_code_in_the_mailbox_and_not_on_the_page(acct, bot):
    """The whole of it in one test. A code this function returns is a code the
    web tier holds, and an attacker who holds it links their own chat and
    receives every summary from then on."""
    action, code, _ = chat_link.begin(acct.id)

    assert action == handoff.CHAT_LINK
    assert code is None, "the code came back to the caller"
    assert len(bot.inbox) == 1
    to_address, subject, body = bot.inbox[0]
    assert to_address == acct.id, "the code went to a mailbox that is not theirs"
    assert subject == handoff.CHAT_CODE_SUBJECT
    assert "do not send the code anywhere" in body


def test_the_emailed_code_is_the_one_the_daemon_will_check(acct, bot):
    """The delivery is worth nothing if the code in the mail is not the code the
    pending change holds."""
    chat_link.begin(acct.id)
    bot.post(CHAT, bot.emailed_code())
    assert chat_link.finish(acct.id).telegram.chat_id == CHAT


def test_a_code_guessed_by_the_web_tier_links_nothing(acct, bot):
    """The attack the delivery closes, spelled out. The web tier can start a
    change and post to the bot, but it cannot read the code, so the chat it
    posts from is never bound."""
    chat_link.begin(acct.id)
    bot.post(OTHER, "LL-AAAAAAAA")
    with pytest.raises(chat_link.ChangeRefused):
        chat_link.finish(acct.id)
    assert account.account_for_email(acct.id).telegram is None


def test_a_sign_in_the_daemon_watched_is_the_proof_the_email_would_ask_for(acct, bot):
    """Google just established mailbox control and this process saw it happen,
    so the inbox round trip would be asking a question that has an answer."""
    auth_recency.record(acct.id)
    action, code, _ = chat_link.begin(acct.id)

    assert action == handoff.CHAT_LINK
    assert code, "a freshly signed-in user should get the code on the page"
    assert bot.inbox == [], "nothing needed to be delivered"

    bot.post(CHAT, code)
    assert chat_link.finish(acct.id).telegram.chat_id == CHAT


def test_the_sign_in_stops_counting_once_it_is_old(acct, bot, monkeypatch):
    """A window somebody can come back to is not a step-up check. Past it, the
    code goes to the mailbox again."""
    auth_recency.record(acct.id)
    later = time.time() + auth_recency.FRESH_SECONDS + 1
    monkeypatch.setattr(auth_recency.time, "time", lambda: later)

    _action, code, _ = chat_link.begin(acct.id)
    assert code is None
    assert len(bot.inbox) == 1


def test_a_mailbox_we_cannot_write_to_refuses_rather_than_falling_back(acct, bot):
    """The fallback that would undo the control: show the code on the page
    because the insert failed. The user cannot tell that apart from the ordinary
    case, so it is exactly the shape of a control that is off and looks on."""
    bot.insert_fails = True
    with pytest.raises(chat_link.ChangeRefused) as refused:
        chat_link.begin(acct.id)

    assert str(refused.value) == chat_link.CODE_NOT_DELIVERED
    assert chat_link._pending == {}, "a change was left pending for an undelivered code"


def test_an_unlink_still_answers_with_its_code(acct, bot):
    """Unlink is answered by the chat being detached, which is already a channel
    the web tier is not on. Emailing there would be friction on the path a user
    takes to *stop* delivery."""
    auth_recency.record(acct.id)
    _link(acct, bot)
    auth_recency.forget(acct.id)

    action, code, _ = chat_link.begin(acct.id)
    assert action == handoff.CHAT_UNLINK
    assert code, "an unlink code should stay on the page"
    assert bot.inbox == [], "an unlink must not need the mailbox"


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
    _begin(acct, bot)
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
