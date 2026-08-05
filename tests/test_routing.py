"""B4 routing: account store accessor, wake spool, and webhook push routing.

Unit-level (not golden) because these pin control-flow, not outbound effects:
which account a push resolves to, that inactive users are unroutable, that the
spool coalesces, and that unparseable pushes fall back to a full sweep.
"""

import base64
import json

from backend.accounts import account
from backend.daemons import wake_queue
from backend.daemons import gmail_hook_server as hook


def _manifest(tmp_path, entries):
    p = tmp_path / "accounts.json"
    p.write_text(json.dumps({"accounts": entries}))
    return p


def _entry(email, first, last, chat, aliases=(), emails=None, status="active"):
    return {
        "id": email,
        "identity": {"first": first, "last": last,
                     "first_aliases": list(aliases),
                     "emails": emails if emails is not None else [email]},
        "telegram": {"chat_id": chat, "token": "tok"},
        "plan_status": status,
    }


def _push_body(email):
    inner = base64.b64encode(json.dumps({"emailAddress": email, "historyId": 42}).encode()).decode()
    return json.dumps({"message": {"data": inner}}).encode()


def test_get_account_resolves_and_filters(tmp_path, monkeypatch):
    monkeypatch.setattr(account, "MANIFEST", _manifest(tmp_path, [
        _entry("alice@x.com", "Alice", "Ng", "111"),
        _entry("bob@x.com", "Bob", "Fox", "222", emails=["bob@x.com", "b@alt.com"]),
        _entry("carol@x.com", "Carol", "Poe", "333", status="inactive"),
    ]))
    assert [a.id for a in account.load_accounts()] == ["alice@x.com", "bob@x.com"]
    assert account.get_account("BOB@X.COM").id == "bob@x.com"       # case-insensitive
    assert account.get_account("b@alt.com").id == "bob@x.com"       # alias address
    assert account.get_account("carol@x.com") is None              # inactive unroutable
    assert account.get_account("stranger@x.com") is None


def test_missing_manifest_refuses_rather_than_inventing_an_account(tmp_path, monkeypatch):
    """No implicit owner: an unseeded box must fail loudly. The old fallback
    silently stopped applying the moment anyone else signed up, which removed
    the owner from routing without a word."""
    monkeypatch.setattr(account, "MANIFEST", tmp_path / "does_not_exist.json")
    try:
        account.get_account("danielmorganrivers@gmail.com")
    except AssertionError as err:
        assert "seed_owner" in str(err)
    else:
        raise AssertionError("expected a missing manifest to raise")


def test_seeded_owner_is_row_one_and_survives_a_later_signup(tmp_path, monkeypatch):
    """The seed makes the owner an ordinary active entry, so a stranger signing
    up afterwards appends a row instead of displacing them."""
    from backend.accounts import seed_owner

    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "c")
    monkeypatch.setattr(account, "ACCOUNTS_DIR", tmp_path)
    monkeypatch.setattr(account, "MANIFEST", tmp_path / "accounts.json")

    owner = seed_owner.seed()
    assert owner.id == "danielmorganrivers@gmail.com"
    assert owner.plan_status == "active"
    assert account.get_account("danielmorganrivers@gmail.com").id == owner.id

    account.register_account("stranger@x.com", "Stranger", "Danger",
                             telegram_chat_id="999")
    assert [a.id for a in account.load_accounts()] == [owner.id]      # signup is inactive
    assert account.get_account("danielmorganrivers@gmail.com") is not None


def test_wake_queue_roundtrip_and_dedup(tmp_path, monkeypatch):
    monkeypatch.setattr(wake_queue, "QUEUE_FILE", tmp_path / "q.jsonl")
    monkeypatch.setattr(wake_queue, "LOCK_FILE", tmp_path / "q.lock")
    assert wake_queue.drain() == []
    wake_queue.enqueue("a"); wake_queue.enqueue("b"); wake_queue.enqueue("a")
    assert wake_queue.drain() == ["a", "b"]     # deduped, order preserved
    assert wake_queue.drain() == []             # cleared


def test_route_push(tmp_path, monkeypatch):
    monkeypatch.setattr(account, "MANIFEST", _manifest(tmp_path, [
        _entry("bob@x.com", "Bob", "Fox", "222"),
    ]))
    monkeypatch.setattr(wake_queue, "QUEUE_FILE", tmp_path / "q.jsonl")
    monkeypatch.setattr(wake_queue, "LOCK_FILE", tmp_path / "q.lock")
    signals = []
    monkeypatch.setattr(hook, "signal_daemon", lambda: signals.append(1))

    hook.route_push(_push_body("bob@x.com"))
    assert wake_queue.drain() == ["bob@x.com"] and signals == [1]

    signals.clear()
    hook.route_push(_push_body("stranger@x.com"))       # unregistered: drop, no wake
    assert wake_queue.drain() == [] and signals == []

    signals.clear()
    hook.route_push(b"not-json")                         # unparseable: full-sweep fallback
    assert wake_queue.drain() == [] and signals == [1]
