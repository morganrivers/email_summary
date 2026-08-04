"""Track C onboarding: account registration writer, per-user watch renewal, and
the sign-in-with-Google callback control flow.

Unit-level (no Google, no Node): the OAuth exchange and watch API call are the
Node boundary and are mocked. What is pinned here is the Python side -- that a
signup writes a correct, loadable manifest entry that starts inactive; that
renewal sets the cursor once and never rewinds it; and that the callback
enforces CSRF state before provisioning.
"""

import json

import pytest

from backend.accounts import account
from backend.onboarding import watch_renew
from backend.onboarding import provisioning as ob

REDIRECT = "https://example.test/auth/callback"


def _use_store(tmp_path, monkeypatch):
    monkeypatch.setattr(account, "ACCOUNTS_DIR", tmp_path)
    monkeypatch.setattr(account, "MANIFEST", tmp_path / "accounts.json")


def test_register_account_writes_inactive_loadable_entry(tmp_path, monkeypatch):
    _use_store(tmp_path, monkeypatch)
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "chat-1")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "tok")

    acct = account.register_account(
        "Alice@Example.com", "Alice", "Ng", "accounts/alice@example.com/.gmail-mcp"
    )
    assert acct.id == "alice@example.com"
    assert acct.plan_status == "inactive"
    assert acct.identity.emails == ["alice@example.com"]

    data = json.loads((tmp_path / "accounts.json").read_text())
    assert [e["id"] for e in data["accounts"]] == ["alice@example.com"]

    # inactive -> unroutable until billing flips it active
    assert account.get_account("alice@example.com") is None
    account.set_plan_status("alice@example.com", "active")
    assert account.get_account("alice@example.com").id == "alice@example.com"


def test_set_telegram_updates_chat_id_only(tmp_path, monkeypatch):
    _use_store(tmp_path, monkeypatch)
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "chat-1")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "tok")
    account.register_account("a@x.com", "A", "N", "d/a/.gmail-mcp",
                             telegram_token="entry-token")

    acct = account.set_telegram("a@x.com", chat_id="chat-2")
    assert acct.telegram.chat_id == "chat-2"
    assert acct.telegram.token == "entry-token"      # untouched
    assert account.account_for_email("a@x.com").telegram.chat_id == "chat-2"


def test_delete_account_removes_entry_and_the_creds_it_owns(tmp_path, monkeypatch):
    _use_store(tmp_path, monkeypatch)
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "chat-1")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "tok")
    creds = tmp_path / "a@x.com" / ".gmail-mcp"
    creds.mkdir(parents=True)
    (creds / "credentials.json").write_text("{}")
    monkeypatch.setattr(account.paths, "REPO_ROOT", tmp_path)
    account.register_account("a@x.com", "A", "N", "a@x.com/.gmail-mcp")

    assert account.delete_account("a@x.com") is True
    assert account.all_accounts() == []
    assert not creds.exists()                        # refresh token not left behind
    assert account.delete_account("a@x.com") is False


def test_delete_account_never_removes_shared_box_paths(tmp_path, monkeypatch):
    """The seeded owner points at the top-level .gmail-mcp and state/, which
    belong to the box. Deleting that entry must drop the row and nothing else."""
    _use_store(tmp_path, monkeypatch)
    monkeypatch.setattr(account.paths, "REPO_ROOT", tmp_path)
    shared_creds = tmp_path / ".gmail-mcp"
    shared_creds.mkdir()
    shared_state = tmp_path / "state" / "state.json"
    shared_state.parent.mkdir()
    shared_state.write_text("{}")
    account.register_account("owner@x.com", "O", "W", ".gmail-mcp",
                             telegram_chat_id="c", state_file="state/state.json")

    assert account.delete_account("owner@x.com") is True
    assert shared_creds.exists() and shared_state.exists()


def test_register_account_without_chat_has_no_notification_target(tmp_path, monkeypatch):
    """A Google consent carries no Telegram chat, and no environment value may
    stand in for one: the env fallback that used to live here sent every new
    signup's draft notifications to the box owner's chat."""
    _use_store(tmp_path, monkeypatch)
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "owners-own-chat")
    acct = account.register_account("bob@x.com", "Bob", "Fox",
                                    "accounts/bob@x.com/.gmail-mcp")
    assert acct.telegram is None
    assert account.account_for_email("bob@x.com").telegram is None


def test_register_account_idempotent_preserves_plan_and_polar(tmp_path, monkeypatch):
    _use_store(tmp_path, monkeypatch)
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "chat-1")
    account.register_account("c@x.com", "Cara", "Poe", "accounts/c@x.com/.gmail-mcp")
    account.set_plan_status("c@x.com", "active")
    data = json.loads((tmp_path / "accounts.json").read_text())
    data["accounts"][0]["polar_customer_id"] = "cus_123"
    (tmp_path / "accounts.json").write_text(json.dumps(data))

    # a second consent (re-onboard) must not wipe an active/paid state
    account.register_account("c@x.com", "Cara", "Poe-Smith", "accounts/c@x.com/.gmail-mcp")
    data = json.loads((tmp_path / "accounts.json").read_text())
    assert len(data["accounts"]) == 1
    entry = data["accounts"][0]
    assert entry["plan_status"] == "active"
    assert entry["polar_customer_id"] == "cus_123"
    assert entry["identity"]["last"] == "Poe-Smith"


def _fake_node(monkeypatch, result):
    payload = json.dumps(result).encode()

    def fake_run(cmd, **kw):
        class R:
            returncode = 0
            stdout = payload
            stderr = b""
        return R()
    monkeypatch.setattr(watch_renew.subprocess, "run", fake_run)


def _one_account(tmp_path, monkeypatch):
    _use_store(tmp_path, monkeypatch)
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "chat-1")
    acct = account.register_account("d@x.com", "Dee", "Ray", "accounts/d@x.com/.gmail-mcp")
    (tmp_path / "d@x.com").mkdir(parents=True, exist_ok=True)  # state file parent
    return acct


def test_renew_sets_cursor_on_first_registration(tmp_path, monkeypatch):
    acct = _one_account(tmp_path, monkeypatch)
    _fake_node(monkeypatch, {"historyId": "1000", "expiration": "1700000000000"})
    watch_renew.renew_account(acct, log=lambda m: None)
    s = acct.state.load()
    assert s["lastHistoryId"] == "1000"
    assert s["watchExpiration"] == "1700000000000"


def test_renew_does_not_rewind_existing_cursor(tmp_path, monkeypatch):
    acct = _one_account(tmp_path, monkeypatch)
    acct.state.update(lastHistoryId="5000", watchExpiration="1")
    _fake_node(monkeypatch, {"historyId": "1000", "expiration": "1700000000000"})
    watch_renew.renew_account(acct, log=lambda m: None)
    s = acct.state.load()
    assert s["lastHistoryId"] == "5000"                 # cursor untouched
    assert s["watchExpiration"] == "1700000000000"      # expiry refreshed


def test_callback_rejects_state_mismatch(monkeypatch):
    with pytest.raises(ob.ProvisionError) as ei:
        ob.handle_callback({"code": "c", "state": "abc"}, "different", REDIRECT)
    assert ei.value.code == 403


def test_callback_rejects_missing_cookie(monkeypatch):
    with pytest.raises(ob.ProvisionError) as ei:
        ob.handle_callback({"code": "c", "state": "abc"}, None, REDIRECT)
    assert ei.value.code == 403


def test_callback_surfaces_consent_denial(monkeypatch):
    with pytest.raises(ob.ProvisionError) as ei:
        ob.handle_callback({"error": "access_denied"}, "x", REDIRECT)
    assert ei.value.code == 400


def test_callback_happy_path_provisions_and_redirects(monkeypatch):
    seen = {}

    class Acct:
        id = "e@x.com"

    def fake_provision(code, redirect_uri):
        seen["code"] = code
        seen["redirect"] = redirect_uri
        return Acct()

    monkeypatch.setattr(ob, "provision", fake_provision)
    monkeypatch.delenv("POLAR_SANDBOX", raising=False)
    monkeypatch.setenv("POLAR_CHECKOUT_URL", "https://polar.sh/checkout/abc")
    acct, loc = ob.handle_callback({"code": "the-code", "state": "s"}, "s", REDIRECT)
    assert acct.id == "e@x.com"
    assert seen["code"] == "the-code" and seen["redirect"] == REDIRECT
    assert loc == "https://polar.sh/checkout/abc?customer_email=e%40x.com"


def test_checkout_redirect_falls_back_without_polar(monkeypatch):
    monkeypatch.delenv("POLAR_SANDBOX", raising=False)
    monkeypatch.setenv("POLAR_CHECKOUT_URL", "")
    assert ob.checkout_redirect("z@x.com", fallback="/dashboard") == "/dashboard"


def test_checkout_redirect_uses_sandbox_url_when_toggled(monkeypatch):
    monkeypatch.setenv("POLAR_SANDBOX", "1")
    monkeypatch.setenv("POLAR_CHECKOUT_URL", "https://buy.polar.sh/prod")
    monkeypatch.setenv("POLAR_CHECKOUT_URL_SANDBOX", "https://sandbox.polar.sh/dev")
    loc = ob.checkout_redirect("z@x.com")
    assert loc == "https://sandbox.polar.sh/dev?customer_email=z%40x.com"
