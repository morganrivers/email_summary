"""Track C onboarding: account registration writer, per-user watch renewal, and
the sign-in-with-Google callback control flow.

Unit-level (no Google, no co-signer): the OAuth exchange and the watch call are
mocked. What is pinned here is everything around them -- that a signup writes a
correct, loadable manifest entry that starts inactive; that renewal sets the
cursor once and never rewinds it; and that the callback enforces CSRF state
before provisioning.
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
        "Alice@Example.com", "Alice", "Ng",
        token_file="database/alice@example.com/token.bin",
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
    account.register_account("a@x.com", "A", "N", telegram_token="entry-token")

    acct = account.set_telegram("a@x.com", chat_id="chat-2")
    assert acct.telegram.chat_id == "chat-2"
    assert acct.telegram.token == "entry-token"      # untouched
    assert account.account_for_email("a@x.com").telegram.chat_id == "chat-2"


def test_delete_account_removes_entry_and_the_token_it_owns(tmp_path, monkeypatch):
    _use_store(tmp_path, monkeypatch)
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "chat-1")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "tok")
    token = tmp_path / "a@x.com" / "token.bin"
    token.parent.mkdir(parents=True)
    token.write_bytes(b"LLTK\x01\x01wrapped")
    monkeypatch.setattr(account.paths, "REPO_ROOT", tmp_path)
    account.register_account("a@x.com", "A", "N", token_file="a@x.com/token.bin")

    assert account.delete_account("a@x.com") is True
    assert account.all_accounts() == []
    assert not token.exists()                        # wrapped token not left behind
    assert account.delete_account("a@x.com") is False


def test_delete_account_never_removes_shared_box_paths(tmp_path, monkeypatch):
    """The seeded owner points at the box's own state/, which outlives any one
    entry. Deleting that entry must drop the row and nothing else."""
    _use_store(tmp_path, monkeypatch)
    monkeypatch.setattr(account.paths, "REPO_ROOT", tmp_path)
    shared_state = tmp_path / "state" / "state.json"
    shared_state.parent.mkdir()
    shared_state.write_text("{}")
    account.register_account("owner@x.com", "O", "W",
                             telegram_chat_id="c", state_file="state/state.json")

    assert account.delete_account("owner@x.com") is True
    assert shared_state.exists()


def test_register_account_without_chat_has_no_notification_target(tmp_path, monkeypatch):
    """A Google consent carries no Telegram chat, and no environment value may
    stand in for one: the env fallback that used to live here sent every new
    signup's draft notifications to the box owner's chat."""
    _use_store(tmp_path, monkeypatch)
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "owners-own-chat")
    acct = account.register_account("bob@x.com", "Bob", "Fox")
    assert acct.telegram is None
    assert account.account_for_email("bob@x.com").telegram is None


def test_register_account_idempotent_preserves_plan_and_polar(tmp_path, monkeypatch):
    _use_store(tmp_path, monkeypatch)
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "chat-1")
    account.register_account("c@x.com", "Cara", "Poe")
    account.set_plan_status("c@x.com", "active")
    data = json.loads((tmp_path / "accounts.json").read_text())
    data["accounts"][0]["polar_customer_id"] = "cus_123"
    (tmp_path / "accounts.json").write_text(json.dumps(data))

    # a second consent (re-onboard) must not wipe an active/paid state
    account.register_account("c@x.com", "Cara", "Poe-Smith")
    data = json.loads((tmp_path / "accounts.json").read_text())
    assert len(data["accounts"]) == 1
    entry = data["accounts"][0]
    assert entry["plan_status"] == "active"
    assert entry["polar_customer_id"] == "cus_123"
    assert entry["identity"]["last"] == "Poe-Smith"


def _fake_watch(monkeypatch, result):
    monkeypatch.setattr(watch_renew.gmail_api, "register_watch",
                        lambda acct, topic: result)


def _one_account(tmp_path, monkeypatch):
    _use_store(tmp_path, monkeypatch)
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "chat-1")
    acct = account.register_account("d@x.com", "Dee", "Ray")
    (tmp_path / "d@x.com").mkdir(parents=True, exist_ok=True)  # state file parent
    return acct


def test_renew_sets_cursor_on_first_registration(tmp_path, monkeypatch):
    acct = _one_account(tmp_path, monkeypatch)
    _fake_watch(monkeypatch, {"historyId": "1000", "expiration": "1700000000000"})
    watch_renew.renew_account(acct, log=lambda m: None)
    s = acct.state.load()
    assert s["lastHistoryId"] == "1000"
    assert s["watchExpiration"] == "1700000000000"


def test_renew_does_not_rewind_existing_cursor(tmp_path, monkeypatch):
    acct = _one_account(tmp_path, monkeypatch)
    acct.state.update(lastHistoryId="5000", watchExpiration="1")
    _fake_watch(monkeypatch, {"historyId": "1000", "expiration": "1700000000000"})
    watch_renew.renew_account(acct, log=lambda m: None)
    s = acct.state.load()
    assert s["lastHistoryId"] == "5000"                 # cursor untouched
    assert s["watchExpiration"] == "1700000000000"      # expiry refreshed


def test_callback_rejects_a_state_this_browser_is_not_waiting_on(monkeypatch):
    with pytest.raises(ob.ProvisionError) as ei:
        ob.handle_callback({"code": "c", "state": "abc"}, lambda s: False, REDIRECT)
    assert ei.value.code == 403


def test_callback_surfaces_consent_denial(monkeypatch):
    with pytest.raises(ob.ProvisionError) as ei:
        ob.handle_callback({"error": "access_denied"}, lambda s: True, REDIRECT)
    assert ei.value.code == 400


def test_callback_happy_path_provisions_and_lands_in_the_app(monkeypatch):
    seen = {}

    class Acct:
        id = "e@x.com"

    def fake_provision(code, redirect_uri, state):
        seen["code"] = code
        seen["redirect"] = redirect_uri
        seen["state"] = state
        return Acct()

    monkeypatch.setattr(ob, "provision", fake_provision)
    monkeypatch.delenv("POLAR_SANDBOX", raising=False)
    monkeypatch.setenv("POLAR_CHECKOUT_URL", "https://polar.sh/checkout/abc")
    acct, loc = ob.handle_callback(
        {"code": "the-code", "state": "s"}, lambda s: s == "s", REDIRECT)
    assert acct.id == "e@x.com"
    assert seen["code"] == "the-code" and seen["redirect"] == REDIRECT
    assert loc == "/dashboard", "signing in must not push the user into checkout"


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


# --- the Python OAuth path (Track I5) -------------------------------------
#
# The exchange moved out of Node because Google binds the refresh token to the
# co-signer's DPoP key at that one request. What is pinned here is that the
# binding is actually asked for, that the PKCE verifier survives the redirect
# without being stored anywhere, and that a signup ends with a wrapped token and
# an account rather than either one alone.

import base64
import hashlib
import json as _json
from urllib.parse import parse_qs, urlparse

from backend import secrets
from backend.custody import client as cosigner
from backend.custody import tokens
from backend.custody import wrapping
from backend.integrations.gmail_gcal import gmail_api, oauth_app


@pytest.fixture
def consent(tmp_path, monkeypatch):
    """A box that can run a consent: dev app secret, throwaway OAuth app keys,
    an empty store, and a co-signer that wraps and signs without ever being
    handed a token."""
    monkeypatch.setenv(wrapping.DEV_SECRET_ENV, "dev-secret-for-tests-0123456789")
    monkeypatch.delenv("TEE_REQUIRED", raising=False)
    monkeypatch.setattr(wrapping, "_app_secret_cache", None)
    keys = tmp_path / "gcp-oauth.keys.json"
    keys.write_text(_json.dumps(
        {"web": {"client_id": "cid", "client_secret": "csecret"}}))
    monkeypatch.setenv(oauth_app.KEYS_ENV, str(keys))
    monkeypatch.delenv(secrets.GOOGLE_CLIENT_ID_ENV, raising=False)
    monkeypatch.delenv(secrets.GOOGLE_CLIENT_SECRET_ENV, raising=False)
    monkeypatch.setattr(account, "ACCOUNTS_DIR", tmp_path / "database")
    monkeypatch.setattr(account, "MANIFEST", tmp_path / "database" / "accounts.json")
    monkeypatch.setattr(cosigner, "dpop_jwk",
                        lambda: {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"})
    monkeypatch.setattr(cosigner, "sign_dpop",
                        lambda htm, htu, nonce=None: f"proof.{htm}.{nonce or ''}")
    monkeypatch.setattr(cosigner, "wrap", lambda uid, inner: b"outer:" + bytes(inner))
    tokens.forget()
    yield tmp_path
    monkeypatch.setattr(wrapping, "_app_secret_cache", None)
    tokens.forget()


def test_auth_url_asks_google_to_bind_the_cosigners_key(consent):
    url = ob.build_auth_url("state-123", REDIRECT)
    params = parse_qs(urlparse(url).query)
    assert params["dpop_jkt"] == [cosigner.dpop_jkt()], (
        "without dpop_jkt Google issues an unbound refresh token, which is "
        "usable by anyone who ever holds it"
    )
    assert params["code_challenge_method"] == ["S256"]
    assert params["access_type"] == ["offline"] and params["prompt"] == ["consent"]
    assert params["redirect_uri"] == [REDIRECT]


def test_the_pkce_verifier_is_derived_not_stored(consent):
    """It has to survive a redirect through Google. Deriving it from the
    enclave's own secret means the exchange reproduces it exactly and a restart
    between the two halves of a sign-in does not strand the user."""
    url = ob.build_auth_url("state-123", REDIRECT)
    challenge = parse_qs(urlparse(url).query)["code_challenge"][0]
    verifier = ob.pkce_verifier("state-123")
    digest = hashlib.sha256(verifier.encode()).digest()
    assert challenge == base64.urlsafe_b64encode(digest).decode().rstrip("=")
    assert ob.pkce_verifier("a-different-state") != verifier


def _google_says(monkeypatch, payload, status=200, seen=None):
    class R:
        status_code = status
        headers = {}
        text = _json.dumps(payload)

        def json(self):
            return payload

    def post(*a, **k):
        if seen is not None:
            seen.update(k.get("data") or {})
        return R()

    monkeypatch.setattr(tokens.requests, "post", post)


def test_the_consent_runs_on_an_injected_oauth_app_with_no_file_present(consent,
                                                                       monkeypatch):
    """Plan §8: the client secret is the widest-blast-radius value the
    deployment holds and the last one that was read off a volume. Inside the
    enclave there is no `.gmail-mcp` mount at all, so both halves of the consent
    -- the auth URL and the code exchange -- have to run on the injected pair."""
    monkeypatch.setenv(oauth_app.KEYS_ENV, str(consent / "no-such-keys.json"))
    monkeypatch.setenv(secrets.GOOGLE_CLIENT_ID_ENV, "injected-id")
    monkeypatch.setenv(secrets.GOOGLE_CLIENT_SECRET_ENV, "injected-secret")
    posted = {}
    _google_says(monkeypatch, {
        "access_token": "ya29.x", "refresh_token": "1//0gRefreshValue",
        "expires_in": 3600,
    }, seen=posted)
    monkeypatch.setattr(gmail_api, "profile_address", lambda token: "inj@example.com")

    params = parse_qs(urlparse(ob.build_auth_url("state-123", REDIRECT)).query)
    assert params["client_id"] == ["injected-id"]

    ob.exchange_code("the-code", REDIRECT, "state-123")
    assert posted["client_id"] == "injected-id"
    assert posted["client_secret"] == "injected-secret"


def test_provision_takes_custody_and_registers_the_account(consent, monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "tok")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "chat")
    _google_says(monkeypatch, {
        "access_token": "ya29.x",
        "refresh_token": "1//0gRefreshValue",
        "expires_in": 3600,
        "id_token": ".".join([
            "hdr",
            base64.urlsafe_b64encode(
                _json.dumps({"given_name": "Dana", "family_name": "Reed"}).encode()
            ).decode().rstrip("="),
            "sig",
        ]),
    })
    monkeypatch.setattr(gmail_api, "profile_address", lambda token: "dana@example.com")
    monkeypatch.setattr(ob.watch_renew, "renew_account", lambda acct, log=None: None)

    acct = ob.provision("the-code", REDIRECT, "state-123")

    assert acct.id == "dana@example.com" and acct.plan_status == "inactive"
    assert acct.identity.first == "Dana" and acct.identity.last == "Reed"
    token_blob = tokens.token_path("dana@example.com").read_bytes()
    assert b"1//0gRefreshValue" not in token_blob, "the refresh token was stored readable"
    assert token_blob.startswith(tokens.RECORD_MAGIC)


def test_a_refused_signup_does_not_leave_a_token_behind(consent, monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "tok")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "chat")
    _google_says(monkeypatch, {
        "access_token": "ya29.x", "refresh_token": "1//0gRefreshValue",
        "expires_in": 3600,
    })
    monkeypatch.setattr(gmail_api, "profile_address", lambda token: "late@example.com")
    monkeypatch.setattr(account, "MAX_ACCOUNTS", 0)

    with pytest.raises(ob.ProvisionError) as ei:
        ob.provision("the-code", REDIRECT, "state-123")
    assert ei.value.code == 503
    assert not tokens.has_custody("late@example.com"), (
        "a token we cannot use was left on disk"
    )


def test_a_consent_without_a_refresh_token_is_refused(consent, monkeypatch):
    _google_says(monkeypatch, {"access_token": "ya29.x", "expires_in": 3600})
    with pytest.raises(ob.ProvisionError) as ei:
        ob.exchange_code("the-code", REDIRECT, "state-123")
    assert ei.value.code == 502


def test_provision_fails_closed_when_the_cosigner_is_down(consent, monkeypatch):
    _google_says(monkeypatch, {
        "access_token": "ya29.x", "refresh_token": "1//0gRefreshValue",
        "expires_in": 3600,
    })
    monkeypatch.setattr(gmail_api, "profile_address", lambda token: "x@example.com")

    def refuse(uid, inner):
        raise cosigner.CoSignerUnavailable("connection refused")

    monkeypatch.setattr(cosigner, "wrap", refuse)
    with pytest.raises(ob.ProvisionError) as ei:
        ob.provision("the-code", REDIRECT, "state-123")
    assert ei.value.code == 503
    assert account.MANIFEST.exists() is False, (
        "an account was registered for a mailbox we cannot reach"
    )
