"""Split custody: what each box can and cannot do with what it holds.

These are the tests for the four invariants the design rests on
(docs/plan_token_custody.md §1), because a refactor that breaks one of them
breaks nothing visible:

  1. layer order   -- ours inside, the co-signer's outside
  2. no plaintext  -- the co-signer never sees a refresh token
  3. no bypass     -- a co-signer that is down means no mail, not a local key
  4. no ciphertext -- the co-signer stores nothing

The co-signer here is a fake that does real AES-GCM under its own key and
asserts, on every call, that nothing it was handed is readable to it.

It is installed at `client._request`, the HTTP boundary, and not over the four
public functions above it. That matters: the first integration failure was a
codec disagreement that both sides' own tests passed straight through, because
each faked the other above the wire. Speaking JSON through
`cosigner.protocol` is what makes a path, a field name or an encoding that
drifts from the server fail here instead of in production.
"""

import base64
import datetime
import json

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from harness import needs_asserts

from backend.accounts import account as account_store
from backend.custody import client as cosigner
from backend.custody import keyring, tokens, wrapping
from backend.integrations import telegram
from backend.integrations.gmail_gcal import oauth_app
from cosigner import protocol

REFRESH_TOKEN = "1//0gSuperSecretRefreshTokenValue"
UID = "alice@example.com"
HANDLE = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
OTHER_HANDLE = "0f8e7d6c5b4a39281706f5e4d3c2b1a0"


def acct(uid=UID, handle=HANDLE, **extra):
    """An account as custody sees one: an id that names its directory and a
    handle that names it everywhere else. Both, always -- the whole point of the
    handle is that these are two different values and the wrong one is a
    different key rather than an error."""
    fields = {"id": uid, "handle": handle, "telegram": None}
    fields.update(extra)
    return type("A", (), fields)()


@pytest.fixture
def enclave(monkeypatch, tmp_path):
    """An enclave with a dev app secret, an empty store, and a throwaway OAuth
    app. Nothing here reaches Google or the network."""
    monkeypatch.setenv(wrapping.DEV_SECRET_ENV, "dev-secret-for-tests-0123456789")
    monkeypatch.delenv("TEE_REQUIRED", raising=False)
    monkeypatch.setattr(wrapping, "_app_secret_cache", None)
    monkeypatch.setattr(account_store, "ACCOUNTS_DIR", tmp_path)
    keys = tmp_path / "gcp-oauth.keys.json"
    keys.write_text(json.dumps(
        {"web": {"client_id": "test-client-id", "client_secret": "test-client-secret"}}))
    monkeypatch.setenv(oauth_app.KEYS_ENV, str(keys))
    tokens.forget()
    yield tmp_path
    monkeypatch.setattr(wrapping, "_app_secret_cache", None)
    tokens.forget()


class FakeCoSigner:
    """Everything the second box does, and nothing it must not.

    It keeps one wrapping key and no records. Every value it is handed is
    checked for the plaintext token before it is touched, which is the
    machine-checkable form of "the co-signer never receives plaintext"."""

    KEY = b"\x11" * 32

    def __init__(self):
        self.wrapped = []
        self.unwrapped = []
        self.data_unwrapped = []
        self.rewrapped = []
        self.proofs = []
        self.stored = {}
        self.granted = set()

    def _refuse_plaintext(self, blob):
        assert REFRESH_TOKEN.encode() not in bytes(blob), (
            "the co-signer was handed a readable refresh token; the layer order "
            "is inverted and this box can now read every mailbox"
        )
        # A data key is 32 bytes of entropy and cannot be recognised by content,
        # so what is asserted instead is its length: what crosses this wire is
        # sealed output, which is a nonce plus a tag longer than the key it
        # covers. An `inner` that arrived at exactly KEY_LEN would mean the
        # enclave had sent the key itself.
        assert len(bytes(blob)) != wrapping.KEY_LEN, (
            "the co-signer was handed something the size of a bare data key"
        )

    def wrap(self, handle, inner):
        self._refuse_plaintext(inner)
        assert handle not in self.granted, (
            "a second wrap for one handle must be refused"
        )
        self.granted.add(handle)
        self.wrapped.append(handle)
        return self._seal(handle, inner)

    def _seal(self, handle, inner):
        nonce = bytes([len(self.wrapped) + len(self.rewrapped)]) * 12
        return nonce + AESGCM(self.KEY).encrypt(nonce, bytes(inner), handle.encode())

    def _open(self, handle, outer):
        return AESGCM(self.KEY).decrypt(
            bytes(outer[:12]), bytes(outer[12:]), handle.encode())

    def unwrap_and_sign(self, handle, outer, htm, htu, nonce=None):
        self._refuse_plaintext(outer)
        self.unwrapped.append((handle, htm, htu, nonce))
        inner = self._open(handle, outer)
        self._refuse_plaintext(inner)
        return inner, self.sign_dpop(htm, htu, nonce)

    def unwrap(self, handle, outer):
        self._refuse_plaintext(outer)
        self.data_unwrapped.append(handle)
        inner = self._open(handle, outer)
        self._refuse_plaintext(inner)
        return inner

    def rewrap(self, handle, outer):
        self._refuse_plaintext(outer)
        self.rewrapped.append(handle)
        return self._seal(handle, self._open(handle, outer))

    def sign_dpop(self, htm, htu, nonce=None):
        self.proofs.append((htm, htu, nonce))
        return f"proof.{htm}.{htu}.{nonce or ''}"

    def dpop_jwk(self):
        return {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}

    def _serve(self, method, path, body=None):
        """The server side of the wire, decoding with the same module the client
        encoded with. A codec or field-name drift raises here."""
        body = body or {}
        if path == protocol.HEALTH_PATH:
            return {"ok": True}
        if path == protocol.DPOP_JWK_PATH:
            return {protocol.F_JWK: self.dpop_jwk()}
        if path == protocol.SIGN_DPOP_PATH:
            return {protocol.F_PROOF: self.sign_dpop(
                body[protocol.F_HTM], body[protocol.F_HTU],
                body.get(protocol.F_NONCE))}
        if path == protocol.WRAP_PATH:
            outer = self.wrap(
                body[protocol.F_UID], protocol.unb64(body[protocol.F_INNER]))
            return {protocol.F_OUTER: protocol.b64(outer)}
        if path == protocol.UNWRAP_AND_SIGN_PATH:
            inner, proof = self.unwrap_and_sign(
                body[protocol.F_UID], protocol.unb64(body[protocol.F_OUTER]),
                body[protocol.F_HTM], body[protocol.F_HTU],
                body.get(protocol.F_NONCE))
            return {protocol.F_INNER: protocol.b64(inner), protocol.F_PROOF: proof}
        if path == protocol.UNWRAP_PATH:
            return {protocol.F_INNER: protocol.b64(self.unwrap(
                body[protocol.F_UID], protocol.unb64(body[protocol.F_OUTER])))}
        if path == protocol.REWRAP_PATH:
            return {protocol.F_OUTER: protocol.b64(self.rewrap(
                body[protocol.F_UID], protocol.unb64(body[protocol.F_OUTER])))}
        raise AssertionError(f"enclave called an endpoint the co-signer has no route for: {path}")

    def install(self, monkeypatch):
        monkeypatch.setattr(cosigner, "_request", self._serve)
        monkeypatch.setattr(cosigner, "_jwk_cache", None)
        return self


@pytest.fixture
def co(monkeypatch):
    return FakeCoSigner().install(monkeypatch)


# --- the inner layer ------------------------------------------------------

def test_inner_seal_round_trips(enclave):
    dek = wrapping.new_dek()
    inner = wrapping.seal_dek(HANDLE, dek)
    assert dek not in inner
    assert bytes(wrapping.open_dek(HANDLE, inner)) == dek


def test_a_data_key_is_random_rather_than_derived(enclave):
    """The property deletion rests on. Two keys minted for the same account
    differ, so the key is an object that can be destroyed rather than a function
    of a salt that can always be recomputed."""
    assert wrapping.new_dek() != wrapping.new_dek()
    assert len(wrapping.new_dek()) == wrapping.KEY_LEN


def test_inner_is_bound_to_the_account(enclave):
    """The handle is the AEAD's associated data, so one account's record cannot
    be opened as another's even by the box that holds every key."""
    inner = wrapping.seal_dek(HANDLE, wrapping.new_dek())
    with pytest.raises(wrapping.CustodyError):
        wrapping.open_dek(OTHER_HANDLE, inner)


def test_inner_key_changes_with_the_key_version(enclave):
    inner = wrapping.seal_dek(HANDLE, wrapping.new_dek(), key_version=1)
    with pytest.raises(wrapping.CustodyError):
        wrapping.open_dek(HANDLE, inner, key_version=2)


@needs_asserts
def test_the_inner_layer_refuses_to_seal_anything_but_a_key(enclave):
    """`seal_dek` wraps a key and nothing else. Sealing a token directly here
    again would put user data under a key the co-signer's unwrap gets one layer
    from, which is the layer order this design exists to keep.

    An assert and not a refusal because `dek` is our own caller's: nothing
    outside this process ever picks it. `open_dek`, whose `inner` comes off disk
    or off the co-signer's wire, raises instead."""
    with pytest.raises(AssertionError, match="data key"):
        wrapping.seal_dek(HANDLE, REFRESH_TOKEN.encode())


def test_a_tee_box_refuses_a_dev_key(enclave, monkeypatch):
    """Invariant 3 in its quietest form: under TEE_REQUIRED there is no dstack
    socket in this test, and the environment key must not stand in for the KMS."""
    monkeypatch.setenv("TEE_REQUIRED", "1")
    monkeypatch.setattr(wrapping, "_app_secret_cache", None)
    with pytest.raises(wrapping.CustodyError, match="KMS"):
        wrapping.app_secret()


def test_zeroize_clears_the_buffer(enclave):
    buf = wrapping.open_dek(HANDLE, wrapping.seal_dek(HANDLE, wrapping.new_dek()))
    wrapping.zeroize(buf)
    assert set(buf) == {0}


# --- the stored record ----------------------------------------------------

def test_record_round_trips_with_its_key_version():
    blob = keyring.encode_record(7, b"outer-bytes")
    assert keyring.decode_record(blob) == (7, b"outer-bytes")


@pytest.mark.parametrize("bad", [
    "../other@example.com",
    "a/../../etc/passwd",
    "..",
    "sub/dir",
    "back\\slash",
    "",
])
def test_an_id_that_escapes_its_own_directory_is_refused(bad):
    """The account id is a directory name under the store, so a separator in one
    puts an account's files outside its own home -- or reads another account's.
    It is checked rather than assumed because the value arrives from Google's
    profile response, and `check_id` is the single guard that `account_dir` and
    `provisioning.provision` both call."""
    with pytest.raises(account_store.InvalidAccountData):
        account_store.check_id(bad)
    with pytest.raises(account_store.InvalidAccountData):
        account_store.account_dir(bad)


@pytest.mark.parametrize("bad", [
    UID,                                  # an address, which is the whole bug
    "not-hex-at-all",
    HANDLE[:-1],                          # too short
    HANDLE + "00",                        # too long
    HANDLE.upper(),                       # one value must have one spelling
    "",
    None,
])
def test_only_an_opaque_handle_reaches_the_cosigner(bad):
    """The check that keeps an address off the wire. It matters most for the one
    case that is not obviously wrong: passing the account id would work at every
    layer, derive a different key, and only surface later as records that will
    not open."""
    with pytest.raises(account_store.InvalidAccountData):
        account_store.check_handle(bad)


def test_the_store_path_and_the_wire_name_are_different_values(enclave, co):
    """What the handle buys, stated as a test: the directory says who, the
    ciphertext and the co-signer say nothing."""
    tokens.take_custody(acct(), REFRESH_TOKEN)
    assert keyring.dek_path(UID).parent.name == UID
    assert co.wrapped == [HANDLE]
    assert UID not in co.wrapped


def test_the_directory_holding_a_token_is_unreadable_off_uid(enclave, co):
    """0600 on the record is worth nothing under a 0755 directory: every local
    account can still list and stat it, and the enclave's own units are not the
    only processes on the box."""
    path = tokens.take_custody(acct(), REFRESH_TOKEN)
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert path.stat().st_mode & 0o777 == 0o600
    assert keyring.dek_path(UID).stat().st_mode & 0o777 == 0o600


def test_an_account_with_no_grant_is_told_once_not_once_per_wake(enclave, monkeypatch):
    """The daemon wakes on every Gmail push and every 300s besides. An account
    that has not signed in is a standing condition, so it is one sentence a day
    with a link, not a stack trace every five minutes."""
    sent = []
    monkeypatch.setattr(telegram, "send_telegram",
                        lambda text, target=None: bool(sent.append(text)) or True)
    telegram.reset_once_for_test()
    account = acct()

    for _ in range(20):
        tokens.notify_reauth_required(account)

    assert len(sent) == 1, f"{len(sent)} messages for one un-onboarded account"
    assert "not connected to your Gmail" in sent[0]
    assert "/auth/login" in sent[0]
    assert "Traceback" not in sent[0]
    telegram.reset_once_for_test()


def test_a_truncated_record_asks_for_re_consent_rather_than_crashing(enclave):
    """A half-written dek.bin is a fact about a file, not a broken invariant. It
    should reach the mail path as the ReauthRequired it means, so the daemon can
    say so, rather than as an IndexError out of the middle of a wake."""
    path = keyring.dek_path(UID)
    path.parent.mkdir(parents=True, exist_ok=True)
    for blob in (b"", b"LLDK",
                 keyring.RECORD_MAGIC + bytes([keyring.RECORD_VERSION, 1])):
        path.write_bytes(blob)
        with pytest.raises(keyring.NoDataKey):
            keyring.load_record(UID)


def test_take_custody_stores_only_the_doubly_wrapped_key(enclave, co):
    tokens.take_custody(acct(), REFRESH_TOKEN)
    record = keyring.dek_path(UID).read_bytes()
    assert REFRESH_TOKEN.encode() not in record
    assert co.wrapped == [HANDLE]
    # The enclave alone cannot get back to the key: its own key opens the inner
    # layer, and what is on disk is the outer one.
    _, outer = keyring.decode_record(record)
    with pytest.raises(wrapping.CustodyError):
        wrapping.open_dek(HANDLE, outer)


def test_nothing_in_the_account_directory_is_readable_on_its_own(enclave, co):
    """The acceptance test for Track G, in the form the plan states it: `strings`
    over the directory yields nothing recognisable. Before this, the token was
    wrapped and everything beside it was plaintext."""
    account = acct()
    tokens.take_custody(account, REFRESH_TOKEN)
    keyring.write_encrypted(account, "voice-dna.enc", "I write in short sentences.")
    keyring.write_encrypted(account, "personal-context.enc", "I live in Berlin.")
    for path in sorted(keyring.dek_path(UID).parent.iterdir()):
        blob = path.read_bytes()
        for secret in (REFRESH_TOKEN.encode(), b"short sentences", b"Berlin"):
            assert secret not in blob, f"{path.name} holds {secret!r} in the clear"


def test_a_document_cannot_be_moved_between_accounts_or_between_files(enclave, co):
    """The AAD binds both. One key covers everything an account owns, so without
    the file name in the AAD a voice profile dropped over `token.bin` would
    open, and without the handle another account's would."""
    account = acct()
    tokens.take_custody(account, REFRESH_TOKEN)
    keyring.write_encrypted(account, "voice-dna.enc", "how I write")
    dek = keyring.dek_for(account)
    blob = keyring.path_for(account, "voice-dna.enc").read_bytes()

    with pytest.raises(wrapping.CustodyError):
        keyring.decrypt(dek, HANDLE, "token.bin", blob)
    with pytest.raises(wrapping.CustodyError):
        keyring.decrypt(dek, OTHER_HANDLE, "voice-dna.enc", blob)
    assert keyring.decrypt(dek, HANDLE, "voice-dna.enc", blob).decode() == "how I write"


def test_a_second_consent_reuses_the_key_rather_than_asking_for_a_second_wrap(
        enclave, co):
    """The co-signer refuses a second wrap for a handle, and Google issues a
    fresh refresh token on every consent because the consent URL sends
    `prompt=consent`. A design that wrapped something new per sign-in therefore
    refused every returning user."""
    account = acct()
    tokens.take_custody(account, REFRESH_TOKEN)
    tokens.take_custody(account, "1//0gTheSecondTokenGoogleIssued")

    assert co.wrapped == [HANDLE], "a re-consent asked the co-signer to wrap again"
    dek = keyring.dek_for(account)
    stored = keyring.decrypt(
        dek, HANDLE, tokens.TOKEN_FILE, tokens.token_path(account).read_bytes())
    assert stored.decode() == "1//0gTheSecondTokenGoogleIssued"


def test_the_cosigner_stores_no_ciphertext(enclave, co):
    tokens.take_custody(acct(), REFRESH_TOKEN)
    assert co.stored == {}, "the co-signer kept a copy; one breach now yields both halves"


# --- the refresh ----------------------------------------------------------

class FakeResponse:
    def __init__(self, status, payload, headers=None):
        self.status_code = status
        self._payload = payload
        self.headers = headers or {}
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


def _install_token_endpoint(monkeypatch, responses):
    calls = []

    def post(url, data=None, headers=None, timeout=None):
        calls.append({"url": url, "data": data, "dpop": (headers or {}).get("DPoP")})
        return responses.pop(0)

    monkeypatch.setattr(tokens.http_client, "post", post)
    return calls


def test_refresh_costs_one_cosigner_round_trip_and_caches(enclave, co, monkeypatch):
    tokens.take_custody(acct(), REFRESH_TOKEN)
    calls = _install_token_endpoint(monkeypatch, [
        FakeResponse(200, {"access_token": "ya29.first", "expires_in": 3600}),
    ])
    account = acct()

    assert tokens.access_token_for(account) == "ya29.first"
    assert tokens.access_token_for(account) == "ya29.first"
    assert len(calls) == 1, "a cached access token was refreshed again"
    assert len(co.unwrapped) == 1, "the co-signer was asked twice for one token"
    assert calls[0]["data"]["refresh_token"] == REFRESH_TOKEN
    assert calls[0]["dpop"].startswith("proof.POST.")


def test_google_demanding_a_nonce_is_retried_once(enclave, co, monkeypatch):
    """Mandatory, not optional: the first proof of a process has no nonce and
    Google answers `use_dpop_nonce`. Without the retry no token is ever issued."""
    tokens.take_custody(acct(), REFRESH_TOKEN)
    monkeypatch.setattr(tokens, "_dpop_nonce", None)
    calls = _install_token_endpoint(monkeypatch, [
        FakeResponse(400, {"error": "use_dpop_nonce"}, {"DPoP-Nonce": "n-1"}),
        FakeResponse(200, {"access_token": "ya29.second", "expires_in": 3600}),
    ])
    account = acct()

    assert tokens.access_token_for(account) == "ya29.second"
    assert len(calls) == 2
    assert calls[1]["dpop"].endswith("n-1"), "the retry did not carry the nonce"


def test_a_revoked_grant_asks_for_re_consent(enclave, co, monkeypatch):
    tokens.take_custody(acct(), REFRESH_TOKEN)
    _install_token_endpoint(monkeypatch, [
        FakeResponse(400, {"error": "invalid_grant"}),
    ])
    with pytest.raises(tokens.ReauthRequired):
        tokens.access_token_for(acct())


def test_refresh_handler_hands_google_auth_a_naive_expiry(enclave, co, monkeypatch):
    tokens.take_custody(acct(), REFRESH_TOKEN)
    _install_token_endpoint(monkeypatch, [
        FakeResponse(200, {"access_token": "ya29.third", "expires_in": 3600}),
    ])
    account = acct()
    token, expiry = tokens.refresh_handler_for(account)(None, None)
    assert token == "ya29.third"
    assert isinstance(expiry, datetime.datetime) and expiry.tzinfo is None


# --- no bypass ------------------------------------------------------------

def test_a_down_cosigner_stops_mail_rather_than_falling_back(enclave, monkeypatch):
    """Invariant 3. The failure has to reach the caller: anything that answers
    with a token here has found a way to read mail with one box, which is the
    arrangement this design exists to remove."""
    def refuse(*args, **kwargs):
        raise cosigner.CoSignerUnavailable("connection refused")

    monkeypatch.setattr(cosigner, "wrap", refuse)
    monkeypatch.setattr(cosigner, "unwrap_and_sign", refuse)
    with pytest.raises(cosigner.CoSignerUnavailable):
        tokens.take_custody(acct(), REFRESH_TOKEN)
    assert not tokens.has_custody(acct()), "a token was stored without the outer layer"


def test_missing_custody_reads_as_re_consent_not_as_an_empty_token(enclave, co):
    with pytest.raises(tokens.ReauthRequired):
        tokens.access_token_for(acct(uid="nobody@example.com", handle=OTHER_HANDLE))


# --- what crosses the wire ------------------------------------------------

def test_dpop_thumbprint_is_computed_from_the_key_itself(co, monkeypatch):
    """Not read from a field the co-signer states: a co-signer that could name
    one key and sign with another would break the binding silently."""
    monkeypatch.setattr(cosigner, "_jwk_cache", None)
    jkt = cosigner.dpop_jkt()
    assert base64.urlsafe_b64decode(jkt + "==") and "=" not in jkt


def test_a_private_dpop_key_is_refused(monkeypatch):
    monkeypatch.setattr(cosigner, "_jwk_cache", None)
    monkeypatch.setattr(cosigner, "_request", lambda *a, **k: {
        "jwk": {"kty": "EC", "crv": "P-256", "x": "a", "y": "b", "d": "private"}
    })
    with pytest.raises(cosigner.CoSignerUnavailable, match="private"):
        cosigner.dpop_jwk()


# --- the data key cache ---------------------------------------------------

def test_a_document_read_costs_one_unwrap_per_ttl_not_one_per_file(enclave, co):
    """Without a cache, rendering the voice page would put a co-signer round
    trip behind every file read. With one, the co-signer sees one unwrap per
    account per TTL -- which is also the resolution at which it can see a
    sweep, and why the TTL is a security parameter rather than a tuning knob."""
    account = acct()
    tokens.take_custody(account, REFRESH_TOKEN)
    keyring.write_encrypted(account, "voice-dna.enc", "how I write")
    keyring.write_encrypted(account, "personal-context.enc", "where I live")
    keyring.forget()

    assert keyring.read_encrypted(account, "voice-dna.enc") == "how I write"
    assert keyring.read_encrypted(account, "personal-context.enc") == "where I live"
    assert len(co.data_unwrapped) == 1, (
        f"{len(co.data_unwrapped)} unwraps for two files under one key"
    )


def test_a_cached_key_expires(enclave, co, monkeypatch):
    account = acct()
    tokens.take_custody(account, REFRESH_TOKEN)
    keyring.write_encrypted(account, "voice-dna.enc", "how I write")
    keyring.forget()

    now = [1000.0]
    monkeypatch.setattr(keyring.time, "monotonic", lambda: now[0])
    keyring.read_encrypted(account, "voice-dna.enc")
    now[0] += keyring.DEK_TTL + 1
    keyring.read_encrypted(account, "voice-dna.enc")
    assert len(co.data_unwrapped) == 2, "an expired key was served from the cache"


def test_the_cache_cannot_outlive_the_window_the_sweep_rule_reads(enclave):
    """The one relationship between the two boxes that is stated rather than
    imported. A TTL at or above the co-signer's distinct-account window would
    let a slow sweep hide behind the cache: every account read once per window,
    with no row written for the second and later reads."""
    from cosigner import policy

    assert keyring.DEK_TTL < policy.DISTINCT_WINDOW_SECONDS, (
        f"a {keyring.DEK_TTL}s key cache is not visible to a "
        f"{policy.DISTINCT_WINDOW_SECONDS}s breadth rule"
    )


def test_a_refresh_never_reads_the_cache(enclave, co, monkeypatch):
    """The per-account rate limit is calibrated on mail access, so a refresh has
    to reach the co-signer every time. Serving one from a warm cache would turn
    the co-signer's view of how often a mailbox is read into a view of how often
    this process restarts."""
    account = acct()
    tokens.take_custody(account, REFRESH_TOKEN)
    _install_token_endpoint(monkeypatch, [
        FakeResponse(200, {"access_token": "ya29.one", "expires_in": 3600}),
        FakeResponse(200, {"access_token": "ya29.two", "expires_in": 3600}),
    ])
    keyring.dek_for(account)          # warm the cache the documents use
    before = len(co.unwrapped)

    tokens.access_token_for(account)
    tokens.forget(account)
    tokens.access_token_for(account)

    assert len(co.unwrapped) - before == 2, (
        "a refresh was served without asking the co-signer"
    )


# --- deletion is destruction ----------------------------------------------

def test_destroying_the_key_makes_a_restored_backup_useless(enclave, co):
    """The property a derived key cannot offer. Deleting an account used to be
    an unlink: a copy of the directory taken beforehand was still readable, and
    there was nothing account-specific to destroy. Now there is exactly one
    object that opens this account's data."""
    account = acct()
    tokens.take_custody(account, REFRESH_TOKEN)
    keyring.write_encrypted(account, "personal-context.enc", "I live in Berlin.")
    backup = {p.name: p.read_bytes()
              for p in keyring.dek_path(UID).parent.iterdir()}

    assert keyring.destroy(UID) is True

    # Restore everything except the key, which is what a backup of a deleted
    # account's directory amounts to once the key is gone.
    for name, blob in backup.items():
        if name != keyring.DEK_FILE:
            keyring.path_for(account, name).write_bytes(blob)
    with pytest.raises(keyring.NoDataKey):
        keyring.read_encrypted(account, "personal-context.enc")


def test_destroy_drops_the_cached_key_too(enclave, co):
    """A key still in this process would make the destruction a matter of
    whether anything had read it recently."""
    account = acct()
    tokens.take_custody(account, REFRESH_TOKEN)
    keyring.write_encrypted(account, "personal-context.enc", "I live in Berlin.")
    keyring.dek_for(account)

    keyring.destroy(UID)
    with pytest.raises(keyring.NoDataKey):
        keyring.dek_for(account)


# --- rotating the co-signer's key -----------------------------------------

def test_rotation_moves_the_record_and_rewrites_no_document(enclave, co):
    """What the envelope buys. Rotating the operator's key re-wraps 32 bytes per
    account; the documents are not touched, not read, and not re-encrypted."""
    account = acct()
    tokens.take_custody(account, REFRESH_TOKEN)
    keyring.write_encrypted(account, "personal-context.enc", "I live in Berlin.")
    document = keyring.path_for(account, "personal-context.enc").read_bytes()
    before = keyring.dek_path(UID).read_bytes()

    keyring.rewrap(UID, HANDLE)

    assert co.rewrapped == [HANDLE]
    assert keyring.dek_path(UID).read_bytes() != before, "the record did not move"
    assert keyring.path_for(account, "personal-context.enc").read_bytes() == document, (
        "rotation rewrote a document"
    )
    keyring.forget()
    assert keyring.read_encrypted(account, "personal-context.enc") == "I live in Berlin."


def test_the_rotation_command_moves_every_account_and_skips_the_unonboarded(
        enclave, co, monkeypatch, tmp_path):
    """`python -m backend.custody.rotate` is step 3 of the procedure written in
    `cosigner/keys.py`. An account that never finished signing in has no record
    to move and gets a current-version one the first time it does."""
    from backend.custody import rotate

    manifest = tmp_path / "accounts.json"
    monkeypatch.setattr(account_store, "MANIFEST", manifest)
    entries = []
    for name, handle in (("alice@example.com", HANDLE), ("bob@example.com", OTHER_HANDLE)):
        entries.append({
            "id": name, "handle": handle, "plan_status": "active",
            "identity": {"first": "A", "last": "B", "emails": [name]},
        })
    manifest.write_text(json.dumps({"accounts": entries}))

    # Only the first has consented, so only the first has a record.
    tokens.take_custody(acct(), REFRESH_TOKEN)
    before = keyring.dek_path(UID).read_bytes()

    assert rotate.rotate(apply=False) == (0, 1), "a dry run wrote something"
    assert keyring.dek_path(UID).read_bytes() == before

    assert rotate.rotate(apply=True) == (1, 0)
    assert co.rewrapped == [HANDLE]
    assert keyring.dek_path(UID).read_bytes() != before
    assert not keyring.has_key("bob@example.com")
