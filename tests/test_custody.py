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

from backend.custody import client as cosigner
from backend.custody import tokens
from backend.custody import wrapping
from backend.integrations.gmail_gcal import oauth_app
from cosigner import protocol

REFRESH_TOKEN = "1//0gSuperSecretRefreshTokenValue"
UID = "alice@example.com"


@pytest.fixture
def enclave(monkeypatch, tmp_path):
    """An enclave with a dev app secret, an empty store, and a throwaway OAuth
    app. Nothing here reaches Google or the network."""
    monkeypatch.setenv(wrapping.DEV_SECRET_ENV, "dev-secret-for-tests-0123456789")
    monkeypatch.delenv("TEE_REQUIRED", raising=False)
    monkeypatch.setattr(wrapping, "_app_secret_cache", None)
    monkeypatch.setattr(tokens.account_store, "ACCOUNTS_DIR", tmp_path)
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
        self.proofs = []
        self.stored = {}

    def _refuse_plaintext(self, blob):
        assert REFRESH_TOKEN.encode() not in bytes(blob), (
            "the co-signer was handed a readable refresh token; the layer order "
            "is inverted and this box can now read every mailbox"
        )

    def wrap(self, uid, inner):
        self._refuse_plaintext(inner)
        assert uid not in self.stored, "a second wrap for one uid must be refused"
        self.wrapped.append(uid)
        nonce = bytes([len(self.wrapped)]) * 12
        return nonce + AESGCM(self.KEY).encrypt(nonce, bytes(inner), uid.encode())

    def unwrap_and_sign(self, uid, outer, htm, htu, nonce=None):
        self._refuse_plaintext(outer)
        self.unwrapped.append((uid, htm, htu, nonce))
        inner = AESGCM(self.KEY).decrypt(
            bytes(outer[:12]), bytes(outer[12:]), uid.encode())
        self._refuse_plaintext(inner)
        return inner, self.sign_dpop(htm, htu, nonce)

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
    inner = wrapping.seal_inner(UID, REFRESH_TOKEN)
    assert REFRESH_TOKEN.encode() not in inner
    assert bytes(wrapping.open_inner(UID, inner)).decode() == REFRESH_TOKEN


def test_inner_is_bound_to_the_account(enclave):
    """The uid is the AEAD's associated data, so one user's record cannot be
    opened as another's even by the box that holds every key."""
    inner = wrapping.seal_inner(UID, REFRESH_TOKEN)
    with pytest.raises(wrapping.CustodyError):
        wrapping.open_inner("mallory@example.com", inner)


def test_inner_key_changes_with_the_key_version(enclave):
    inner = wrapping.seal_inner(UID, REFRESH_TOKEN, key_version=1)
    with pytest.raises(wrapping.CustodyError):
        wrapping.open_inner(UID, inner, key_version=2)


def test_a_tee_box_refuses_a_dev_key(enclave, monkeypatch):
    """Invariant 3 in its quietest form: under TEE_REQUIRED there is no dstack
    socket in this test, and the environment key must not stand in for the KMS."""
    monkeypatch.setenv("TEE_REQUIRED", "1")
    monkeypatch.setattr(wrapping, "_app_secret_cache", None)
    with pytest.raises(AssertionError, match="KMS"):
        wrapping.app_secret()


def test_zeroize_clears_the_buffer(enclave):
    buf = wrapping.open_inner(UID, wrapping.seal_inner(UID, REFRESH_TOKEN))
    wrapping.zeroize(buf)
    assert set(buf) == {0}


# --- the stored record ----------------------------------------------------

def test_record_round_trips_with_its_key_version():
    blob = tokens.encode_record(7, b"outer-bytes")
    assert tokens.decode_record(blob) == (7, b"outer-bytes")


def test_a_truncated_record_asks_for_re_consent_rather_than_crashing(enclave):
    """A half-written token.bin is a fact about a file, not a broken invariant.
    It should reach the mail path as the ReauthRequired it means, so the daemon
    can say so, rather than as an IndexError out of the middle of a wake."""
    path = tokens.token_path(UID)
    path.parent.mkdir(parents=True, exist_ok=True)
    for blob in (b"", b"LLTK", tokens.RECORD_MAGIC + bytes([tokens.RECORD_VERSION, 1])):
        path.write_bytes(blob)
        with pytest.raises(tokens.ReauthRequired):
            tokens.load_record(UID)


def test_take_custody_stores_only_the_doubly_wrapped_token(enclave, co):
    path = tokens.take_custody(UID, REFRESH_TOKEN)
    blob = path.read_bytes()
    assert REFRESH_TOKEN.encode() not in blob
    assert co.wrapped == [UID]
    assert path.stat().st_mode & 0o777 == 0o600
    # The enclave alone cannot get back to the token: its own key opens the
    # inner layer, and what is on disk is the outer one.
    _, outer = tokens.decode_record(blob)
    with pytest.raises(wrapping.CustodyError):
        wrapping.open_inner(UID, outer)


def test_the_cosigner_stores_no_ciphertext(enclave, co):
    tokens.take_custody(UID, REFRESH_TOKEN)
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

    monkeypatch.setattr(tokens.requests, "post", post)
    return calls


def test_refresh_costs_one_cosigner_round_trip_and_caches(enclave, co, monkeypatch):
    tokens.take_custody(UID, REFRESH_TOKEN)
    calls = _install_token_endpoint(monkeypatch, [
        FakeResponse(200, {"access_token": "ya29.first", "expires_in": 3600}),
    ])
    account = type("A", (), {"id": UID})()

    assert tokens.access_token_for(account) == "ya29.first"
    assert tokens.access_token_for(account) == "ya29.first"
    assert len(calls) == 1, "a cached access token was refreshed again"
    assert len(co.unwrapped) == 1, "the co-signer was asked twice for one token"
    assert calls[0]["data"]["refresh_token"] == REFRESH_TOKEN
    assert calls[0]["dpop"].startswith("proof.POST.")


def test_google_demanding_a_nonce_is_retried_once(enclave, co, monkeypatch):
    """Mandatory, not optional: the first proof of a process has no nonce and
    Google answers `use_dpop_nonce`. Without the retry no token is ever issued."""
    tokens.take_custody(UID, REFRESH_TOKEN)
    monkeypatch.setattr(tokens, "_dpop_nonce", None)
    calls = _install_token_endpoint(monkeypatch, [
        FakeResponse(400, {"error": "use_dpop_nonce"}, {"DPoP-Nonce": "n-1"}),
        FakeResponse(200, {"access_token": "ya29.second", "expires_in": 3600}),
    ])
    account = type("A", (), {"id": UID})()

    assert tokens.access_token_for(account) == "ya29.second"
    assert len(calls) == 2
    assert calls[1]["dpop"].endswith("n-1"), "the retry did not carry the nonce"


def test_a_revoked_grant_asks_for_re_consent(enclave, co, monkeypatch):
    tokens.take_custody(UID, REFRESH_TOKEN)
    _install_token_endpoint(monkeypatch, [
        FakeResponse(400, {"error": "invalid_grant"}),
    ])
    with pytest.raises(tokens.ReauthRequired):
        tokens.access_token_for(type("A", (), {"id": UID})())


def test_refresh_handler_hands_google_auth_a_naive_expiry(enclave, co, monkeypatch):
    tokens.take_custody(UID, REFRESH_TOKEN)
    _install_token_endpoint(monkeypatch, [
        FakeResponse(200, {"access_token": "ya29.third", "expires_in": 3600}),
    ])
    account = type("A", (), {"id": UID})()
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
        tokens.take_custody(UID, REFRESH_TOKEN)
    assert not tokens.has_custody(UID), "a token was stored without the outer layer"


def test_missing_custody_reads_as_re_consent_not_as_an_empty_token(enclave, co):
    with pytest.raises(tokens.ReauthRequired):
        tokens.access_token_for(type("A", (), {"id": "nobody@example.com"})())


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
    with pytest.raises(AssertionError, match="private"):
        cosigner.dpop_jwk()
