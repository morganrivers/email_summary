"""The Pub/Sub push token: what `gmail_hook_server` accepts and what it refuses.

The endpoint is public and the token is the whole of its authentication, so
every rule gets a case. Tokens are minted here with a throwaway RSA key and the
certificate cache is pointed at it, which is what makes a forged signature and a
wrong algorithm testable rather than assumed.
"""

import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from google.auth import crypt
from google.auth import jwt as google_jwt

from backend.daemons import gmail_hook_server as hook

KID = "test-key-1"
OTHER_KID = "test-key-2"


def _keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return crypt.RSASigner.from_string(pem, KID), cert


@pytest.fixture
def signer(monkeypatch):
    """A signer whose certificate is the only one the module will accept, with
    the network fetch removed so a test cannot silently reach Google."""
    rsa_signer, cert = _keypair()

    def _no_network():
        raise AssertionError("download_certs called in a test")

    monkeypatch.setattr(hook, "download_certs", _no_network)
    certs = hook.SigningCerts()
    certs._certs = {KID: cert}
    certs._fetched = time.time()
    certs._expires = time.time() + 3600
    monkeypatch.setattr(hook, "_CERTS", certs)
    return rsa_signer


def _claims(**overrides):
    now = int(time.time())
    claims = {
        "iss": "https://accounts.google.com",
        "aud": hook.EXPECTED_AUD,
        "email": hook.PUBSUB_SERVICE_ACCOUNT,
        "email_verified": True,
        "sub": "1234567890",
        "iat": now,
        "exp": now + 3600,
    }
    claims.update(overrides)
    return claims


def _token(signer, **overrides):
    return google_jwt.encode(signer, _claims(**overrides)).decode()


def _reject(signer, **overrides):
    with pytest.raises(hook.HookError) as caught:
        hook.verify_jwt(_token(signer, **overrides))
    assert caught.value.code == 401, caught.value.msg
    return caught.value.msg


def test_genuine_push_token_is_accepted(signer):
    claims = hook.verify_jwt(_token(signer))
    assert claims["email"] == hook.PUBSUB_SERVICE_ACCOUNT


def test_wrong_issuer_is_refused(signer):
    assert "iss" in _reject(signer, iss="https://accounts.example.com")


def test_missing_issuer_is_refused(signer):
    token = google_jwt.encode(signer, {k: v for k, v in _claims().items() if k != "iss"})
    with pytest.raises(hook.HookError):
        hook.verify_jwt(token.decode())


def test_wrong_audience_is_refused(signer):
    assert _reject(signer, aud="https://api.example.com/")


def test_audience_as_a_list_is_refused(signer):
    """OIDC permits a list; a Google push token is a string. Accepting the list
    form would mean accepting a token minted for somebody else as well as us."""
    assert _reject(signer, aud=[hook.EXPECTED_AUD])


def test_another_service_account_is_refused(signer):
    assert "email" in _reject(signer, email="someone-else@example.iam.gserviceaccount.com")


def test_unverified_email_is_refused(signer):
    assert _reject(signer, email_verified=False)


def test_string_true_does_not_pass_for_email_verified(signer):
    """The check that used to run here was `str(claim).lower() == "true"`."""
    assert _reject(signer, email_verified="true")


def test_missing_email_verified_is_refused(signer):
    token = google_jwt.encode(
        signer, {k: v for k, v in _claims().items() if k != "email_verified"}
    )
    with pytest.raises(hook.HookError):
        hook.verify_jwt(token.decode())


def test_expired_token_is_refused(signer):
    now = int(time.time())
    assert _reject(signer, iat=now - 7200, exp=now - 3600)


def test_token_from_the_future_is_refused(signer):
    now = int(time.time())
    assert _reject(signer, iat=now + 3600, exp=now + 7200)


def test_clock_skew_is_bounded(signer):
    now = int(time.time())
    hook.verify_jwt(_token(signer, exp=now - hook.CLOCK_SKEW_SECONDS + 5))
    assert _reject(signer, iat=now - 7200, exp=now - hook.CLOCK_SKEW_SECONDS - 5)


def test_signature_from_an_unknown_key_is_refused(signer):
    other, _ = _keypair()
    with pytest.raises(hook.HookError) as caught:
        hook.verify_jwt(google_jwt.encode(other, _claims()).decode())
    assert caught.value.code == 401


def test_tampered_payload_is_refused(signer):
    header, payload, signature = _token(signer).split(".")
    forged = google_jwt._helpers.unpadded_urlsafe_b64encode(
        json.dumps(_claims(email="attacker@example.com")).encode()
    ).decode()
    with pytest.raises(hook.HookError) as caught:
        hook.verify_jwt(f"{header}.{forged}.{signature}")
    assert caught.value.code == 401


def test_unsigned_token_is_refused(signer):
    """alg=none, the classic. `google.auth.jwt` knows only RS256 and ES256."""
    header = google_jwt._helpers.unpadded_urlsafe_b64encode(
        json.dumps({"alg": "none", "kid": KID}).encode()
    ).decode()
    payload = google_jwt._helpers.unpadded_urlsafe_b64encode(
        json.dumps(_claims()).encode()
    ).decode()
    with pytest.raises(hook.HookError) as caught:
        hook.verify_jwt(f"{header}.{payload}.")
    assert caught.value.code == 401


def test_garbage_is_refused_without_a_traceback(signer):
    for junk in ("", "not-a-jwt", "a.b.c", "..", "x" * 4096):
        with pytest.raises(hook.HookError) as caught:
            hook.verify_jwt(junk)
        assert caught.value.code == 401


def test_unreachable_certs_are_a_503_not_a_401(monkeypatch):
    """Pub/Sub retries a 503 and drops a 401, so our own outage must not read
    as a verdict on the token."""
    certs = hook.SigningCerts()
    monkeypatch.setattr(hook, "_CERTS", certs)

    def _down():
        raise OSError("network is unreachable")

    monkeypatch.setattr(hook, "download_certs", _down)
    header = google_jwt._helpers.unpadded_urlsafe_b64encode(
        json.dumps({"alg": "RS256", "kid": KID}).encode()
    ).decode()
    payload = google_jwt._helpers.unpadded_urlsafe_b64encode(
        json.dumps(_claims()).encode()
    ).decode()
    with pytest.raises(hook.HookError) as caught:
        hook.verify_jwt(f"{header}.{payload}.c2ln")
    assert caught.value.code == 503


class _Clock:
    def __init__(self, now):
        self.now = now

    def __call__(self):
        return self.now


def test_certs_are_fetched_once_per_stated_lifetime(monkeypatch):
    clock = _Clock(1000.0)
    monkeypatch.setattr(hook.time, "time", clock)
    calls = []

    def _fetch():
        calls.append(clock.now)
        return {KID: b"cert"}, 3600

    monkeypatch.setattr(hook, "download_certs", _fetch)
    certs = hook.SigningCerts()
    for _ in range(5):
        certs.for_kid(KID)
    assert len(calls) == 1
    clock.now += 3601
    certs.for_kid(KID)
    assert len(calls) == 2


def test_unknown_kid_refetches_at_most_once_per_floor(monkeypatch):
    """The one refetch an anonymous caller can trigger. Unmetered, it is an
    outbound request per forged token."""
    clock = _Clock(1000.0)
    monkeypatch.setattr(hook.time, "time", clock)
    calls = []

    def _fetch():
        calls.append(clock.now)
        return {KID: b"cert"}, 3600

    monkeypatch.setattr(hook, "download_certs", _fetch)
    certs = hook.SigningCerts()
    certs.for_kid(KID)
    assert len(calls) == 1
    for _ in range(10):
        certs.for_kid(OTHER_KID)
    assert len(calls) == 1
    clock.now += hook.CERTS_REFETCH_FLOOR
    certs.for_kid(OTHER_KID)
    assert len(calls) == 2


def test_a_failed_refetch_keeps_unexpired_certs(monkeypatch):
    clock = _Clock(1000.0)
    monkeypatch.setattr(hook.time, "time", clock)
    certs = hook.SigningCerts()
    monkeypatch.setattr(hook, "download_certs", lambda: ({KID: b"cert"}, 3600))
    certs.for_kid(KID)

    def _down():
        raise OSError("down")

    monkeypatch.setattr(hook, "download_certs", _down)
    clock.now += hook.CERTS_REFETCH_FLOOR
    assert certs.for_kid(OTHER_KID) == {KID: b"cert"}


def test_expired_certs_that_cannot_be_refreshed_are_an_error(monkeypatch):
    """Serving a stale set forever is how a revoked key stays trusted."""
    clock = _Clock(1000.0)
    monkeypatch.setattr(hook.time, "time", clock)
    certs = hook.SigningCerts()
    monkeypatch.setattr(hook, "download_certs", lambda: ({KID: b"cert"}, 3600))
    certs.for_kid(KID)

    def _down():
        raise OSError("down")

    monkeypatch.setattr(hook, "download_certs", _down)
    clock.now += 3601
    with pytest.raises(OSError):
        certs.for_kid(KID)


def test_cache_lifetime_is_clamped():
    assert hook.cache_lifetime("public, max-age=3600") == 3600
    assert hook.cache_lifetime("max-age=0") == hook.CERTS_TTL_MIN
    assert hook.cache_lifetime("max-age=999999") == hook.CERTS_TTL_MAX
    assert hook.cache_lifetime("") == hook.CERTS_TTL_MIN
    assert hook.cache_lifetime("no-store") == hook.CERTS_TTL_MIN


def test_certs_host_is_on_the_egress_allowlist():
    from backend import egress

    assert "www.googleapis.com" in egress.hosts()
    assert hook.CERTS_URL.startswith("https://www.googleapis.com/")
    assert egress.refusal("www.googleapis.com", 443) is None


def test_log_lines_cannot_be_forged_by_a_caller(capsys):
    hook.log("path=/x\ngmail-hook OK verified, routing push")
    assert capsys.readouterr().err.count("\n") == 1
