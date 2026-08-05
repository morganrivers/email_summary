"""The enclave's only channel to the co-signer. Sole network boundary of Track I.

The co-signer is a second box under a different operator. It holds the outer
wrapping key and the DPoP private key, stores nothing, and has never seen a
refresh token: everything crossing this wire is either ciphertext it cannot open
(`inner`), ciphertext it can only re-wrap (`outer`), or a signature over an HTTP
request description (`htm`, `htu`, `iat`, `jti`, `nonce`). Compromising it
yields a wrapping key with nothing to unwrap and a signing key that signs no
secrets.

The wire contract is not written down here. It lives in `cosigner/protocol.py`,
next to the server that implements it, and this module imports paths, field
names and the base64 codec from there. Two copies is what produced the first
integration failure: both halves agreed on every path and field name and still
could not talk, because one spelled binary as padded standard base64 and the
other as unpadded base64url, and the co-signer's decoder validates. A wrong
codec surfaces as an AES-GCM tag failure, which this design reports as
tampering, so the bug arrives disguised as an attack.

The import points enclave -> cosigner and never the other way, so moving that
service to its own host does not drag `backend/` along.

Unwrap and sign are one call, not two: it halves the round trips and it makes
the co-signer's rate limit count refreshes rather than half-refreshes.

There is deliberately no bypass. A co-signer that is unreachable means no mail
is processed for anyone, and that is the trade the design accepts: a
denial-of-service possibility in exchange for removing a confidentiality one. A
cached local key or a "proceed anyway" fallback would collapse the whole
property back to a single box holding everything, so failures raise
CoSignerUnavailable and alert the operator instead.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time

import requests

from backend import secrets
from backend import site
from backend.custody.wrapping import CustodyError
from backend.integrations import telegram
from backend.tee import tee_boot
from backend.tee.dstack_client import DstackClient, DstackError
from cosigner import protocol

TIMEOUT = 15

CA_ENV = "COSIGNER_CA"
CLIENT_CERT_ENV = "COSIGNER_CLIENT_CERT"
CLIENT_KEY_ENV = "COSIGNER_CLIENT_KEY"

RA_TLS_SUBJECT = "letterlock-enclave"

# One alert per outage, not one per mailbox wake. The daemon retries on every
# push, so an unrate-limited alert turns a co-signer restart into a flood.
ALERT_INTERVAL = 300

_last_alert = 0.0
_jwk_cache = None
_client_identity_cache = None


class CoSignerUnavailable(CustodyError):
    """The co-signer refused or could not be reached. Never caught into a
    fallback: there isn't one."""


def _jwk_b64u(raw):
    """base64url without padding, which RFC 7638 fixes for a JWK thumbprint.
    Deliberately not the wire codec: this value goes to Google as `dpop_jkt`,
    never to the co-signer, and the spec that governs it is not ours to pick."""
    return base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")


def _alert_operator(msg):
    """Box-level failure, so it goes to the operator's own chat. Never to an
    account's target: whose mail stalled is not the user's problem to diagnose,
    and the per-account path deliberately has no env fallback."""
    global _last_alert
    now = time.time()
    if now - _last_alert < ALERT_INTERVAL:
        return
    _last_alert = now
    target = telegram.operator_target()
    if target is None:
        return
    telegram.send_telegram(f"🔒 <b>Co-signer unavailable</b>\n{msg}", target)


def _client_identity():
    """The client certificate this enclave authenticates with, as (cert, key)
    file paths, or None when the co-signer is not asking for one.

    Inside a CVM the pair is RA-TLS material from the guest agent: the TDX quote
    is embedded in the certificate, so the co-signer verifies the measurement at
    the handshake with no extra round trip. It is written to the attestation
    tmpfs because `requests` takes paths, and tmpfs is the one place the private
    key does not land on the volume at rest."""
    global _client_identity_cache
    if _client_identity_cache is not None:
        return _client_identity_cache
    dev_cert = os.environ.get(CLIENT_CERT_ENV, "")
    dev_key = os.environ.get(CLIENT_KEY_ENV, "")
    if dev_cert and dev_key:
        assert not secrets.tee_required(), (
            "TEE_REQUIRED is set but the co-signer client certificate comes "
            f"from {CLIENT_CERT_ENV}. Inside a CVM it must be RA-TLS material "
            "from the guest agent, or the co-signer is authenticating a file "
            "rather than a measurement."
        )
        _client_identity_cache = (dev_cert, dev_key)
        return _client_identity_cache
    dstack = DstackClient()
    if not dstack.available():
        assert not secrets.tee_required(), (
            "TEE_REQUIRED is set but there is no dstack guest agent to issue an "
            "RA-TLS client certificate."
        )
        return None
    try:
        tls = dstack.get_tls_key(
            subject=RA_TLS_SUBJECT, ra_tls=True, server_auth=False, client_auth=True,
        )
    except DstackError as err:
        raise CoSignerUnavailable(f"guest agent refused an RA-TLS client key: {err}")
    chain = tls.get("certificate_chain") or []
    assert chain and tls.get("key"), "guest agent returned no RA-TLS keypair"
    out_dir = tee_boot.ATTEST_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    cert_path = out_dir / "cosigner_client.crt"
    key_path = out_dir / "cosigner_client.key"
    cert_path.write_text("\n".join(chain))
    key_path.write_text(tls["key"])
    key_path.chmod(0o600)
    _client_identity_cache = (str(cert_path), str(key_path))
    return _client_identity_cache


def _verify():
    """What to check the co-signer's server certificate against. A path to the
    co-signer's own certificate in dev (it is self-signed there); the system
    trust store otherwise. Never False: an unverified TLS session to the box
    holding the other half of custody is a co-signer an attacker can stand in
    for."""
    ca = os.environ.get(CA_ENV, "")
    return ca if ca else True


def _request(method, path, body=None):
    url = site.cosigner_url(path)
    try:
        resp = requests.request(
            method, url, json=body, timeout=TIMEOUT,
            cert=_client_identity(), verify=_verify(),
        )
    except requests.RequestException as err:
        _alert_operator(f"{method} {path}: {err}")
        raise CoSignerUnavailable(f"{method} {url} failed: {err}") from err
    if resp.status_code != 200:
        detail = resp.text[:200]
        _alert_operator(f"{method} {path} -> HTTP {resp.status_code}: {detail}")
        raise CoSignerUnavailable(
            f"{method} {url} -> HTTP {resp.status_code}: {detail}"
        )
    try:
        parsed = resp.json()
    except json.JSONDecodeError as err:
        raise CoSignerUnavailable(f"{method} {url} returned non-JSON: {err}") from err
    assert isinstance(parsed, dict), f"{path} returned non-object: {parsed!r}"
    return parsed


def health():
    return _request("GET", protocol.HEALTH_PATH)


def dpop_jwk():
    """The co-signer's DPoP public key, fetched once per process. Public
    material: it is what Google binds the refresh token to, and it is in every
    proof header anyway."""
    global _jwk_cache
    if _jwk_cache is None:
        jwk = _request("GET", protocol.DPOP_JWK_PATH).get(protocol.F_JWK)
        assert isinstance(jwk, dict) and jwk.get("kty"), (
            f"co-signer returned no usable DPoP JWK: {jwk!r}"
        )
        assert "d" not in jwk, (
            "co-signer served a DPoP JWK containing a private key. The private "
            "half must never leave that box; refusing to use it."
        )
        _jwk_cache = jwk
    return _jwk_cache


def dpop_jkt():
    """RFC 7638 thumbprint of the DPoP key, for the `dpop_jkt` authorization
    parameter. Computed here from the key itself rather than accepted as a
    stated value, so a co-signer cannot name one key and sign with another."""
    jwk = dpop_jwk()
    kty = jwk["kty"]
    if kty == "EC":
        members = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "RSA":
        members = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    else:
        raise CustodyError(f"unsupported DPoP key type {kty!r}")
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True)
    return _jwk_b64u(hashlib.sha256(canonical.encode()).digest())


def sign_dpop(htm, htu, nonce=None):
    """A DPoP proof for one request, signed by the key the enclave does not
    hold. Used at the authorization-code exchange, where there is no account id
    yet because the owning mailbox is unknown until Google answers."""
    assert htm and htu, "sign_dpop needs an HTTP method and URI"
    body = {protocol.F_HTM: htm, protocol.F_HTU: htu}
    if nonce:
        body[protocol.F_NONCE] = nonce
    proof = _request("POST", protocol.SIGN_DPOP_PATH, body).get(protocol.F_PROOF)
    assert proof, "co-signer returned an empty DPoP proof"
    return proof


def wrap(uid, inner):
    """Onboarding only: put the co-signer's layer around a freshly sealed token.
    The co-signer refuses a second wrap for a uid it has already wrapped, so a
    replay here surfaces as a failed provision rather than a silent overwrite."""
    assert uid and inner, "wrap needs a uid and an inner ciphertext"
    outer = _request(
        "POST", protocol.WRAP_PATH,
        {protocol.F_UID: uid, protocol.F_INNER: protocol.b64(inner)},
    ).get(protocol.F_OUTER)
    assert outer, "co-signer returned an empty outer ciphertext"
    return protocol.unb64(outer)


def unwrap_and_sign(uid, outer, htm, htu, nonce=None):
    """One refresh: strip the outer layer and sign the proof that goes with it.

    Returns (inner, proof). `inner` is still ciphertext -- the co-signer cannot
    open it and neither can anyone reading this wire. Only the enclave's
    wrapping.open_inner() turns it into a token."""
    assert uid and outer, "unwrap_and_sign needs a uid and an outer ciphertext"
    assert htm and htu, "unwrap_and_sign needs an HTTP method and URI"
    body = {
        protocol.F_UID: uid, protocol.F_OUTER: protocol.b64(outer),
        protocol.F_HTM: htm, protocol.F_HTU: htu,
    }
    if nonce:
        body[protocol.F_NONCE] = nonce
    answer = _request("POST", protocol.UNWRAP_AND_SIGN_PATH, body)
    inner, proof = answer.get(protocol.F_INNER), answer.get(protocol.F_PROOF)
    assert inner and proof, (
        f"co-signer answered /unwrap-and-sign without both fields: "
        f"inner={bool(inner)} proof={bool(proof)}"
    )
    return protocol.unb64(inner), proof


def reset_cache():
    """Drop cached co-signer material. For tests and for a co-signer that has
    rotated its DPoP key; the enclave then re-fetches on the next call."""
    global _jwk_cache, _client_identity_cache, _last_alert
    _jwk_cache = None
    _client_identity_cache = None
    _last_alert = 0.0
