"""The enclave's only channel to the co-signer. Sole network boundary of Track I.

The co-signer is a second box under a different operator. It holds the outer
wrapping key and the DPoP private key, stores no ciphertext, and has never seen
a refresh token or a data key: everything crossing this wire is either
ciphertext it cannot open (`inner`), ciphertext it can only re-wrap (`outer`),
or a signature over an HTTP request description (`htm`, `htu`, `iat`, `jti`,
`nonce`).

What compromising it yields, stated exactly, because the short version of this
sentence used to omit the third item:

  * a wrapping key with nothing to unwrap,
  * a signing key that signs no secrets,
  * and its audit log -- how many accounts exist, and when each one's mail was
    processed, for as long as `cosigner/retention.py` keeps the rows.

The third is why the identifier on this wire is an opaque handle rather than an
address (`backend.accounts.account.new_handle`). The activity timeline survives;
what it is attached to is a random 128-bit value that this box cannot turn back
into a person, and the mapping exists in one file on the enclave. That is a real
reduction and not an elimination: an attacker who holds the co-signer's log and
the enclave's manifest has both halves, but that is two boxes, which is the
whole design.

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

from backend import paths, secrets, site
from backend.custody.wrapping import CustodyError
from backend.integrations import telegram
from backend.tee import quote_policy, tee_boot
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
_attestation_checked = False


class CoSignerUnavailable(CustodyError):
    """The co-signer refused or could not be reached. Never caught into a
    fallback: there isn't one."""


class CoSignerNotAttesting(CustodyError):
    """The co-signer is not verifying the enclave it is answering.

    Its own type because it is neither an outage nor a bug: it is the two boxes
    disagreeing about whether this deployment is production, and the answer is
    to fix the co-signer's allowlist rather than to retry."""


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
        if secrets.tee_required():
            raise CustodyError(
                "TEE_REQUIRED is set but the co-signer client certificate comes "
                f"from {CLIENT_CERT_ENV}. Inside a CVM it must be RA-TLS material "
                "from the guest agent, or the co-signer is authenticating a file "
                "rather than a measurement."
            )
        _client_identity_cache = (dev_cert, dev_key)
        return _client_identity_cache
    dstack = DstackClient()
    if not dstack.available():
        if secrets.tee_required():
            raise CustodyError(
                "TEE_REQUIRED is set but there is no dstack guest agent to issue "
                "an RA-TLS client certificate."
            )
        return None
    try:
        tls = dstack.get_tls_key(
            subject=RA_TLS_SUBJECT, ra_tls=True, server_auth=False, client_auth=True,
        )
    except DstackError as err:
        raise CoSignerUnavailable(f"guest agent refused an RA-TLS client key: {err}")
    chain = tls.get("certificate_chain") or []
    if not (chain and tls.get("key")):
        raise CoSignerUnavailable("guest agent returned no RA-TLS keypair")
    out_dir = tee_boot.ATTEST_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    cert_path = out_dir / "cosigner_client.crt"
    key_path = out_dir / "cosigner_client.key"
    cert_path.write_text("\n".join(chain))
    # Created at 0600 rather than created and then narrowed: the tmpfs this
    # lands on is mounted mode 0777 (the runtime makes it as root, the
    # container's process is not root), so a plain write_text puts the key
    # this enclave authenticates with on a world-readable file until the
    # chmod lands.
    paths.write_private(key_path, tls["key"])
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


def _require_attesting_cosigner():
    """Refuse to use a co-signer that is not checking who it answers.

    `cosigner/allowlist.json` can say `dev-insecure`, under which
    `attest.verify_client` passes a request carrying no client certificate at
    all. That switch is read on the co-signer's box, and the only thing guarding
    it there is `TEE_REQUIRED` in the co-signer's *own* environment -- a
    variable the enclave sets for itself and cannot set for another machine. So
    an attested enclave could hand every record it owns to a service that
    authenticates nobody, and nothing anywhere would say so.

    This is the missing half: the side that knows it is production asks the
    other side what it is doing. Once per process, because the answer is a
    configuration file read at that service's startup, and under
    `TEE_REQUIRED` only, because outside a CVM dev-insecure is the correct
    answer and asking would break every laptop.

    It is not a proof. A co-signer that has been taken over answers whatever it
    likes here, and only its client certificate check could tell us otherwise --
    which is the thing being asked about. What it closes is the
    misconfiguration: the deploy that pins measurements on one box and leaves
    the other in the mode it was built in."""
    global _attestation_checked
    if _attestation_checked or not secrets.tee_required():
        return
    stated = _request("GET", protocol.HEALTH_PATH).get(protocol.F_ATTESTATION)
    if stated != quote_policy.REQUIRED:
        msg = (
            f"co-signer reports attestation={stated!r}, not "
            f"{quote_policy.REQUIRED!r}. This enclave runs under TEE_REQUIRED, so "
            "the co-signer must verify the RA-TLS quote of whatever connects to "
            "it; while it does not, its client certificate check is authenticating "
            "nothing. Refusing to use it."
        )
        _alert_operator(msg)
        raise CoSignerNotAttesting(msg)
    _attestation_checked = True


def _request(method, path, body=None):
    # The health check is how the question below gets asked, so it is the one
    # request that cannot wait for its answer.
    if path != protocol.HEALTH_PATH:
        _require_attesting_cosigner()
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
    if not isinstance(parsed, dict):
        raise CoSignerUnavailable(f"{path} returned non-object: {parsed!r}")
    return parsed


def dpop_jwk():
    """The co-signer's DPoP public key, fetched once per process. Public
    material: it is what Google binds the refresh token to, and it is in every
    proof header anyway."""
    global _jwk_cache
    if _jwk_cache is None:
        jwk = _request("GET", protocol.DPOP_JWK_PATH).get(protocol.F_JWK)
        if not (isinstance(jwk, dict) and jwk.get("kty")):
            raise CoSignerUnavailable(
                f"co-signer returned no usable DPoP JWK: {jwk!r}"
            )
        if "d" in jwk:
            raise CoSignerUnavailable(
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
    if not proof:
        raise CoSignerUnavailable("co-signer returned an empty DPoP proof")
    return proof


def wrap(handle, inner):
    """Onboarding only: put the co-signer's layer around a freshly sealed data
    key. The co-signer refuses a second wrap for a handle it has already
    wrapped, so a replay here surfaces as a failed provision rather than a
    silent overwrite. A re-consent does not come through here at all: the
    account's data key already exists and is reused."""
    assert handle and inner, "wrap needs a handle and an inner ciphertext"
    outer = _request(
        "POST", protocol.WRAP_PATH,
        {protocol.F_UID: handle, protocol.F_INNER: protocol.b64(inner)},
    ).get(protocol.F_OUTER)
    if not outer:
        raise CoSignerUnavailable("co-signer returned an empty outer ciphertext")
    return protocol.unb64(outer)


def unwrap_and_sign(handle, outer, htm, htu, nonce=None):
    """One refresh: strip the outer layer and sign the proof that goes with it.

    Returns (inner, proof). `inner` is still ciphertext -- the co-signer cannot
    open it and neither can anyone reading this wire. Only the enclave's
    wrapping.open_dek() turns it into a key."""
    assert handle and outer, "unwrap_and_sign needs a handle and an outer ciphertext"
    assert htm and htu, "unwrap_and_sign needs an HTTP method and URI"
    body = {
        protocol.F_UID: handle, protocol.F_OUTER: protocol.b64(outer),
        protocol.F_HTM: htm, protocol.F_HTU: htu,
    }
    if nonce:
        body[protocol.F_NONCE] = nonce
    answer = _request("POST", protocol.UNWRAP_AND_SIGN_PATH, body)
    inner, proof = answer.get(protocol.F_INNER), answer.get(protocol.F_PROOF)
    if not (inner and proof):
        raise CoSignerUnavailable(
            f"co-signer answered /unwrap-and-sign without both fields: "
            f"inner={bool(inner)} proof={bool(proof)}"
        )
    return protocol.unb64(inner), proof


def unwrap(handle, outer):
    """Release an account's data key with no proof beside it, for reading the
    documents that account owns.

    Separate from `unwrap_and_sign` because a proof is a capability: minting one
    to render a settings page would hand the enclave a signature it has no
    request to attach it to, and would write a row on the co-signer claiming a
    mail refresh that never happened."""
    assert handle and outer, "unwrap needs a handle and an outer ciphertext"
    inner = _request(
        "POST", protocol.UNWRAP_PATH,
        {protocol.F_UID: handle, protocol.F_OUTER: protocol.b64(outer)},
    ).get(protocol.F_INNER)
    if not inner:
        raise CoSignerUnavailable("co-signer answered /unwrap with no inner ciphertext")
    return protocol.unb64(inner)


def rewrap(handle, outer):
    """Move one record onto the co-signer's current outer key version.

    Nothing is released: ciphertext in, ciphertext out. The enclave never learns
    which version it landed on, which is correct -- the outer version is the
    co-signer's to know, and the record that comes back opens under whatever it
    chose."""
    assert handle and outer, "rewrap needs a handle and an outer ciphertext"
    rewrapped = _request(
        "POST", protocol.REWRAP_PATH,
        {protocol.F_UID: handle, protocol.F_OUTER: protocol.b64(outer)},
    ).get(protocol.F_OUTER)
    if not rewrapped:
        raise CoSignerUnavailable("co-signer answered /rewrap with no outer ciphertext")
    return protocol.unb64(rewrapped)


def reset_cache():
    """Drop cached co-signer material. For tests and for a co-signer that has
    rotated its DPoP key; the enclave then re-fetches on the next call."""
    global _jwk_cache, _client_identity_cache, _last_alert, _attestation_checked
    _jwk_cache = None
    _client_identity_cache = None
    _last_alert = 0.0
    _attestation_checked = False
