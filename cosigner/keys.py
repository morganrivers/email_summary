"""The co-signer's key custody: the outer wrapping key and the DPoP signing key.

Both arrive through systemd's `LoadCredentialEncrypted=`, which seals them to
the host TPM and decrypts them into `$CREDENTIALS_DIRECTORY` at unit start.
That is the whole reason this service does not use Vault: a Shamir-sealed Vault
starts sealed after every reboot, and a fail-closed design plus a human-operated
unseal means no mail moves until someone wakes up (docs/plan_token_custody.md
§3). No third party, no human, one directory readable only by this unit.

The outer key is per user: `HKDF(master, salt=uid, info="outer")`. Deriving per
uid is what makes a future per-user revocation and a per-user audit line mean
something -- a single global key would make every row in the log say the same
thing about blast radius.

What this module must never do is open an `inner`. It cannot: `K_inner` comes
from the dstack KMS and is released only to an attested enclave. If a change
here ever makes `unwrap()` return something a caller can read as a token, the
layer order has been reversed and this box has become the single point that can
read every mailbox. See the invariants in `cosigner/__init__.py`.

Provisioning the credentials (once, on the box, as root):

    head -c 32 /dev/urandom | base64 | \\
      systemd-creds encrypt --name=cosigner-master - \\
      /etc/credstore.encrypted/cosigner-master
    openssl ecparam -genkey -name prime256v1 -noout | \\
      openssl pkcs8 -topk8 -nocrypt | \\
      systemd-creds encrypt --name=cosigner-dpop - \\
      /etc/credstore.encrypted/cosigner-dpop

For a dev box with no TPM, `python -m cosigner.keys <dir>` writes the same two
files in the clear and `COSIGNER_CREDENTIALS_DIR` points at them.
"""

import base64
import os
import sys
import threading
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from requests_oauth2client import DPoPKey

MASTER_NAME = "cosigner-master"
DPOP_NAME = "cosigner-dpop"

MASTER_BYTES = 32
NONCE_BYTES = 12

# Prefixed to every `outer` so the master key can be rotated without a schema
# change: an old ciphertext still says which derivation produced it.
KEY_VERSION = 1

DPOP_ALG = "ES256"

_LOCK = threading.Lock()
_CACHE = {}


class NotConfigured(RuntimeError):
    """Credentials are absent or malformed. Fail closed; never improvise a key."""


def reset_for_test(directory=None):
    """Forget the loaded keys so a test can point at a fresh directory."""
    with _LOCK:
        _CACHE.clear()
    if directory is not None:
        os.environ["COSIGNER_CREDENTIALS_DIR"] = str(directory)


def credentials_dir():
    """systemd's credential directory, or the dev override. No default path:
    guessing one is how a service ends up reading a key it was not given.

    The explicit override wins over `CREDENTIALS_DIRECTORY`, which any shell
    can inherit from an unrelated unit -- a dev run must not silently go
    looking for these keys in another service's credential directory."""
    raw = os.environ.get("COSIGNER_CREDENTIALS_DIR") or os.environ.get("CREDENTIALS_DIRECTORY")
    if not raw:
        raise NotConfigured(
            "no CREDENTIALS_DIRECTORY (systemd LoadCredentialEncrypted=) and no "
            "COSIGNER_CREDENTIALS_DIR"
        )
    return Path(raw)


def _read(name):
    path = credentials_dir() / name
    if not path.exists():
        raise NotConfigured(f"credential {name} not found at {path}")
    raw = path.read_bytes()
    if not raw.strip():
        raise NotConfigured(f"credential {name} at {path} is empty")
    return raw


def _cached(name, build):
    with _LOCK:
        if name not in _CACHE:
            _CACHE[name] = build()
        return _CACHE[name]


def master_key():
    """The 32 bytes every outer key is derived from. Base64 in the file, so it
    survives being piped through systemd-creds and read back by eye."""
    def build():
        text = _read(MASTER_NAME).decode(errors="replace").strip()
        try:
            key = base64.b64decode(text, validate=True)
        except Exception as err:
            raise NotConfigured(f"{MASTER_NAME} is not valid base64: {err}") from err
        if len(key) != MASTER_BYTES:
            raise NotConfigured(
                f"{MASTER_NAME} decodes to {len(key)} bytes, expected {MASTER_BYTES}"
            )
        return key

    return _cached(MASTER_NAME, build)


def outer_key(uid, version=KEY_VERSION):
    assert uid, "outer_key requires a non-empty uid"
    assert version == KEY_VERSION, f"unknown outer key version {version}"
    return HKDF(
        algorithm=SHA256(), length=32, salt=uid.encode(), info=b"outer"
    ).derive(master_key())


def wrap(uid, inner):
    """Put the operator's layer on the outside of the enclave's ciphertext.

    `inner` is opaque here and must stay that way: it is AES-GCM output under a
    KMS-released key this box has never held."""
    assert uid, "wrap requires a uid"
    assert isinstance(inner, (bytes, bytearray)) and inner, "wrap requires non-empty inner bytes"
    nonce = os.urandom(NONCE_BYTES)
    sealed = AESGCM(outer_key(uid)).encrypt(nonce, bytes(inner), uid.encode())
    return bytes([KEY_VERSION]) + nonce + sealed


def unwrap(uid, outer):
    """Strip the outer layer. What comes back is still ciphertext.

    The uid is the AAD, so an `outer` belonging to one user cannot be replayed
    under another's id to get their rate-limit budget or their audit line."""
    assert uid, "unwrap requires a uid"
    assert isinstance(outer, (bytes, bytearray)), "unwrap requires bytes"
    header = 1 + NONCE_BYTES
    assert len(outer) > header + 16, f"outer too short to be a sealed record ({len(outer)} bytes)"
    version = outer[0]
    assert version == KEY_VERSION, f"unknown outer key version {version}"
    nonce = bytes(outer[1:header])
    return AESGCM(outer_key(uid, version)).decrypt(nonce, bytes(outer[header:]), uid.encode())


def dpop_key():
    """The DPoP signing key, which never leaves this box.

    Google binds a refresh token to this key at the authorization-code
    exchange, so a refresh token lifted out of enclave RAM is inert without a
    proof signed here. That is what makes the second barrier permanent instead
    of one-shot (docs/plan_token_custody.md §1)."""
    def build():
        raw = _read(DPOP_NAME)
        try:
            private = serialization.load_pem_private_key(raw, password=None)
        except Exception as err:
            raise NotConfigured(f"{DPOP_NAME} is not a PEM private key: {err}") from err
        if not isinstance(private, ec.EllipticCurvePrivateKey):
            raise NotConfigured(f"{DPOP_NAME} is not an EC key ({type(private).__name__})")
        if private.curve.name != "secp256r1":
            raise NotConfigured(
                f"{DPOP_NAME} is on curve {private.curve.name}, {DPOP_ALG} needs secp256r1"
            )
        return DPoPKey(private_key=private, alg=DPOP_ALG)

    return _cached(DPOP_NAME, build)


def dpop_proof(htm, htu, nonce=None):
    """A finished proof JWT. Covers `htm`, `htu`, `iat`, `jti` and `nonce`; no
    token material, which is why signing one teaches this box nothing."""
    assert htm and htu, "a proof needs a method and a target URI"
    return str(dpop_key().proof(htm=htm, htu=htu, nonce=nonce))


def dpop_public_jwk():
    """The public half, for the enclave's `dpop_jkt` at the code exchange.

    `d` is the private scalar. Asserting its absence here rather than trusting
    `public_jwk` to have dropped it is the one check standing between a library
    change and this service publishing its signing key over HTTP."""
    jwk = dict(dpop_key().public_jwk)
    assert "d" not in jwk, "refusing to publish a JWK carrying the private key"
    return jwk


def dpop_jkt():
    return dpop_key().dpop_jkt


def configured():
    """None when both keys load, else why they do not. `deploy/preflight.py`
    calls this so an unprovisioned box is reported instead of being restarted
    into a crash loop."""
    try:
        master_key()
        dpop_key()
    except NotConfigured as err:
        return str(err)
    return None


def write_dev_credentials(directory):
    """Dev-only: the same two files, unsealed, for a box with no TPM. Kept here
    so the file names and formats have one definition rather than one in the
    service and another in a README that drifts."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    master = directory / MASTER_NAME
    dpop = directory / DPOP_NAME
    assert not master.exists() and not dpop.exists(), (
        f"refusing to overwrite existing credentials in {directory}; every "
        "wrapped token on the enclave becomes unreadable when the master key changes"
    )
    master.write_text(base64.b64encode(os.urandom(MASTER_BYTES)).decode() + "\n")
    dpop.write_bytes(
        ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    master.chmod(0o600)
    dpop.chmod(0o600)
    return directory


def main(argv):
    if not argv:
        print(f"usage: python -m {__package__}.keys <dev-credentials-dir>", file=sys.stderr)
        return 2
    directory = write_dev_credentials(argv[0])
    print(f"wrote {MASTER_NAME} and {DPOP_NAME} to {directory}")
    print(f"COSIGNER_CREDENTIALS_DIR={directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
