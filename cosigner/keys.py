"""The co-signer's key custody: the outer wrapping key and the DPoP signing key.

Both arrive through systemd's `LoadCredentialEncrypted=`, which seals them to
the host TPM and decrypts them into `$CREDENTIALS_DIRECTORY` at unit start.
That is the whole reason this service does not use Vault: a Shamir-sealed Vault
starts sealed after every reboot, and a fail-closed design plus a human-operated
unseal means no mail moves until someone wakes up (docs/plan_token_custody.md
§3). No third party, no human, one directory readable only by this unit.

The outer key is per account: `HKDF(master, salt=handle, info="outer")`. The
salt is an opaque handle the enclave minted, not an address and not anything
this box can turn back into a person (`backend.accounts.account.new_handle`).
Deriving per handle is what makes a per-account revocation and a per-account
audit line mean something -- a single global key would make every row in the log
say the same thing about blast radius.

What this module must never do is open an `inner`. It cannot: `K_inner` comes
from the dstack KMS and is released only to an attested enclave. If a change
here ever makes `unwrap()` return something a caller can read as a data key, the
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

Rotating the master key, which this service can now actually do:

 1. Provision the next one beside the current one. Version 1 is the unsuffixed
    name above; every later version is `cosigner-master-vN`.

        head -c 32 /dev/urandom | base64 | \\
          systemd-creds encrypt --name=cosigner-master-v2 - \\
          /etc/credstore.encrypted/cosigner-master-v2

    and add a `LoadCredentialEncrypted=` line for it to the unit.
 2. Bump `KEY_VERSION` here and restart. New wraps use v2; every existing record
    still opens, because `unwrap()` reads the version out of the record and
    `known_versions()` reports both keys as loadable.
 3. Run `python -m backend.custody.rotate` on the enclave. It hands each stored
    record back through `/rewrap`, which unwraps under whichever version the
    record names and re-wraps under the current one. No plaintext is involved on
    either box: what is re-wrapped is still the enclave's sealed ciphertext.
 4. Once `rotate` reports every record at the current version, delete the old
    credential and its `LoadCredentialEncrypted=` line. `known_versions()` then
    stops reporting it and a record still carrying it fails closed.

The DPoP key is the one that cannot be rotated at all: Google binds every
refresh token to it at the authorization-code exchange, so replacing it forces
every user to consent again.

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

# Which master key new wraps are made under. Prefixed to every `outer`, so an
# old ciphertext still says which derivation produced it and rotation is a
# re-wrap of small records rather than a re-encryption of user data.
KEY_VERSION = 1

# Version 1 is the unsuffixed credential, because that is the one already sealed
# to the TPM on the deployed box and a rename is a re-provisioning nobody would
# get right at 3am. Later versions are suffixed. One function owns the mapping,
# so the file name a rotation must create is derived rather than remembered.
FIRST_VERSION = 1
MAX_VERSION = 255

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


def current_version(version=None):
    """`version`, or the one new wraps are made under.

    Resolved at call time rather than as a default argument. A default is bound
    at import, so a `KEY_VERSION` changed afterwards -- by a rotation rehearsal,
    or by a test -- would move the version written into a record without moving
    the key it was derived from, and the record would open until the day the two
    disagreed."""
    version = KEY_VERSION if version is None else version
    assert FIRST_VERSION <= version <= MAX_VERSION, f"key version {version} out of range"
    return version


def master_name(version=None):
    """The credential file holding one version's master key. Sole definition of
    the name, so the rotation procedure in the module docstring, the unit's
    `LoadCredentialEncrypted=` lines and the dev writer cannot disagree."""
    version = current_version(version)
    return MASTER_NAME if version == FIRST_VERSION else f"{MASTER_NAME}-v{version}"


def master_key(version=None):
    """The 32 bytes one version's outer keys are derived from. Base64 in the
    file, so it survives being piped through systemd-creds and read back by
    eye."""
    name = master_name(version)

    def build():
        text = _read(name).decode(errors="replace").strip()
        try:
            key = base64.b64decode(text, validate=True)
        except Exception as err:
            raise NotConfigured(f"{name} is not valid base64: {err}") from err
        if len(key) != MASTER_BYTES:
            raise NotConfigured(
                f"{name} decodes to {len(key)} bytes, expected {MASTER_BYTES}"
            )
        return key

    return _cached(name, build)


def known_versions():
    """Every master key this box can actually load, newest first.

    Derived from what is in the credential directory rather than from a second
    constant, so retiring a key is deleting its file and nothing else. That is
    also what makes retirement fail closed: a record still naming a version
    whose credential is gone does not open, which is the whole point of
    finishing a rotation before deleting the old key."""
    found = []
    for version in range(KEY_VERSION, FIRST_VERSION - 1, -1):
        try:
            master_key(version)
        except NotConfigured:
            continue
        found.append(version)
    return tuple(found)


def outer_key(handle, version=None):
    assert handle, "outer_key requires a non-empty handle"
    return HKDF(
        algorithm=SHA256(), length=32, salt=handle.encode(), info=b"outer"
    ).derive(master_key(current_version(version)))


def wrap(handle, inner):
    """Put the operator's layer on the outside of the enclave's ciphertext,
    under the current key version.

    `inner` is opaque here and must stay that way: it is AES-GCM output under a
    KMS-released key this box has never held."""
    assert handle, "wrap requires a handle"
    assert isinstance(inner, (bytes, bytearray)) and inner, "wrap requires non-empty inner bytes"
    # Read once and used for both the derivation and the prefix. Letting the
    # prefix come from the module global while the key came from a default
    # argument bound at import time is a record that says one version and is
    # encrypted under another -- which opens fine until the day the two differ,
    # and then fails as tampering.
    version = current_version()
    nonce = os.urandom(NONCE_BYTES)
    sealed = AESGCM(outer_key(handle, version)).encrypt(
        nonce, bytes(inner), handle.encode())
    return bytes([version]) + nonce + sealed


def unwrap(handle, outer):
    """Strip the outer layer, under whichever version the record names. What
    comes back is still ciphertext.

    Accepting an older version is what makes rotation possible at all: the new
    key has to coexist with the old one for as long as it takes to re-wrap every
    record, and a service that only opened its current version would make every
    stored record unreadable the moment `KEY_VERSION` moved. A version whose
    credential is not present raises, so retiring a key is still a hard stop
    rather than a silent fallback to another one.

    The handle is the AAD, so an `outer` belonging to one account cannot be
    replayed under another's to get their rate-limit budget or their audit
    line."""
    assert handle, "unwrap requires a handle"
    assert isinstance(outer, (bytes, bytearray)), "unwrap requires bytes"
    header = 1 + NONCE_BYTES
    assert len(outer) > header + 16, f"outer too short to be a sealed record ({len(outer)} bytes)"
    version = outer[0]
    versions = known_versions()
    assert version in versions, (
        f"record was wrapped under outer key version {version}; this box can "
        f"load {list(versions) or 'no versions'}"
    )
    nonce = bytes(outer[1:header])
    return AESGCM(outer_key(handle, version)).decrypt(
        nonce, bytes(outer[header:]), handle.encode())


def rewrap(handle, outer):
    """Move one record onto the current key version. Returns the new `outer`.

    The only operation that reads a record and writes one back, and it is still
    blind: what it unwraps is the enclave's sealed ciphertext, which this box
    cannot read at either version. Possession of an `outer` that opens is the
    authorization -- it is a value that exists only in the enclave's store, so
    presenting one proves the caller is the box already entitled to unwrap it,
    and unlike `/wrap` this cannot introduce a record for an account that had
    none.

    Already-current records are re-wrapped rather than skipped: the caller
    cannot tell the version without parsing our record format, and a second wrap
    at the same version is harmless."""
    assert handle, "rewrap requires a handle"
    return wrap(handle, unwrap(handle, outer))


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


def write_dev_credentials(directory, version=None):
    """Dev-only: the same two files, unsealed, for a box with no TPM. Kept here
    so the file names and formats have one definition rather than one in the
    service and another in a README that drifts.

    `version` writes the master key under a later version's name, which is how a
    rotation is rehearsed off the box. The DPoP key is written only alongside
    version 1, because there is only ever one of it."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    master = directory / master_name(version)
    dpop = directory / DPOP_NAME
    assert not master.exists(), (
        f"refusing to overwrite {master}; every record wrapped under this "
        "version becomes unreadable when the key behind it changes"
    )
    master.write_text(base64.b64encode(os.urandom(MASTER_BYTES)).decode() + "\n")
    master.chmod(0o600)
    if not dpop.exists():
        dpop.write_bytes(
            ec.generate_private_key(ec.SECP256R1()).private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        dpop.chmod(0o600)
    return directory


def main(argv):
    if not argv:
        print(f"usage: python -m {__package__}.keys <dev-credentials-dir> [key-version]",
              file=sys.stderr)
        return 2
    version = int(argv[1]) if len(argv) > 1 else KEY_VERSION
    directory = write_dev_credentials(argv[0], version)
    print(f"wrote {master_name(version)} and {DPOP_NAME} to {directory}")
    print(f"COSIGNER_CREDENTIALS_DIR={directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
