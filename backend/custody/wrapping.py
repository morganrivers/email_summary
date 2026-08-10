"""The enclave's half of split custody: the inner encryption layer.

Every account has one random 32-byte data encryption key. That DEK is what
encrypts the account's data -- its refresh token, its voice profile, its
personal information. The DEK itself is protected by two independent keys. This
module owns the inner one, derived from the dstack KMS `app_secret`, which is
released only to a CVM whose measurement the KMS has authorized. The outer layer
belongs to the co-signer (backend.custody.client) and is applied on top, so the
wrapped DEK that reaches disk cannot be opened by either box alone.

Layer order is the whole guarantee and it is not symmetric. The operator's wrap
is outside; ours is inside. Reversed, the co-signer's unwrap would yield a
plaintext data key, making it the single box that can read every mailbox, which
is the arrangement this design exists to avoid. Anything that changes the order
here silently destroys the property, so seal_dek/open_dek are the only functions
that touch a plaintext key and neither one talks to the network.

What the DEK buys over encrypting each file directly under a derived key:
rotation re-wraps 32 bytes per account instead of rewriting every record, and
destroying one account's wrapped DEK destroys that account's data without
touching anyone else's -- a per-user revocation a purely derived scheme cannot
offer, because there is nothing account-specific to destroy.

The DEK is keyed to an opaque handle, not to an address. See
`backend.accounts.account.new_handle`.

Outside a CVM there is no KMS. A dev key from the environment stands in, but
only while TEE_REQUIRED is unset: on a box that claims to be an enclave, a
derived-from-nothing key would mean the data was never protected at all.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from backend import secrets
from backend.tee import tee_boot
from backend.tee.dstack_client import DstackClient, DstackError

# Bumping this re-derives every inner key. The version travels with each stored
# record (keyring.encode_record), so an old record stays openable after a bump
# and rotation needs no schema change.
KEY_VERSION = 1

KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16

_INFO_INNER = b"account-dek"

DEV_SECRET_ENV = "LETTERLOCK_DEV_APP_SECRET"  # nosec B105  # the variable name

_app_secret_cache = None


class CustodyError(RuntimeError):
    """Custody could not be established or exercised. Always fail closed."""


def _decode_kms_key(raw):
    """The guest agent returns the derived key as hex. Accept raw bytes too
    rather than guessing wrong on a future agent version."""
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    if not (isinstance(raw, str) and raw):
        raise CustodyError(f"KMS returned no usable key: {raw!r}")
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return raw.encode()


def app_secret():
    """The KMS-released seed every inner key derives from, cached per process.

    Cached because a refresh happens per mailbox wake and the socket round trip
    would otherwise sit on that path. The value lives in enclave RAM either way;
    caching it changes nothing about who can read it."""
    global _app_secret_cache
    if _app_secret_cache is not None:
        return _app_secret_cache
    client = DstackClient()
    if client.available():
        try:
            released = client.get_key(tee_boot.APP_KEY_PATH, purpose="seal")
        except DstackError as err:
            raise CustodyError(f"KMS refused to release the app secret: {err}") from err
        secret = _decode_kms_key(released.get("key"))
    else:
        dev = os.environ.get(DEV_SECRET_ENV, "")
        if secrets.tee_required():
            raise CustodyError(
                "TEE_REQUIRED is set but there is no dstack guest agent to release "
                "the app secret. Refusing to protect refresh tokens with a key that "
                "did not come from the KMS."
            )
        if not dev:
            raise CustodyError(
                f"no dstack guest agent and no {DEV_SECRET_ENV} in the environment. "
                "Set one to run split custody on a dev box."
            )
        secret = dev.encode()
    if len(secret) < 16:
        raise CustodyError(f"app secret is only {len(secret)} bytes")
    _app_secret_cache = secret
    return secret


def derive(salt, info, length=KEY_LEN):
    """Sole HKDF over the app secret. Everything the enclave keys off its own
    KMS material comes from here, so there is one place to check that two
    purposes can never collide on a key."""
    assert isinstance(salt, bytes) and salt, "derive needs a non-empty salt"
    assert isinstance(info, bytes) and info, "derive needs a non-empty info label"
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=salt, info=info,
    ).derive(app_secret())


def inner_key(handle, key_version=KEY_VERSION):
    assert handle, "inner_key needs an account handle"
    salt = f"{handle}|{key_version}".encode()
    return derive(salt, _INFO_INNER)


def new_dek():
    """A fresh data encryption key. Random, not derived: derived keys cannot be
    destroyed, and destroying one account's key is what makes deleting that
    account mean something beyond unlinking its files."""
    return os.urandom(KEY_LEN)


def seal_dek(handle, dek, key_version=KEY_VERSION):
    """Encrypt an account's data key under this enclave's key. The result is what
    the co-signer wraps; it never sees anything else."""
    assert handle, "seal_dek needs an account handle"
    assert isinstance(dek, (bytes, bytearray)) and len(dek) == KEY_LEN, (
        f"a data key is {KEY_LEN} bytes, got {len(dek) if dek else 0}"
    )
    nonce = os.urandom(NONCE_LEN)
    sealed = AESGCM(inner_key(handle, key_version)).encrypt(
        nonce, bytes(dek), handle.encode()
    )
    return nonce + sealed


def open_dek(handle, inner, key_version=KEY_VERSION):
    """Decrypt what the co-signer handed back. Returns a bytearray so the caller
    can clear it after use; a bytes could not be.

    A tag failure means the ciphertext, the handle or the key does not match, and
    the message says exactly that and nothing else. Logging the ciphertext here
    would put the one thing the co-signer is not allowed to see into a log the
    enclave writes.

    `handle` is our own caller's and stays an assert. `inner` is not: it is what
    the co-signer just answered with, or what `keyring.load_record` read off
    disk, so its shape is refused rather than asserted."""
    assert handle, "open_dek needs an account handle"
    if not isinstance(inner, (bytes, bytearray)):
        raise CustodyError(f"inner must be bytes, got {type(inner).__name__}")
    if len(inner) <= NONCE_LEN + TAG_LEN:
        raise CustodyError(
            f"inner ciphertext is {len(inner)} bytes, too short to be sealed output"
        )
    nonce, sealed = bytes(inner[:NONCE_LEN]), bytes(inner[NONCE_LEN:])
    try:
        plaintext = AESGCM(inner_key(handle, key_version)).decrypt(
            nonce, sealed, handle.encode()
        )
    except Exception as err:
        raise CustodyError(
            f"inner unwrap failed for {handle} at key_version {key_version}: "
            f"{type(err).__name__}"
        ) from None
    if len(plaintext) != KEY_LEN:
        raise CustodyError(
            f"inner layer opened to {len(plaintext)} bytes, which is not a data key"
        )
    return bytearray(plaintext)


def zeroize(buf):
    """Overwrite a mutable buffer holding a plaintext token.

    Not a guarantee: the interpreter may have copied the bytes elsewhere, and a
    refresh token has to exist in enclave RAM at the moment it is used. It
    shortens the window, which is all any in-process measure can do."""
    if buf is None:
        return
    assert isinstance(buf, bytearray), "zeroize needs a bytearray"
    for i in range(len(buf)):
        buf[i] = 0
