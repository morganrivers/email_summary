"""One data key per account, and everything encrypted under it.

Each account owns a random 32-byte data encryption key. That key encrypts the
account's refresh token and the documents the account owns; the key itself is
sealed by `wrapping` and then wrapped by the co-signer, so opening it costs a
round trip to a box that meters and logs the request. Nothing here can read an
account's data without that round trip and there is deliberately no bypass.

The record on disk holds the wrapped key and no data:

    database/<id>/dek.bin   LLDK | record version | inner key version | outer

The inner key version is here because it selects the HKDF salt that opens the
sealed key. The outer version is not: the co-signer writes its own version into
the first byte of `outer` and reads it back itself, so this box neither knows
nor needs to know which of the co-signer's keys a record is on.

Why a stored key rather than another derived one. A derived key cannot be
destroyed, so deleting an account could only unlink files; here `destroy()`
removes the one object that opens that account's data, and a copy of the
directory taken beforehand stays ciphertext. It also makes rotation cheap: the
co-signer re-wraps 32 bytes per account instead of the enclave rewriting every
document.

Two ways out of this module and they are metered differently on purpose.
`release_for_refresh()` is the mail path: it takes the DPoP proof with the key,
is never cached, and therefore costs one co-signer round trip per token refresh,
which is what makes the co-signer's rate limit count mail access. `dek_for()` is
the document path: no proof, and cached for `DEK_TTL` so rendering a page does
not put a network call behind every file read.
"""

from __future__ import annotations

import os
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend import paths
from backend.accounts import account as account_store
from backend.custody import client as cosigner
from backend.custody import wrapping

DEK_FILE = "dek.bin"
RECORD_MAGIC = b"LLDK"
RECORD_VERSION = 1
# magic | record version | inner key version, and then the outer ciphertext.
HEADER_LEN = len(RECORD_MAGIC) + 2

# How long an opened data key stays in enclave memory.
#
# A security parameter, not a performance knob. It is the window in which an
# attacker who reaches this process reads a warm account's documents without
# asking the co-signer for anything, and it is the granularity at which the
# co-signer sees document reads at all: one unwrap per account per TTL.
#
# Five minutes. It has to be well under the co-signer's distinct-account window
# (`cosigner.policy.DISTINCT_WINDOW_SECONDS`, 15 minutes) so that a sweep across
# accounts still produces a row per account inside the window the sweep rule
# reads; a TTL at or above that window would let a slow sweep hide behind the
# cache. It also has to be long enough that one person's visit to the settings
# pages, or one drafting run reading a voice profile and a personal context, is
# a single unwrap rather than one per file. Not imported from the co-signer:
# `backend/` depends on `cosigner/protocol.py` alone, so the relationship is
# stated here and asserted by tests/test_custody.py rather than by an import.
DEK_TTL = 300

_lock = threading.Lock()
_dek_cache = {}


class NoDataKey(wrapping.CustodyError):
    """This account has no data key record, so nothing it owns can be opened.

    An account that never finished signing in is the ordinary cause. It is
    raised rather than asserted because the caller -- a page render, a mailbox
    wake -- has a sensible answer for it, and that answer is to ask the user to
    consent again rather than to crash."""


class BadRecord(wrapping.CustodyError):
    """A data key record does not decode: a truncated write, a restored backup,
    a record from a schema this build predates."""


class DataKeyExists(wrapping.CustodyError):
    """This account already has a data key, and a second one would orphan every
    file encrypted under the first.

    Wrap-once, checked against what is on disk rather than against anything this
    process knows, which is why it is a refusal: the record is a file another
    process may have written since. The co-signer enforces the same rule, so
    this is the local half of it and both halves have to fail closed."""


# --- the record on disk ---------------------------------------------------

def dek_path(uid):
    return account_store.account_dir(uid) / DEK_FILE


def has_key(uid):
    return dek_path(uid).exists()


def encode_record(key_version, outer):
    """magic | record version | inner key version | outer ciphertext.

    The inner key version sits outside the ciphertext because it is needed to
    derive the key that opens it. Keeping it in the record rather than in the
    manifest means a key and the version it was sealed at cannot drift apart."""
    assert 0 <= key_version <= 255, f"key_version {key_version} does not fit a byte"
    assert outer, "encode_record needs an outer ciphertext"
    return RECORD_MAGIC + bytes([RECORD_VERSION, key_version]) + bytes(outer)


def decode_record(blob):
    """(inner key version, outer ciphertext), or `BadRecord`."""
    if len(blob) <= HEADER_LEN:
        raise BadRecord(f"data key record is {len(blob)} bytes, too short to hold a header")
    if blob[:len(RECORD_MAGIC)] != RECORD_MAGIC:
        raise BadRecord("not a Letterlock data key record")
    record_version, key_version = blob[4], blob[5]
    if record_version != RECORD_VERSION:
        raise BadRecord(f"data key record version {record_version} is not {RECORD_VERSION}")
    return key_version, blob[HEADER_LEN:]


def store_record(uid, outer, key_version=wrapping.KEY_VERSION):
    """Write one account's wrapped data key. Restricted to the application's own
    group inside a directory of the same: the mode is worth nothing under a
    world-readable parent, and the enclave's units are not the only processes on
    the box.

    Shared rather than mail-only because this record is what the web tier hands
    the co-signer to unwrap for a document render. It is ciphertext the web tier
    cannot open alone, which is the whole point of the outer layer."""
    path = dek_path(uid)
    account_store.secure_dir(path.parent)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(encode_record(key_version, outer))
    tmp.chmod(paths.file_mode())
    tmp.replace(path)
    return path


def load_record(uid):
    path = dek_path(uid)
    if not path.exists():
        raise NoDataKey(f"no data key record at {path}")
    try:
        return decode_record(path.read_bytes())
    except BadRecord as err:
        raise NoDataKey(f"{path}: {err}") from err


def destroy(uid):
    """Crypto-shred: remove the one object that opens this account's data.

    Called by account deletion before the directory goes, so a copy of that
    directory taken beforehand -- a backup, a snapshot, a forensic image --
    stays ciphertext rather than becoming readable again if it is restored."""
    forget(uid)
    path = dek_path(uid)
    if path.exists():
        path.unlink()
        return True
    return False


# --- opening the key ------------------------------------------------------

def create(uid, handle):
    """Mint this account's data key and put it under both layers. Returns the
    record path.

    Onboarding only, and once per account: the co-signer refuses a second wrap
    for a handle it has already wrapped. A returning user re-consenting keeps
    the key they already have, because every document they own is encrypted
    under it.

    Seeds the cache rather than handing the key back, so the caller that writes
    a file straight afterwards goes through `dek_for()` like every other writer
    instead of carrying a second kind of key argument. Nothing is spent for it:
    the key was in this process a line ago, and asking the co-signer to unwrap
    what it has just wrapped would be a metered round trip for a value already
    in hand."""
    account_store.check_handle(handle)
    if has_key(uid):
        raise DataKeyExists(
            f"{uid} already has a data key; replacing it would orphan every "
            "file encrypted under the old one"
        )
    dek = bytearray(wrapping.new_dek())
    outer = cosigner.wrap(handle, wrapping.seal_dek(handle, dek))
    path = store_record(uid, outer)
    with _lock:
        _dek_cache[uid] = (dek, time.monotonic() + DEK_TTL)
    return path


def open_key(uid, handle):
    """This account's data key, straight from the co-signer. Uncached.

    The caller owns the buffer and should `wrapping.zeroize()` it when done."""
    account_store.check_handle(handle)
    key_version, outer = load_record(uid)
    return wrapping.open_dek(handle, cosigner.unwrap(handle, outer), key_version)


def release_for_refresh(uid, handle, htm, htu, nonce=None):
    """The data key and a DPoP proof for one Google token request.

    Never cached, and separate from `dek_for` for that reason: a refresh has to
    cost a co-signer round trip, because that round trip is what puts mail
    access inside the co-signer's rate limit and its log. Returns (dek, proof);
    the caller owns the buffer."""
    account_store.check_handle(handle)
    key_version, outer = load_record(uid)
    inner, proof = cosigner.unwrap_and_sign(handle, outer, htm, htu, nonce=nonce)
    return wrapping.open_dek(handle, inner, key_version), proof


def rewrap(uid, handle):
    """Move this account's record onto the co-signer's current outer key.

    No plaintext on either box: the enclave hands over ciphertext it cannot open
    and stores back ciphertext it still cannot open. The inner layer and the
    data key are untouched, so no document is rewritten."""
    account_store.check_handle(handle)
    key_version, outer = load_record(uid)
    store_record(uid, cosigner.rewrap(handle, outer), key_version)
    return dek_path(uid)


class AccountGone(wrapping.CustodyError):
    """The account this key belongs to is no longer in the manifest.

    Not an assert: the manifest is read from disk and another process may have
    removed the row a moment ago, which is a race to refuse rather than a bug
    in this caller."""


def _refuse_if_deleted(account, uid):
    """Refuse to mint a data key for an account that has been deleted.

    Called only where a key would be *created*, which is the whole of the race.
    Deletion runs in the web process; this may be the daemon, which can hold a
    cached key for `DEK_TTL` and a voice generation that finishes after the
    manifest row is gone. `write_encrypted` would then mint a key, recreate
    `database/<id>/` and write a file into it -- unreadable, since the record
    was shredded, but the directory, its name and its timestamps are back after
    the user asked to be erased.

    `handoff.OP_ACCOUNT_FORGET` waits for that job before the deletion and is
    the tidy path; this is the one that has to be right, because a notification
    can be lost and a thread can outlast the wait for it.

    Two things are deliberately not refused. An `(id, handle)` pair, because
    `identify()` accepts that shape for exactly one caller -- onboarding, which
    encrypts a refresh token *before* writing the entry that would carry it. And
    a box with no manifest at all, which is a laptop or a test rather than a
    store somebody was removed from: absence of the file is not absence of the
    row."""
    if isinstance(account, tuple):
        return
    if account_store.MANIFEST.exists() and \
            account_store.account_for_email(uid, include_inactive=True) is None:
        forget(uid)
        raise AccountGone(
            f"{uid} is not in the account manifest; refusing to create a data "
            "key for an account that has been deleted"
        )


def dek_for(account):
    """A cached data key for reading the documents this account owns.

    The lock is held across the unwrap rather than only around the cache read:
    two page renders arriving together would otherwise spend two of this
    account's co-signer budget to reach the same key."""
    uid, handle = identify(account)
    now = time.monotonic()
    with _lock:
        cached = _dek_cache.get(uid)
        if cached and cached[1] > now:
            return cached[0]
        dek = open_key(uid, handle)
        _dek_cache[uid] = (dek, now + DEK_TTL)
        return dek


def forget(uid=None):
    """Drop cached data keys, zeroizing as we go. Called when an account's
    custody changes, when it is deleted, and by tests."""
    with _lock:
        stale = list(_dek_cache) if uid is None else [uid]
        for key in stale:
            entry = _dek_cache.pop(key, None)
            if entry is not None:
                wrapping.zeroize(entry[0])


def identify(account):
    """(id, handle) for an account, or a refusal naming what is missing.

    Takes an Account, or the pair itself. The pair is for onboarding, which has
    to encrypt a refresh token before the manifest entry that would carry it
    exists: the alternative was registering the account first and writing its
    token pointer in a second pass, which makes every signup two manifest writes
    and two audit rows to work around an ordering.

    Custody refuses to work from an id alone. Falling back to it would put an
    address back on the co-signer's wire and, worse, derive a different key with
    it, so the mistake would surface as unopenable records rather than as a leak
    anyone noticed."""
    if isinstance(account, tuple):
        uid, handle = account
    else:
        uid = getattr(account, "id", None)
        handle = getattr(account, "handle", None)
    assert uid, f"custody needs an account object or an (id, handle) pair, not {account!r}"
    assert handle, (
        f"account {uid} has no opaque handle, so its data key cannot be named. "
        "An account registered before handles existed has none; re-onboard it "
        "through /auth/callback."
    )
    return account_store.check_id(uid), account_store.check_handle(handle)


# --- files encrypted under the key ----------------------------------------

def aad(handle, name):
    """What a ciphertext is bound to: the account and the file it is stored as.

    Both, so a record cannot be moved between accounts and cannot be moved
    between files within one account -- a voice profile put in place of a token
    record would otherwise open, since one key covers everything the account
    owns."""
    return f"{handle}|{name}".encode()


def encrypt(dek, handle, name, plaintext):
    assert len(dek) == wrapping.KEY_LEN, f"a data key is {wrapping.KEY_LEN} bytes"
    assert name, "encrypt needs the name the ciphertext will be stored as"
    data = plaintext.encode() if isinstance(plaintext, str) else bytes(plaintext)
    nonce = os.urandom(wrapping.NONCE_LEN)
    return nonce + AESGCM(bytes(dek)).encrypt(nonce, data, aad(handle, name))


def decrypt(dek, handle, name, blob):
    assert len(dek) == wrapping.KEY_LEN, f"a data key is {wrapping.KEY_LEN} bytes"
    assert name, "decrypt needs the name the ciphertext was stored as"
    if len(blob) <= wrapping.NONCE_LEN + wrapping.TAG_LEN:
        raise BadRecord(f"{name} is {len(blob)} bytes, too short to be sealed output")
    nonce, sealed = bytes(blob[:wrapping.NONCE_LEN]), bytes(blob[wrapping.NONCE_LEN:])
    try:
        return AESGCM(bytes(dek)).decrypt(nonce, sealed, aad(handle, name))
    except Exception as err:
        raise wrapping.CustodyError(
            f"{name} did not open under this account's data key: {type(err).__name__}"
        ) from None


def path_for(account, name):
    uid, _ = identify(account)
    return account_store.account_dir(uid) / name


def write_encrypted(account, name, text, shared=True):
    """Store one of this account's documents, encrypted under its data key.

    Mints the key if the account has none. In practice it always has one --
    reaching any page that writes a document means having signed in, and signing
    in takes custody -- but the alternative is a write that fails with "no data
    key" for a user who has done nothing wrong, and there is no state in which
    storing the document in the clear instead would be the better answer.
    Creating it here costs the account's single `/wrap`, which is the same one
    onboarding would have spent.

    `shared=False` writes a file only the mail uid may read afterwards, and the
    refresh token is the one caller that asks for it. Everything else here is a
    document the web tier renders. The distinction is a mode rather than a
    second key because both files open under the same data key: what separates
    them is which process can obtain the ciphertext, not which can obtain the
    key."""
    uid, handle = identify(account)
    if not has_key(uid):
        _refuse_if_deleted(account, uid)
        create(uid, handle)
    path = path_for(account, name)
    account_store.secure_dir(path.parent)
    blob = encrypt(dek_for(account), handle, name, text)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(blob)
    tmp.chmod(paths.file_mode(shared))
    tmp.replace(path)
    return path


def read_encrypted(account, name, default=None):
    """One of this account's documents, or `default` when there is none.

    A missing file is an ordinary answer -- a user who has not written a voice
    profile has no file. A file that will not open is not: it means the record
    was tampered with or the key is the wrong one, and it raises."""
    _, handle = identify(account)
    path = path_for(account, name)
    if not path.exists():
        return default
    return decrypt(dek_for(account), handle, name, path.read_bytes()).decode()


def clear_encrypted(account, name):
    path = path_for(account, name)
    if path.exists():
        path.unlink()
        return True
    return False
