"""What deletion has to release, and what the manifest has to survive.

Two things are pinned here and both are about a second process. Deleting an
account runs in the *web* tier: it shreds the data key and removes the
directory, and until now that was the whole of it. The mail daemon is a
different process, and at that moment it can be holding this account's data key,
its access token, a Google service object and a voice generation halfway through
a Gmail sweep -- none of which the web tier's caches know about. It also holds
the only thing that can still read the refresh token, which is what withdraws the
Google grant and stops the mailbox watch; a moment later that token is bytes
nobody can read, so those two stop being *possible* rather than merely skipped.

The manifest lock is the same shape of problem one level down. Every mutator
read the file whole, changed one field and wrote it whole, with no lock. The
rename was atomic so nothing tore, but the later writer's stale copy reverted
the earlier one -- and `delete_account` racing any other writer put the deleted
row back, after its files were already shredded.
"""

import threading

import pytest
from harness import account_entry as _entry
from harness import write_manifest as _manifest

from backend.accounts import account
from backend.custody import handoff, handoff_server, keyring
from backend.drafting import voice_dna


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(account, "ACCOUNTS_DIR", tmp_path)
    monkeypatch.setattr(account, "MANIFEST", _manifest(tmp_path, [
        _entry("dana@x.com", status="active"),
        _entry("erin@x.com", status="active"),
    ]))
    return tmp_path


# --- the manifest transaction ---------------------------------------------


def test_concurrent_writers_do_not_lose_each_others_updates(store):
    """Two threads, two fields, one file. Without the lock each read the whole
    manifest and wrote the whole manifest back, so whichever finished second
    reverted the first -- a plan flip discarded by a settings save, a Telegram
    unlink discarded by a billing event."""
    barrier = threading.Barrier(2)

    def flip_plan():
        barrier.wait()
        account.set_plan_status("dana@x.com", "inactive")

    def save_settings():
        barrier.wait()
        account.set_settings("dana@x.com", timezone="Europe/Berlin")

    threads = [threading.Thread(target=flip_plan), threading.Thread(target=save_settings)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    acct = account.account_for_email("dana@x.com")
    assert acct.plan_status == "inactive", "the plan flip was reverted"
    assert acct.timezone == "Europe/Berlin", "the settings save was reverted"


def test_a_deletion_racing_a_writer_does_not_resurrect_the_row(store):
    """The bad one. The other writer's stale copy of the account list still
    holds the deleted entry, so writing it back puts a user's address, timezone
    and chat id on disk after they asked to be erased -- pointing at files that
    are already crypto-shredded."""
    barrier = threading.Barrier(2)

    def delete():
        barrier.wait()
        account.delete_account("dana@x.com")

    def touch_the_other():
        barrier.wait()
        account.set_plan_status("erin@x.com", "inactive")

    threads = [threading.Thread(target=delete), threading.Thread(target=touch_the_other)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert account.account_for_email("dana@x.com") is None
    assert account.account_for_email("erin@x.com").plan_status == "inactive"


def test_the_manifest_is_never_written_outside_the_transaction(store):
    """The assert is the rule: a write built from an unlocked read is a write
    about to discard somebody else's change."""
    data = account._read_manifest()
    with pytest.raises(AssertionError, match="_manifest_transaction"):
        account._write_manifest(data)


def test_a_body_that_raises_leaves_the_manifest_alone(store):
    before = account.MANIFEST.read_text()
    with pytest.raises(ValueError):
        with account._manifest_transaction("test") as data:
            data["accounts"] = []
            raise ValueError("changed my mind")
    assert account.MANIFEST.read_text() == before


# --- releasing the account ------------------------------------------------


class Daemon:
    """The mail role's side of the handoff, with Google faked out."""

    def __init__(self, monkeypatch):
        self.calls = []
        monkeypatch.setattr(handoff_server.gmail_api, "stop_watch",
                            lambda acct: self.calls.append(("stop_watch", acct.id)) or True)
        monkeypatch.setattr(handoff_server.tokens, "revoke",
                            lambda acct: self.calls.append(("revoke", acct.id)) or True)
        monkeypatch.setattr(handoff_server.tokens, "forget",
                            lambda acct=None: self.calls.append(("forget", acct.id)))
        monkeypatch.setattr(handoff_server.google_client, "forget_services",
                            lambda account_id=None: self.calls.append(
                                ("forget_services", account_id)))

    def forget(self, account_id):
        return handoff_server.dispatch(
            {handoff.F_OP: handoff.OP_ACCOUNT_FORGET,
             handoff.F_ARGS: {"account_id": account_id}},
            lambda _msg: None,
        )


@pytest.fixture
def daemon(monkeypatch):
    return Daemon(monkeypatch)


@pytest.fixture(autouse=True)
def _no_jobs():
    voice_dna._JOBS.clear()
    yield
    voice_dna._JOBS.clear()


def test_forgetting_an_account_withdraws_the_grant_and_drops_the_caches(store, daemon):
    """All four, in the daemon, while the key that reads the refresh token still
    exists. Run after `delete_account` instead, the first two are not skipped --
    they are impossible."""
    reply = daemon.forget("dana@x.com")

    assert reply[handoff.F_RESULT] == {"voice": "none", "revoked": True,
                                       "watch_stopped": True}
    assert dict.fromkeys(name for name, _ in daemon.calls) == dict.fromkeys(
        ("stop_watch", "revoke", "forget", "forget_services"))


def test_a_failure_at_google_does_not_stop_the_release(store, daemon, monkeypatch):
    """The user asked to be deleted. An outage at Google must not turn that into
    an error page, and the caches must still be dropped."""
    def boom(acct):
        raise RuntimeError("google is down")

    monkeypatch.setattr(handoff_server.tokens, "revoke", boom)
    reply = daemon.forget("dana@x.com")

    assert reply[handoff.F_RESULT]["revoked"] is False
    assert reply[handoff.F_RESULT]["watch_stopped"] is True
    assert ("forget_services", "dana@x.com") in daemon.calls


def test_an_account_already_gone_still_has_its_caches_dropped(store, daemon):
    """The race this operation exists to lose gracefully: the row went first, so
    there is nothing to read a token with and nothing to name at Google, but the
    key is still in this process's memory."""
    reply = daemon.forget("nobody@x.com")

    assert reply[handoff.F_RESULT] == {"voice": "none", "revoked": False,
                                       "watch_stopped": False}
    assert ("forget_services", "nobody@x.com") in daemon.calls


def test_a_finished_voice_job_is_waited_out_and_dropped(store, daemon):
    voice_dna._JOBS["dana@x.com"] = {"state": "done", "started": 0, "error": None}
    assert daemon.forget("dana@x.com")[handoff.F_RESULT]["voice"] == "done"
    assert "dana@x.com" not in voice_dna._JOBS


def test_the_wait_fits_inside_the_window_the_web_tier_allows():
    """A wait longer than `handoff.TIMEOUT` turns an orderly release into a
    `HandoffUnavailable` on the deleting side, which then deletes anyway with
    the Google grant still standing."""
    assert voice_dna.AWAIT_TIMEOUT < handoff.TIMEOUT


def test_a_running_job_that_outlasts_the_wait_is_reported(store, daemon, monkeypatch):
    """There is no cancelling a thread mid-Gmail-fetch, so the honest answer is
    to say the wait ran out. What makes that safe is the refusal below, not the
    wait."""
    monkeypatch.setattr(voice_dna, "AWAIT_TIMEOUT", 0)
    monkeypatch.setattr(voice_dna, "AWAIT_POLL", 0)
    voice_dna._JOBS["dana@x.com"] = {"state": "running", "started": 0, "error": None}

    assert daemon.forget("dana@x.com")[handoff.F_RESULT]["voice"] == "timeout"


def test_no_key_is_minted_for_an_account_that_has_been_deleted(store, monkeypatch):
    """The refusal the wait cannot replace. `write_encrypted` mints a key when
    the account has none and `secure_dir` recreates `database/<id>/` to hold it,
    so a generation finishing after the deletion put the directory, its name and
    its timestamps back."""
    minted = []
    monkeypatch.setattr(keyring, "create", lambda uid, handle: minted.append(uid))
    gone = account.account_for_email("dana@x.com")
    account.delete_account("dana@x.com")

    with pytest.raises(keyring.AccountGone):
        keyring.write_encrypted(gone, "voice-dna.enc", "a profile")
    assert minted == []
    assert not (store / "dana@x.com").exists()


def test_onboarding_still_writes_before_the_manifest_entry_exists(store, monkeypatch):
    """The exemption, and why it is safe: `identify()` accepts an `(id, handle)`
    pair for exactly one caller, which encrypts a refresh token before writing
    the entry that would carry it. An Account object was built from a row that
    existed, so its absence now is the race."""
    minted = []
    monkeypatch.setattr(keyring, "create", lambda uid, handle: minted.append(uid))
    monkeypatch.setattr(keyring, "dek_for", lambda account: bytearray(32))

    keyring.write_encrypted(("newcomer@x.com", "a" * 32), "token.bin", "tok")
    assert minted == ["newcomer@x.com"]


# --- the job table --------------------------------------------------------


def test_finished_jobs_are_swept_rather_than_held_for_the_process_lifetime():
    """`clear_status` only ever ran for an account whose page was reloaded, so a
    user who closed the tab -- or deleted their account -- left an entry keyed by
    their address resident until the daemon restarted."""
    voice_dna._JOBS["stale@x.com"] = {"state": "done",
                                      "started": voice_dna.time.time()
                                      - voice_dna.JOB_RETENTION - 1,
                                      "error": None}
    voice_dna._JOBS["fresh@x.com"] = {"state": "done",
                                      "started": voice_dna.time.time(), "error": None}
    voice_dna._JOBS["busy@x.com"] = {"state": "running", "started": 0, "error": None}

    assert voice_dna.status("fresh@x.com") is not None
    assert "stale@x.com" not in voice_dna._JOBS
    assert "busy@x.com" in voice_dna._JOBS, "a running job is never swept"
