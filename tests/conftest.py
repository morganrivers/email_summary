"""Hermetic wiring for the characterization suite.

.env is NEVER read: backend.secrets.load -- the one loader every module now
calls -- is marked already-done before any app module imports, load_dotenv is
neutralized for anything outside the package, and dummy secrets are forced into
the environment first (modules read env at import). test_secrets.py exercises
the real loader by clearing that flag against a temporary file.
"""

import json
import os
import sys
from collections import deque
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

os.environ["DEEPSEEK_API_KEY"] = "test-key-not-real"
os.environ["TELEGRAM_BOT_TOKEN"] = "test-bot-token"
os.environ["TELEGRAM_CHAT_ID"] = "test-chat-id"

import dotenv

dotenv.load_dotenv = lambda *args, **kwargs: False

from backend import secrets as app_secrets

app_secrets._loaded = True

import harness
import identity_fixture
import pytest

# owner_identity() reads these through secrets.get at call time, so they can be
# set after the app modules import. There is deliberately no default in the
# code: a box with no owner configured must fail loudly rather than mask every
# account's mail under whatever name shipped in the repository.
os.environ.update(identity_fixture.OWNER_ENV)


@pytest.fixture(autouse=True)
def audit_log(tmp_path):
    """Every account mutator writes an audit row, so every test that touches one
    would otherwise write into the checkout's own state/audit.db. Autouse rather
    than opt-in: a test that forgets it pollutes the working tree instead of
    failing, which is the kind of miss nobody notices."""
    from backend import audit

    audit.reset_for_test(tmp_path / "audit")
    yield audit
    audit.reset_for_test()
    os.environ.pop("LETTERLOCK_AUDIT_DIR", None)


@pytest.fixture
def wire(monkeypatch, tmp_path):
    import requests

    from backend.accounts import account, state
    from backend.drafting import agentic_drafter, schedule_from_sent, voice_dna
    from backend.integrations import llm_client

    rec = harness.Recorder()

    # Pin the masking mode before the account is built, so what the goldens
    # record does not depend on whether Presidio and spaCy happen to be
    # installed on the machine running pytest. See harness.without_analyzer.
    real_owner_identity = account.owner_identity
    monkeypatch.setattr(account, "owner_identity",
                        lambda: harness.without_analyzer(real_owner_identity()))

    # The voice profile is per account now; the fixture stands in for the
    # neutral default that any account without its own profile gets.
    monkeypatch.setattr(voice_dna, "DEFAULT_PROFILE", harness.VOICE_FIXTURE)
    monkeypatch.setattr(state, "DEFAULT_STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(agentic_drafter, "datetime", harness.FrozenDateTime)
    monkeypatch.setattr(schedule_from_sent, "datetime", harness.frozen_datetime_namespace())

    # There is no implicit account any more: anything that enumerates users goes
    # through the manifest, so the harness writes a throwaway one holding exactly
    # the owner. Keyed "default" like owner_account() rather than by email, so
    # the golden outputs stay pinned to the identity under test.
    acct = account.owner_account()
    manifest = tmp_path / "database" / "accounts.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps({"accounts": [{
        "id": acct.id,
        # The same handle the in-memory account carries. Every registered
        # account has one, and the paths that read a user's own documents name
        # their key by it; a manifest entry without one is an account whose
        # personal context cannot be opened, which the sweep swallows as a
        # per-account failure rather than reporting.
        "handle": acct.handle,
        "identity": {
            "first": acct.identity.first,
            "last": acct.identity.last,
            "first_aliases": acct.identity.first_aliases,
            "emails": acct.identity.emails,
        },
        "telegram": {"chat_id": acct.telegram.chat_id, "token": acct.telegram.token},
        "state_file": str(acct.state.path),
        "plan_status": "active",
        "timezone": "Europe/Berlin",
        "auto_schedule": True,
        # Same pin as the identity above: an account reloaded from this manifest
        # must mask the way the goldens were recorded, not the way the box is
        # provisioned. Without it _account_from_entry defaults to True and the
        # two disagree.
        "pii_analyzer": False,
    }]}))
    monkeypatch.setattr(account, "ACCOUNTS_DIR", manifest.parent)
    monkeypatch.setattr(account, "MANIFEST", manifest)

    def install(responses=(), gmail_outputs=None):
        dq = deque(responses)
        monkeypatch.setattr(llm_client, "OpenAI", lambda *a, **k: harness.FakeOpenAI(rec, dq))
        harness.install_gmail_fakes(monkeypatch, rec, gmail_outputs or {})
        monkeypatch.setattr(requests, "post", harness.make_fake_post(rec))
        return rec

    # The drafting path reads two per-account documents, and since Track G both
    # are encrypted under that account's data key. Without custody in place they
    # do not read as empty -- they raise -- so every fixture that drafts needs
    # both halves present, which is the change working as intended.
    with harness.custody_available(tmp_path, monkeypatch):
        yield SimpleNamespace(rec=rec, install=install, tmp_path=tmp_path, account=acct)
