"""Hermetic wiring for the characterization suite.

.env is NEVER read: load_dotenv is neutralized and dummy secrets are forced
into the environment BEFORE any app module imports (they read env at import).
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
os.environ.pop("LANGCHAIN_API_KEY", None)
os.environ.pop("LANGSMITH_API_KEY", None)

import dotenv
dotenv.load_dotenv = lambda *args, **kwargs: False

import pytest

import harness


@pytest.fixture
def wire(monkeypatch, tmp_path):
    import subprocess
    import requests
    from backend.integrations import llm_client
    from backend.accounts import state
    from backend.accounts import account
    from backend.drafting import draft_replies
    from backend.drafting import agentic_drafter
    from backend.drafting import schedule_from_sent
    from backend.drafting import voice_dna

    rec = harness.Recorder()

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
    }]}))
    monkeypatch.setattr(account, "ACCOUNTS_DIR", manifest.parent)
    monkeypatch.setattr(account, "MANIFEST", manifest)
    real_run = subprocess.run

    def install(responses=(), node_outputs=None):
        dq = deque(responses)
        monkeypatch.setattr(llm_client, "OpenAI", lambda *a, **k: harness.FakeOpenAI(rec, dq))
        monkeypatch.setattr(subprocess, "run", harness.make_fake_run(rec, node_outputs or {}, real_run))
        monkeypatch.setattr(requests, "post", harness.make_fake_post(rec))
        return rec

    return SimpleNamespace(rec=rec, install=install, tmp_path=tmp_path, account=acct)
