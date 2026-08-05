"""How a secret reaches the process, and the gate that refuses to run without one.

Two properties are pinned here, both of which the previous arrangement lost
silently: that under TEE_REQUIRED nothing is read off the volume (no .env load,
and a .env that exists at all fails the boot gate), and that the gate's notion
of "provisioned" covers every secret a service actually needs -- SESSION_SECRET
and the Polar credentials among them, which the old four-name list omitted.

The Google OAuth client is the exception, and is tested as one: oauth_app.py
still reads it off the volume, so the gate must not demand the injected form
yet.

The gate is exercised against a fake dstack client: attestation itself is Track
F's business, what is under test is what happens after it passes.
"""

import pytest

from backend import paths
from backend import secrets
from backend.tee import tee_boot


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    """A .env in a throwaway app root, with the loader reset to unread."""
    path = tmp_path / ".env"
    monkeypatch.setattr(paths, "ENV_FILE", path)
    monkeypatch.setattr(secrets, "_loaded", False)
    monkeypatch.setattr(secrets, "_from_file", set())
    return path


def test_load_reads_env_file_outside_a_tee(env_file, monkeypatch):
    monkeypatch.delenv("TEE_REQUIRED", raising=False)
    monkeypatch.delenv("SOME_API_KEY", raising=False)
    env_file.write_text("SOME_API_KEY=from-the-file\n")

    assert secrets.get("SOME_API_KEY") == "from-the-file"
    assert secrets.file_backed() == ("SOME_API_KEY",)


def test_injected_environment_wins_over_the_file(env_file, monkeypatch):
    monkeypatch.delenv("TEE_REQUIRED", raising=False)
    monkeypatch.setenv("SOME_API_KEY", "injected")
    env_file.write_text("SOME_API_KEY=from-the-file\n")

    assert secrets.get("SOME_API_KEY") == "injected"
    assert secrets.file_backed() == ()


def test_tee_reads_no_file_even_when_one_is_present(env_file, monkeypatch):
    monkeypatch.setenv("TEE_REQUIRED", "1")
    monkeypatch.delenv("SOME_API_KEY", raising=False)
    env_file.write_text("SOME_API_KEY=from-the-file\n")

    assert secrets.get("SOME_API_KEY") is None
    assert secrets.file_backed() == ()


def test_require_names_the_variable_and_not_the_value(env_file, monkeypatch):
    monkeypatch.delenv("TEE_REQUIRED", raising=False)
    monkeypatch.setenv("SOME_API_KEY", "s3cret")

    assert secrets.require("SOME_API_KEY") == "s3cret"
    with pytest.raises(AssertionError) as err:
        secrets.require("NEVER_SET_ANYWHERE")
    assert "NEVER_SET_ANYWHERE" in str(err.value)


def _provision(monkeypatch):
    """Every secret the gate requires, present."""
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k")
    monkeypatch.setenv("TRESOR_API_KEY", "k")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "k")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "c")
    monkeypatch.setenv("SESSION_SECRET", "s")
    monkeypatch.setenv("POLAR_API_TOKEN", "t")
    monkeypatch.setenv("POLAR_ORGANIZATION_ID", "o")
    monkeypatch.setenv("POLAR_WEBHOOK_SECRET", "w")


def test_fully_provisioned_box_has_no_gaps(env_file, monkeypatch):
    _provision(monkeypatch)
    assert secrets.missing() == []


@pytest.mark.parametrize("name", [
    "SESSION_SECRET",
    "POLAR_API_TOKEN",
    "POLAR_WEBHOOK_SECRET",
    "DEEPSEEK_API_KEY",
    "TELEGRAM_CHAT_ID",
])
def test_each_required_secret_is_actually_required(env_file, monkeypatch, name):
    _provision(monkeypatch)
    monkeypatch.delenv(name, raising=False)

    gaps = secrets.missing()
    assert gaps, f"{name} missing but the gate saw no gap"
    assert any(name in reason for reason in gaps), gaps


def test_google_oauth_pair_is_read_but_not_yet_gated(env_file, monkeypatch):
    """oauth_app.py still reads the client secret off the volume, so requiring
    the injected pair would refuse boot over a value nothing consults. The
    accessor and the check exist for onboarding-exchange-4 to switch on; what
    is pinned here is that the gate does not demand them before then."""
    _provision(monkeypatch)
    monkeypatch.delenv(secrets.GOOGLE_CLIENT_ID_ENV, raising=False)
    monkeypatch.delenv(secrets.GOOGLE_CLIENT_SECRET_ENV, raising=False)

    assert secrets.google_oauth_client() is None
    assert secrets.GOOGLE_CLIENT_SECRET_ENV in secrets.google_oauth_configured()
    assert secrets.missing() == []

    monkeypatch.setenv(secrets.GOOGLE_CLIENT_ID_ENV, "id")
    monkeypatch.setenv(secrets.GOOGLE_CLIENT_SECRET_ENV, "sec")
    assert secrets.google_oauth_client() == ("id", "sec")
    assert secrets.google_oauth_configured() is None


class FakeDstack:
    """An enclave that attests cleanly. Refusals are Track F's tests, not these."""

    INFO = {"app_id": "app", "instance_id": "inst", "compose_hash": "abc",
            "mr_aggregated": "mr", "os_image_hash": "os", "key_provider_info": {}}

    def available(self):
        return True

    def info(self):
        return dict(self.INFO)

    def get_tls_key(self, subject=None, client_auth=False):
        return {"key": "-----BEGIN PRIVATE KEY-----", "certificate_chain": ["-----BEGIN CERT-----"]}

    def get_key(self, path, purpose=None):
        return {"key": "00", "signature_chain": []}

    def get_quote(self, report_data):
        return {"quote": "de", "event_log": "[]", "report_data": report_data.hex()}


@pytest.fixture
def attested(tmp_path, monkeypatch):
    monkeypatch.setattr(tee_boot, "DstackClient", lambda *a, **k: FakeDstack())
    monkeypatch.setattr(tee_boot, "ATTEST_DIR", tmp_path / "attestation")
    monkeypatch.setenv("TEE_REQUIRED", "1")
    monkeypatch.delenv("EXPECTED_COMPOSE_HASH", raising=False)


def test_gate_passes_when_attested_and_provisioned(attested, env_file, monkeypatch):
    _provision(monkeypatch)
    assert tee_boot.run_gate() == 0


def test_gate_fails_closed_on_a_missing_secret(attested, env_file, monkeypatch, capsys):
    _provision(monkeypatch)
    monkeypatch.delenv("SESSION_SECRET", raising=False)

    assert tee_boot.run_gate() == 1
    assert "SESSION_SECRET" in capsys.readouterr().err


def test_gate_fails_closed_when_a_dotenv_file_exists(attested, env_file, monkeypatch, capsys):
    _provision(monkeypatch)
    env_file.write_text("DEEPSEEK_API_KEY=from-the-volume\n")

    assert tee_boot.run_gate() == 1
    assert "FAIL-CLOSED" in capsys.readouterr().err


def test_gate_no_ops_outside_a_tee(env_file, monkeypatch):
    monkeypatch.setattr(tee_boot, "DstackClient", lambda *a, **k: FakeDstack())
    monkeypatch.delenv("TEE_REQUIRED", raising=False)
    env_file.write_text("DEEPSEEK_API_KEY=from-the-volume\n")

    assert tee_boot.run_gate() == 0


def test_fingerprint_identifies_without_revealing():
    secret = "polar_whs_a-real-looking-value"
    fp = secrets.fingerprint(secret)

    assert fp == secrets.fingerprint(secret)
    assert fp != secrets.fingerprint(secret + "x")
    assert secret not in fp and secret[:6] not in fp
    assert secrets.fingerprint("") == "(unset)"
    assert secrets.fingerprint(None) == "(unset)"
    assert secrets.fingerprint(secret.encode()) == fp
