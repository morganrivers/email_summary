"""How a secret reaches the process, and the gate that refuses to run without one.

Two properties are pinned here, both of which the previous arrangement lost
silently: that under TEE_REQUIRED nothing is read off the volume (no .env load,
and a .env that exists at all fails the boot gate), and that the gate's notion
of "provisioned" covers every secret a service actually needs -- SESSION_SECRET
and the Polar credentials among them, which the old four-name list omitted.

The Google OAuth client is the widest-blast-radius value of the set and the last
one that was read off a volume. It is pinned in both directions: injected wins
everywhere, the file still serves a plain box, and inside a CVM the file is
refused by the reader and by the gate rather than quietly used.

The gate is exercised against a fake dstack client: attestation itself is Track
F's business, what is under test is what happens after it passes.
"""

import json

import pytest

from backend import paths, secrets, site
from backend.integrations import inference_attestation
from backend.integrations.gmail_gcal import oauth_app
from backend.tee import tee_boot


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    """A .env in a throwaway app root, with the loader reset to unread.

    The OAuth key file is pointed at the same throwaway root: it is a volume
    secret like .env now, so a developer's real one must not decide what these
    tests see."""
    path = tmp_path / ".env"
    monkeypatch.setattr(paths, "ENV_FILE", path)
    monkeypatch.setenv(oauth_app.KEYS_ENV, str(tmp_path / "gcp-oauth.keys.json"))
    monkeypatch.setattr(secrets, "_loaded", False)
    monkeypatch.setattr(secrets, "_from_file", set())
    return path


def write_keys_file(tmp_path):
    """The OAuth app as a file on the volume, the way a Hetzner box holds it."""
    path = tmp_path / "gcp-oauth.keys.json"
    path.write_text(json.dumps(
        {"web": {"client_id": "file-id", "client_secret": "file-secret"}}))
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
    monkeypatch.setenv("NEARAI_API_KEY", "k")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "k")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "c")
    monkeypatch.setenv("SESSION_SECRET", "s")
    monkeypatch.setenv("POLAR_API_TOKEN", "t")
    monkeypatch.setenv("POLAR_ORGANIZATION_ID", "o")
    monkeypatch.setenv("POLAR_WEBHOOK_SECRET", "w")
    monkeypatch.setenv(secrets.GOOGLE_CLIENT_ID_ENV, "id")
    monkeypatch.setenv(secrets.GOOGLE_CLIENT_SECRET_ENV, "sec")


def test_fully_provisioned_box_has_no_gaps(env_file, monkeypatch):
    _provision(monkeypatch)
    assert secrets.missing() == []


@pytest.mark.parametrize("name", [
    "SESSION_SECRET",
    "POLAR_API_TOKEN",
    "POLAR_WEBHOOK_SECRET",
    "DEEPSEEK_API_KEY",
    "TELEGRAM_CHAT_ID",
    "GOOGLE_OAUTH_CLIENT_SECRET",
])
def test_each_required_secret_is_actually_required(env_file, monkeypatch, name):
    _provision(monkeypatch)
    monkeypatch.delenv(name, raising=False)

    gaps = secrets.missing()
    assert gaps, f"{name} missing but the gate saw no gap"
    assert any(name in reason for reason in gaps), gaps


def test_the_injected_oauth_pair_beats_the_file_on_the_volume(
        env_file, tmp_path, monkeypatch):
    """A stale key file must not shadow what the KMS released; the file is the
    fallback, never the winner."""
    monkeypatch.delenv("TEE_REQUIRED", raising=False)
    write_keys_file(tmp_path)
    monkeypatch.setenv(secrets.GOOGLE_CLIENT_ID_ENV, "injected-id")
    monkeypatch.setenv(secrets.GOOGLE_CLIENT_SECRET_ENV, "injected-secret")

    assert oauth_app.load_keys() == ("injected-id", "injected-secret")


def test_the_key_file_still_serves_a_plain_box(env_file, tmp_path, monkeypatch):
    """Hetzner has no KMS to inject from. Removing the fallback would take
    sign-in down on the box that runs today."""
    monkeypatch.delenv("TEE_REQUIRED", raising=False)
    monkeypatch.delenv(secrets.GOOGLE_CLIENT_ID_ENV, raising=False)
    monkeypatch.delenv(secrets.GOOGLE_CLIENT_SECRET_ENV, raising=False)
    write_keys_file(tmp_path)

    assert oauth_app.load_keys() == ("file-id", "file-secret")
    assert secrets.google_oauth_configured() is None


def test_half_an_injected_pair_is_not_a_pair(env_file, tmp_path, monkeypatch):
    """A stray client_id with no secret must fall through to the file rather
    than send a half-configured app to Google."""
    monkeypatch.delenv("TEE_REQUIRED", raising=False)
    monkeypatch.setenv(secrets.GOOGLE_CLIENT_ID_ENV, "injected-id")
    monkeypatch.delenv(secrets.GOOGLE_CLIENT_SECRET_ENV, raising=False)
    write_keys_file(tmp_path)

    assert secrets.google_oauth_client() is None
    assert oauth_app.load_keys() == ("file-id", "file-secret")


def test_a_tee_refuses_the_key_file_and_names_what_to_inject(
        env_file, tmp_path, monkeypatch):
    """The client secret is the widest-blast-radius value here. Inside the
    enclave a file copy is one the KMS does not gate, so the reader refuses it
    outright instead of preferring the injected pair and quietly falling back."""
    monkeypatch.setenv("TEE_REQUIRED", "1")
    monkeypatch.delenv(secrets.GOOGLE_CLIENT_ID_ENV, raising=False)
    monkeypatch.delenv(secrets.GOOGLE_CLIENT_SECRET_ENV, raising=False)
    write_keys_file(tmp_path)

    with pytest.raises(AssertionError) as err:
        oauth_app.load_keys()
    assert secrets.GOOGLE_CLIENT_SECRET_ENV in str(err.value)
    assert "file-secret" not in str(err.value), "the refusal quoted the secret"

    reason = secrets.google_oauth_configured()
    assert reason and secrets.GOOGLE_CLIENT_ID_ENV in reason


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
    # The two role capabilities, satisfied so the secret checks are what these
    # tests are reading. Whether the dcap-qvl wheel made it into the image is a
    # property of the build and not of this environment; the hosts are read at
    # import, so a CVM sets them before the process starts and a test cannot.
    monkeypatch.setattr(inference_attestation, "configured", lambda providers: None)
    monkeypatch.setattr(site, "APP_HOST", "enclave.example")
    monkeypatch.setattr(site, "API_HOST", "api.enclave.example")


@pytest.mark.parametrize("role", sorted(secrets.REQUIRED_BY_ROLE))
def test_gate_passes_when_attested_and_provisioned(attested, env_file, monkeypatch, role):
    _provision(monkeypatch)
    assert tee_boot.run_gate(role) == 0


def test_gate_fails_closed_on_a_missing_secret(attested, env_file, monkeypatch, capsys):
    _provision(monkeypatch)
    monkeypatch.delenv("SESSION_SECRET", raising=False)

    assert tee_boot.run_gate("web") == 1
    assert "SESSION_SECRET" in capsys.readouterr().err


def test_the_gate_asks_only_what_a_role_is_handed(attested, env_file, monkeypatch):
    """The bug this replaced: the gate applied the whole-box set, so `web`
    failed for holding no inference key and `mail` for holding no
    SESSION_SECRET. Both are absent by design and measured to be absent, so the
    tempting repair -- every variable in every container -- is the partition
    undone."""
    _provision(monkeypatch)
    monkeypatch.delenv("SESSION_SECRET", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("NEARAI_API_KEY", raising=False)

    assert tee_boot.run_gate("mail") == 1, "mail needs an inference key"
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k")
    monkeypatch.setenv("NEARAI_API_KEY", "k")
    assert tee_boot.run_gate("mail") == 0, "mail was refused for a secret it never holds"


def test_the_gate_refuses_a_container_it_cannot_name(attested, env_file, monkeypatch, capsys):
    """No role, nothing to require. A gate that fell back to the whole-box set
    here would be the old bug reachable by dropping one argument, and one that
    fell back to the empty set would pass anything."""
    _provision(monkeypatch)

    assert tee_boot.run_gate("") == 1
    assert tee_boot.run_gate("everything") == 1
    assert "FAIL-CLOSED" in capsys.readouterr().err


def test_the_gate_refuses_a_role_still_naming_the_other_deployment(
        attested, env_file, monkeypatch, capsys):
    """Every externally visible URL is built from `site.APP_HOST`. Left at the
    compiled-in default, an enclave sends its users to the Hetzner box for
    consent and for the checkout return."""
    _provision(monkeypatch)
    monkeypatch.setattr(site, "APP_HOST", site.DEFAULT_APP_HOST)

    assert tee_boot.run_gate("web") == 1
    assert "LETTERLOCK_HOST" in capsys.readouterr().err


def test_the_mail_gate_refuses_an_image_that_cannot_attest_inference(
        attested, env_file, monkeypatch, capsys):
    """A build that dropped the dcap-qvl wheel starts cleanly and then refuses
    every confidential draft at the first email, with the reason in a per-draft
    log line. The role that drafts is the role that has to ask at boot."""
    _provision(monkeypatch)
    monkeypatch.setattr(inference_attestation, "configured",
                        lambda providers: "dcap-qvl is not installed")

    assert tee_boot.run_gate("web") == 0, "the web role reads no mailbox"
    assert tee_boot.run_gate("mail") == 1
    assert "dcap-qvl" in capsys.readouterr().err


def test_gate_fails_closed_when_a_dotenv_file_exists(attested, env_file, monkeypatch, capsys):
    _provision(monkeypatch)
    env_file.write_text("DEEPSEEK_API_KEY=from-the-volume\n")

    assert tee_boot.run_gate("mail") == 1
    assert "FAIL-CLOSED" in capsys.readouterr().err


def test_gate_fails_closed_when_the_oauth_key_file_exists(attested, env_file,
                                                          tmp_path, monkeypatch, capsys):
    """Re-adding the /app/.gmail-mcp mount must stop the enclave booting rather
    than silently putting the client secret back outside the KMS. The injected
    pair is present here, so the only thing being refused is the file."""
    _provision(monkeypatch)
    keys = write_keys_file(tmp_path)

    assert tee_boot.run_gate("mail") == 1
    assert str(keys) in capsys.readouterr().err


def test_gate_fails_closed_without_the_oauth_client(attested, env_file, monkeypatch, capsys):
    """Nothing on the volume to fall back to, and nothing injected: the enclave
    would boot into a sign-in surface that cannot talk to Google."""
    _provision(monkeypatch)
    monkeypatch.delenv(secrets.GOOGLE_CLIENT_SECRET_ENV, raising=False)

    assert tee_boot.run_gate("mail") == 1
    assert secrets.GOOGLE_CLIENT_SECRET_ENV in capsys.readouterr().err


def test_gate_no_ops_outside_a_tee(env_file, monkeypatch):
    monkeypatch.setattr(tee_boot, "DstackClient", lambda *a, **k: FakeDstack())
    monkeypatch.delenv("TEE_REQUIRED", raising=False)
    env_file.write_text("DEEPSEEK_API_KEY=from-the-volume\n")

    assert tee_boot.run_gate("mail") == 0


def test_fingerprint_identifies_without_revealing():
    secret = "polar_whs_a-real-looking-value"
    fp = secrets.fingerprint(secret)

    assert fp == secrets.fingerprint(secret)
    assert fp != secrets.fingerprint(secret + "x")
    assert secret not in fp and secret[:6] not in fp
    assert secrets.fingerprint("") == "(unset)"
    assert secrets.fingerprint(None) == "(unset)"
    assert secrets.fingerprint(secret.encode()) == fp
