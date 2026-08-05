"""What must hold before a user's mail reaches an inference enclave.

The rest of the suite is hermetic, so the checks that talk to NEAR AI's real
endpoints are opt-in: run them with LETTERLOCK_LIVE_ATTESTATION=1. They are the
only thing that can tell you the pins in inference_allowlist.json still
describe what is deployed, so run them before a release, not only in CI.
Everything else here works offline against a recorded report.
"""

import copy
import json
import os
from pathlib import Path

import pytest

from backend.integrations import inference_attestation as att
from backend.integrations import llm_client
from backend.tee import quote_policy

FIXTURE = Path(__file__).parent / "fixtures" / "nearai_attestation_report.json"

live = pytest.mark.skipif(
    not os.environ.get("LETTERLOCK_LIVE_ATTESTATION"),
    reason="set LETTERLOCK_LIVE_ATTESTATION=1 to check the pins against the live enclaves",
)

pytestmark = pytest.mark.usefixtures("packaged_allowlist")


@pytest.fixture
def packaged_allowlist():
    att.reset_for_test()
    yield
    att.reset_for_test()


@pytest.fixture
def recorded():
    payload = json.loads(FIXTURE.read_text())
    return att.Report(payload, payload["request_nonce"])


def provider(name):
    return llm_client.PROVIDERS[name]


def test_every_confidential_provider_names_an_attestation_endpoint():
    for p in llm_client.PROVIDERS.values():
        assert p.confidential == p.attests(), (
            f"{p.name} claims confidential={p.confidential} but attests()={p.attests()}"
        )


def test_a_confidential_provider_cannot_be_declared_without_an_endpoint():
    with pytest.raises(AssertionError) as err:
        llm_client.Provider(
            name="claims-too-much", label="x", base_url="https://example.invalid/v1",
            model="m", key_env="X_API_KEY", confidential=True, blurb="",
        )
    assert "names no attestation endpoint" in str(err.value)


def test_every_confidential_provider_is_pinned():
    assert att.configured(llm_client.PROVIDERS.values()) is None


def test_report_data_binds_the_signing_address_and_our_nonce(recorded):
    expected = recorded.expected_report_data()
    assert len(expected) == 64
    assert expected[:20] == recorded.address_bytes()
    assert expected[32:] == bytes.fromhex(recorded.nonce)


def test_a_replayed_nonce_is_refused(recorded):
    stale = att.Report(recorded.payload, "00" * att.NONCE_BYTES)
    assert not stale.echoed_our_nonce()


def test_binding_rejects_a_quote_bound_to_something_else():
    assert quote_policy._binds(b"abc" + bytes(5), b"abc")
    assert not quote_policy._binds(b"abd" + bytes(5), b"abc")
    assert not quote_policy._binds(b"abc" + b"\x01", b"abc")


def test_an_empty_binding_is_refused():
    with pytest.raises(AssertionError):
        quote_policy._binds(b"anything", b"")


def test_an_allowlist_entry_must_pin_mr_td(tmp_path):
    path = tmp_path / "allowlist.json"
    path.write_text(json.dumps({
        "mode": "required", "pccs_url": "https://pccs.phala.network",
        "allowed_tcb_status": ["UpToDate"],
        "measurements": [{"name": "pins nothing", "scope": "nearai-glm"}],
    }))
    att.reset_for_test(path)
    with pytest.raises(AssertionError) as err:
        att.policy().match({"mr_td": "whatever"}, "nearai-glm")
    assert "does not pin mr_td" in str(err.value)


def test_a_pin_authorizes_only_its_own_provider():
    entries = att.policy().entries("nearai-glm")
    assert entries, "GLM has no authorized image"
    actual = {f: entries[0].get(f) for f in quote_policy.MEASUREMENT_FIELDS}
    assert att.policy().match(actual, "nearai-glm")
    assert att.policy().match(actual, "nearai-gpt-oss") is None


def test_dev_insecure_is_refused_on_a_pinned_box():
    with pytest.raises(AssertionError) as err:
        att.policy().mode("dev-insecure")
    assert "looks provisioned for production" in str(err.value)


def test_require_raises_rather_than_returning_an_unverified_client(monkeypatch):
    monkeypatch.setattr(att, "verify", lambda p: quote_policy.Verdict(
        False, p.name, reason="measurement is not on the allowlist", measurement="abc"))
    with pytest.raises(att.AttestationError) as err:
        att.require(provider("nearai-glm"))
    assert "refusing to send mail" in str(err.value)


def test_make_client_refuses_when_attestation_fails(monkeypatch):
    monkeypatch.setenv("NEARAI_API_KEY", "k")

    class Account:
        inference_provider = "nearai-glm"

    monkeypatch.setattr(att, "verify", lambda p: quote_policy.Verdict(
        False, p.name, reason="quote does not parse"))
    with pytest.raises(att.AttestationError):
        llm_client.make_client(Account())


def test_a_wrong_model_is_refused(monkeypatch, recorded):
    payload = copy.deepcopy(recorded.payload)
    payload["model_name"] = "openai/gpt-oss-120b"
    monkeypatch.setattr(att, "fetch", lambda p, nonce=None: att.Report(
        payload, payload["request_nonce"]))
    verdict = att.verify(provider("nearai-glm"))
    assert not verdict.ok
    assert "not 'z-ai/glm-5.2'" in verdict.reason


def test_an_unreachable_endpoint_is_a_denial_not_a_pass(monkeypatch):
    def boom(provider, nonce=None):
        raise OSError("connection refused")

    monkeypatch.setattr(att, "fetch", boom)
    verdict = att.verify(provider("nearai-glm"))
    assert not verdict.ok
    assert "unavailable" in verdict.reason


@live
@pytest.mark.parametrize("name", ["nearai-glm", "nearai-gpt-oss"])
def test_live_endpoint_verifies_against_the_committed_pins(name):
    verdict = att.verify(provider(name))
    assert verdict.ok, (
        f"{name} no longer matches the allowlist: {verdict.reason}. Re-pin with "
        f"`python -m backend.integrations.inference_attestation {name}`, review "
        f"the diff, and commit it."
    )
    assert verdict.attested


@live
def test_live_endpoint_binds_a_nonce_we_choose():
    report = att.fetch(provider("nearai-glm"))
    assert report.echoed_our_nonce()
    quote = report.quote
    dcap = quote_policy.load_dcap()
    report_data = bytes(dcap.parse_quote(quote).report.report_data)
    assert report_data == report.expected_report_data()
