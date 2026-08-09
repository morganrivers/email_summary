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


def test_a_cached_pass_is_not_served_to_an_endpoint_that_ignores_our_nonce(
        monkeypatch, recorded):
    """The cache key is what the endpoint says about itself, so freshness has to
    be established before it is consulted. Otherwise anything that can replay a
    verified instance's signing address, instance id and actions_hash inherits
    that instance's verdict without ever answering the nonce we sent."""
    subject = f"nearai-glm:{recorded.identity()}"
    att._CACHE.put(subject, quote_policy.Verdict(True, subject, attested=True))
    payload = copy.deepcopy(recorded.payload)
    monkeypatch.setattr(att, "fetch",
                        lambda p, nonce=None: att.Report(payload, "a-nonce-we-just-made"))

    verdict = att.verify(provider("nearai-glm"))

    assert not verdict.ok
    assert "not the one we sent" in verdict.reason


def test_a_refusal_is_rechecked_long_before_a_pass_is(recorded):
    """A pass describes an image and holds for a day. A refusal is as likely to
    describe a PCCS that timed out, and holding that for a day would take
    drafting down until the process restarts."""
    cache = quote_policy.VerdictCache()
    assert cache.failure_seconds < cache.recheck_seconds / 10

    cache.put("subject", quote_policy.Verdict(False, "subject", reason="collateral timed out"))
    assert cache.get("subject") is not None
    cache.failure_seconds = 0
    assert cache.get("subject") is None

    cache.put("subject", quote_policy.Verdict(True, "subject", attested=True))
    assert cache.get("subject") is not None


@pytest.mark.parametrize("field,value", [
    ("intel_quote", "not hex at all"),
    ("intel_quote", ""),
    ("signing_address", "0xdeadbeef"),
])
def test_a_malformed_field_is_a_denial_with_a_reason(monkeypatch, recorded, field, value):
    """Every field of a report is written by the party being checked, so a hex
    string that does not decode is an answer, not a bug here. It has to come
    back as a Verdict like any other refusal rather than as an AssertionError or
    a ValueError out of the middle of drafting."""
    payload = copy.deepcopy(recorded.payload)
    payload[field] = value
    monkeypatch.setattr(att, "fetch", lambda p, nonce=None: att.Report(
        payload, payload["request_nonce"]))

    verdict = att.verify(provider("nearai-glm"))

    assert not verdict.ok
    assert field.split("_")[-1] in verdict.reason


def test_an_unreachable_endpoint_is_a_denial_not_a_pass(monkeypatch):
    def boom(provider, nonce=None):
        raise OSError("connection refused")

    monkeypatch.setattr(att, "fetch", boom)
    verdict = att.verify(provider("nearai-glm"))
    assert not verdict.ok
    assert "unavailable" in verdict.reason


def test_actions_hash_is_recomputed_not_trusted(recorded):
    log = recorded.compose_log()
    assert log.hash_is_honest()
    assert log.computed_hash() == log.claimed_hash


def test_an_appended_action_breaks_the_hash(recorded):
    payload = copy.deepcopy(recorded.compose_log().payload)
    payload["actions"].append({
        "timestamp": "2026-08-05T00:00:00+00:00", "action": "compose_up",
        "tag": "v0", "commit": "0" * 40, "file": "exfiltrate.yaml",
        "file_sha256": "0" * 64,
    })
    tampered = att.ComposeLog(payload, recorded.nonce)
    assert not tampered.hash_is_honest(), (
        "an edited action log must not still match the hash the quote signs"
    )


def test_compose_log_report_data_binds_the_hash_and_our_nonce(recorded):
    log = recorded.compose_log()
    expected = log.expected_report_data()
    assert len(expected) == 64
    assert expected.hex() == log.payload["report_data"]
    assert expected[:32].hex() == log.claimed_hash
    assert expected[32:].hex() == recorded.nonce


def test_started_tracks_up_and_down(recorded):
    """A compose counts as started when its most recent action brought it up.
    Anything torn down since must not be demanded of the allowlist."""
    log = recorded.compose_log()
    started = log.started()
    assert started, "the log records no compose brought up"
    assert all(isinstance(v, str) and len(v) == 64 for v in started.values())
    for name in started:
        last = [a for a in log.actions if a.get("file") == name][-1]
        assert last["action"] == "compose_up", (
            f"{name} is reported started but its last action was {last['action']}"
        )
    torn_down = {a["file"] for a in log.actions if a.get("action") == "compose_down"}
    for name in torn_down - set(started):
        last = [a for a in log.actions if a.get("file") == name][-1]
        assert last["action"] == "compose_down"


def test_every_started_compose_is_authorized(recorded):
    authorized = {row["file"]: row["file_sha256"]
                  for row in att.policy().rows("composes", "nearai-glm")}
    for name, digest in recorded.compose_log().started().items():
        assert authorized.get(name) == digest, (
            f"{name} ran in the enclave but is not pinned; review it and add it"
        )


def _with_extra_action(recorded, entry):
    payload = copy.deepcopy(recorded.payload)
    payload["compose_manager_attestation"]["actions"].append(entry)
    return payload


UNPINNED = {
    "timestamp": "2026-08-05T00:00:00+00:00", "action": "compose_up",
    "tag": "v0", "commit": "0" * 40, "file": "prod/something-new.yaml",
    "file_sha256": "1" * 64,
}


def test_appending_an_action_and_rehashing_still_fails(monkeypatch, recorded):
    """Recomputing actions_hash is not a way around the log: the quote signs the
    hash the manager published, so a consistent-looking forgery no longer binds
    to it. This is the stronger of the two failures and must come first."""
    payload = _with_extra_action(recorded, UNPINNED)
    log = payload["compose_manager_attestation"]
    log["actions_hash"] = att.ComposeLog(log, recorded.nonce).computed_hash()
    monkeypatch.setattr(att, "fetch", lambda p, nonce=None: att.Report(
        payload, payload["request_nonce"]))
    verdict = att.verify(provider("nearai-glm"))
    assert not verdict.ok
    assert "report_data does not carry the expected binding" in verdict.reason


def test_an_unpinned_compose_is_refused(monkeypatch, recorded):
    """The authorization decision itself, with both quotes taken as good, so the
    test does not need PCCS. `test_live_endpoint_verifies_against_the_committed_pins`
    is what checks the real ones."""
    payload = _with_extra_action(recorded, UNPINNED)
    log = payload["compose_manager_attestation"]
    log["actions_hash"] = att.ComposeLog(log, recorded.nonce).computed_hash()
    monkeypatch.setattr(quote_policy, "verify", lambda *a, **k: quote_policy.Verdict(
        True, "stub", measurement="stub", attested=True))
    monkeypatch.setattr(att, "fetch", lambda p, nonce=None: att.Report(
        payload, payload["request_nonce"]))
    verdict = att.verify(provider("nearai-glm"))
    assert not verdict.ok
    assert "unauthorized composes" in verdict.reason
    assert "prod/something-new.yaml" in verdict.reason


def test_a_missing_compose_log_is_a_denial(monkeypatch, recorded):
    payload = copy.deepcopy(recorded.payload)
    payload.pop("compose_manager_attestation")
    monkeypatch.setattr(att, "fetch", lambda p, nonce=None: att.Report(
        payload, payload["request_nonce"]))
    verdict = att.verify(provider("nearai-glm"))
    assert not verdict.ok
    assert "no compose-manager attestation" in verdict.reason


def test_two_instances_sharing_a_signing_key_are_not_conflated(recorded):
    """NEAR runs several CVMs behind one hostname and they can share a signing
    address. Caching on that alone would let a pinned instance's pass be
    replayed for an unpinned one, which is the whole check bypassed by a load
    balancer."""
    other = copy.deepcopy(recorded.payload)
    other["info"]["instance_id"] = "a" * 40
    assert recorded.signing_address == att.Report(other, recorded.nonce).signing_address
    assert recorded.identity() != att.Report(other, recorded.nonce).identity()


def test_identity_changes_when_the_compose_log_does(recorded):
    other = copy.deepcopy(recorded.payload)
    other["compose_manager_attestation"]["actions_hash"] = "b" * 64
    assert recorded.identity() != att.Report(other, recorded.nonce).identity()


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
@pytest.mark.parametrize("name", ["nearai-glm", "nearai-gpt-oss"])
def test_live_pins_cover_the_whole_instance_pool(name):
    """One hostname is a pool. Verifying once proves only that we landed on a
    pinned instance, so this samples enough times to reach the others."""
    att.reset_for_test()
    seen, failures = set(), []
    for _ in range(12):
        try:
            report = att.fetch(provider(name))
        except Exception:
            continue
        seen.add(report.info.get("instance_id"))
        verdict = att.verify(provider(name))
        if not verdict.ok:
            failures.append(verdict.reason)
    assert seen, f"{name} returned no attestation report in 12 attempts"
    assert not failures, (
        f"{name} has unpinned instances in its pool across {len(seen)} seen: "
        f"{sorted(set(failures))}"
    )


@live
def test_live_endpoint_binds_a_nonce_we_choose():
    report = att.fetch(provider("nearai-glm"))
    assert report.echoed_our_nonce()
    quote = report.quote
    dcap = quote_policy.load_dcap()
    report_data = bytes(dcap.parse_quote(quote).report.report_data)
    assert report_data == report.expected_report_data()
