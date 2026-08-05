"""Track J: the split-custody co-signer.

What is pinned here is the property the second box exists for, not the happy
path. Every test below fails if one of the four invariants in
`cosigner/__init__.py` is broken by a plausible-looking change:

  * layer order -- `unwrap` returns what was wrapped and nothing more, so an
    `inner` that came in sealed goes out still sealed;
  * no plaintext here -- the audit log is searched for every byte that crossed
    the wire;
  * no bypass -- the kill switch, the rate limits and the aggregate ceiling
    each refuse, and refusals never consume budget;
  * no stored ciphertext -- the schema has nowhere to put one, and `/wrap`
    refuses a second time for a uid using the log rather than a saved record.

The server is driven over a real socket so routing, status codes and the
client-certificate header are exercised as deployed, with Caddy's role played
by setting the header directly.
"""

import json
import threading
from http.server import ThreadingHTTPServer

import pytest
import requests

from cosigner import attest
from cosigner import audit
from cosigner import keys
from cosigner import policy
from cosigner import protocol
from cosigner import server

UID = "alice@example.com"
SEALED = b"\x01" * 12 + b"pretend this is AES-GCM output from the enclave"


@pytest.fixture
def cosigner(tmp_path, monkeypatch):
    """A running co-signer with fresh keys, a fresh log, and attestation off."""
    monkeypatch.setenv("COSIGNER_ATTESTATION", attest.DEV_INSECURE)
    monkeypatch.delenv("TEE_REQUIRED", raising=False)
    monkeypatch.delenv("COSIGNER_DISABLED", raising=False)
    monkeypatch.setenv("COSIGNER_STATE_DIR", str(tmp_path / "state"))
    keys.reset_for_test(keys.write_dev_credentials(tmp_path / "creds"))
    audit.reset_for_test(tmp_path / "state")
    attest.reset_for_test()
    monkeypatch.setattr(policy, "_LAST_ALERT", {})
    sent = []
    monkeypatch.setattr(policy.alerts, "notify_operator", lambda text: sent.append(text))

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    class Client:
        alerts = sent

        def post(self, path, **body):
            return requests.post(base + path, json=body, timeout=10)

        def get(self, path):
            return requests.get(base + path, timeout=10)

        def wrap(self, uid=UID, inner=SEALED):
            return self.post(protocol.WRAP_PATH, uid=uid, inner=protocol.b64(inner))

        def unwrap(self, uid=UID, outer=None, htm="POST", htu=protocol.TOKEN_ENDPOINT,
                   nonce=None):
            return self.post(protocol.UNWRAP_AND_SIGN_PATH, uid=uid,
                             outer=protocol.b64(outer), htm=htm, htu=htu, nonce=nonce)

        def sign(self, htm="POST", htu=protocol.TOKEN_ENDPOINT, nonce=None, uid=None):
            return self.post(protocol.SIGN_DPOP_PATH, htm=htm, htu=htu, nonce=nonce,
                             uid=uid)

    yield Client()
    httpd.shutdown()
    audit.reset_for_test()


def _outer(client, uid=UID, inner=SEALED):
    resp = client.wrap(uid=uid, inner=inner)
    assert resp.status_code == 200, resp.text
    return protocol.unb64(resp.json()[protocol.F_OUTER])


def test_wrap_then_unwrap_returns_the_ciphertext_unchanged(cosigner):
    """The round trip is the whole service. What comes back out is the enclave's
    sealed blob, byte for byte -- not something this box could read."""
    outer = _outer(cosigner)
    assert SEALED not in outer

    resp = cosigner.unwrap(outer=outer)
    assert resp.status_code == 200, resp.text
    assert protocol.unb64(resp.json()[protocol.F_INNER]) == SEALED


def test_outer_is_bound_to_the_uid(cosigner):
    """The uid is the AAD, so one user's record cannot be replayed under
    another's id to spend their budget or muddy their audit line."""
    outer = _outer(cosigner)
    resp = cosigner.unwrap(uid="mallory@example.com", outer=outer)
    assert resp.status_code == 400
    assert "did not open" in resp.json()[protocol.F_ERROR]


def test_tampered_outer_is_refused_without_detail(cosigner):
    outer = bytearray(_outer(cosigner))
    outer[-1] ^= 0xFF
    resp = cosigner.unwrap(outer=bytes(outer))
    assert resp.status_code == 400
    assert protocol.b64(bytes(outer)) not in resp.text


def test_second_wrap_for_a_uid_is_refused(cosigner):
    """Idempotency by refusal, decided from the log: a second wrap is either a
    bug or an attacker asking us to re-wrap something."""
    _outer(cosigner)
    resp = cosigner.wrap()
    assert resp.status_code == 403
    assert "already wrapped" in resp.json()[protocol.F_ERROR]


def test_proof_covers_the_request_and_carries_no_token_material(cosigner):
    outer = _outer(cosigner)
    resp = cosigner.unwrap(outer=outer, nonce="nonce-from-google")
    proof = resp.json()[protocol.F_PROOF]

    header, payload, _ = proof.split(".")
    claims = json.loads(protocol.unb64(payload + "=" * (-len(payload) % 4)))
    assert claims["htm"] == "POST"
    assert claims["htu"] == protocol.TOKEN_ENDPOINT
    assert claims["nonce"] == "nonce-from-google"
    assert set(claims) == {"jti", "htm", "htu", "iat", "nonce"}

    published = cosigner.get(protocol.DPOP_JWK_PATH).json()
    assert json.loads(protocol.unb64(header + "=" * (-len(header) % 4)))["jwk"] == \
        published[protocol.F_JWK]


def test_published_jwk_carries_no_private_key(cosigner):
    """The enclave needs this to compute `dpop_jkt` at the code exchange, so it
    is served to anything Caddy lets through. `d` is the signing key itself."""
    published = cosigner.get(protocol.DPOP_JWK_PATH).json()
    assert "d" not in published[protocol.F_JWK]
    assert published[protocol.F_JKT]


def test_sign_dpop_needs_no_uid(cosigner):
    """At the code exchange the mailbox is unknown until Google answers, so a
    proof has to be obtainable before any uid exists."""
    resp = cosigner.sign(nonce="nonce-from-google")
    assert resp.status_code == 200, resp.text

    payload = resp.json()[protocol.F_PROOF].split(".")[1]
    claims = json.loads(protocol.unb64(payload + "=" * (-len(payload) % 4)))
    assert claims["htu"] == protocol.TOKEN_ENDPOINT
    assert claims["nonce"] == "nonce-from-google"

    row = audit.recent(1)[0]
    assert (row["action"], row["decision"], row["uid"]) == (
        policy.ACTION_SIGN, audit.ALLOW, "")


def test_sign_dpop_target_is_fixed(cosigner):
    assert cosigner.sign(htu="https://evil.example/token").status_code == 403
    assert cosigner.sign(htm="GET").status_code == 403


def test_sign_dpop_has_its_own_ceiling(cosigner, monkeypatch):
    """It carries no uid, so the per-user limit cannot reach it. Without a
    ceiling of its own it is the unmetered path around the metered one."""
    monkeypatch.setenv("COSIGNER_RATE_SIGN_HOUR", "2")
    assert cosigner.sign().status_code == 200
    assert cosigner.sign().status_code == 200
    resp = cosigner.sign()
    assert resp.status_code == 429
    assert "sign ceiling" in resp.json()[protocol.F_ERROR]


def test_sign_dpop_and_unwrap_budgets_are_separate(cosigner, monkeypatch):
    """A signing spree must not lock every mailbox out of its refresh, and an
    exhausted sign ceiling must not be spendable by unwrapping instead."""
    monkeypatch.setenv("COSIGNER_RATE_SIGN_HOUR", "1")
    monkeypatch.setenv("COSIGNER_RATE_TOTAL_HOUR", "1")
    outer = _outer(cosigner)
    assert cosigner.sign().status_code == 200
    assert cosigner.sign().status_code == 429
    assert cosigner.unwrap(outer=outer).status_code == 200
    assert cosigner.unwrap(outer=outer).status_code == 429


def test_proof_target_is_fixed(cosigner):
    """Without this the co-signer is a signing oracle for any URL an
    enclave-side attacker names."""
    outer = _outer(cosigner)
    resp = cosigner.unwrap(outer=outer, htu="https://evil.example/token")
    assert resp.status_code == 403
    assert "refusing to sign" in resp.json()[protocol.F_ERROR]

    resp = cosigner.unwrap(outer=outer, htm="GET")
    assert resp.status_code == 403


def test_per_user_rate_limit(cosigner, monkeypatch):
    monkeypatch.setenv("COSIGNER_RATE_PER_USER_HOUR", "2")
    outer = _outer(cosigner)
    assert cosigner.unwrap(outer=outer).status_code == 200
    assert cosigner.unwrap(outer=outer).status_code == 200
    resp = cosigner.unwrap(outer=outer)
    assert resp.status_code == 429
    assert "per-user rate limit" in resp.json()[protocol.F_ERROR]


def test_aggregate_ceiling_bounds_a_live_breach(cosigner, monkeypatch):
    """The number that decides how long draining the user base takes."""
    monkeypatch.setenv("COSIGNER_RATE_PER_USER_HOUR", "100")
    monkeypatch.setenv("COSIGNER_RATE_TOTAL_HOUR", "2")
    first = _outer(cosigner, uid="a@example.com")
    second = _outer(cosigner, uid="b@example.com")
    third = _outer(cosigner, uid="c@example.com")
    assert cosigner.unwrap(uid="a@example.com", outer=first).status_code == 200
    assert cosigner.unwrap(uid="b@example.com", outer=second).status_code == 200
    resp = cosigner.unwrap(uid="c@example.com", outer=third)
    assert resp.status_code == 429
    assert "aggregate ceiling" in resp.json()[protocol.F_ERROR]


def test_refusal_does_not_consume_budget(cosigner, monkeypatch):
    """A denied request must not count against the limit it was denied by, or a
    single misconfigured caller locks a user out for an hour."""
    monkeypatch.setenv("COSIGNER_RATE_PER_USER_HOUR", "2")
    outer = _outer(cosigner)
    for _ in range(5):
        assert cosigner.unwrap(outer=outer, htu="https://evil.example/token").status_code == 403
    assert cosigner.unwrap(outer=outer).status_code == 200


def test_kill_switch_refuses_everything(cosigner):
    outer = _outer(cosigner)
    policy.kill_switch_path().parent.mkdir(parents=True, exist_ok=True)
    policy.kill_switch_path().write_text("suspected breach\n")
    resp = cosigner.unwrap(outer=outer)
    assert resp.status_code == 503
    assert "kill switch" in resp.json()[protocol.F_ERROR]

    policy.kill_switch_path().unlink()
    assert cosigner.unwrap(outer=outer).status_code == 200


def test_refusals_reach_the_operator(cosigner):
    outer = _outer(cosigner)
    cosigner.unwrap(outer=outer, htu="https://evil.example/token")
    assert cosigner.alerts, "a refusal is either a bug or a breach; both want a human"


def test_audit_records_every_decision_and_no_ciphertext(cosigner):
    outer = _outer(cosigner)
    cosigner.unwrap(outer=outer)
    cosigner.unwrap(outer=outer, htu="https://evil.example/token")

    rows = audit.recent()
    assert [(r["action"], r["decision"]) for r in rows] == [
        (policy.ACTION_UNWRAP, audit.DENY),
        (policy.ACTION_UNWRAP, audit.ALLOW),
        (policy.ACTION_WRAP, audit.ALLOW),
    ]
    assert all(r["attested"] == 0 for r in rows), "dev runs must be marked unattested"

    blob = json.dumps(rows)
    for secret in (protocol.b64(SEALED), protocol.b64(outer), SEALED.hex(), outer.hex()):
        assert secret not in blob


def test_audit_schema_cannot_hold_a_ciphertext(cosigner):
    columns = {row[1] for row in audit.connect().execute("PRAGMA table_info(requests)")}
    assert columns == {"id", "ts", "uid", "action", "decision", "reason",
                       "fingerprint", "measurement", "attested"}


def test_attestation_required_refuses_a_connection_without_a_certificate(cosigner,
                                                                        monkeypatch):
    """Caddy is configured to demand a client certificate, so its absence means
    the proxy was bypassed. Fail closed."""
    outer = _outer(cosigner)
    monkeypatch.setenv("COSIGNER_ATTESTATION", attest.REQUIRED)
    attest.reset_for_test()
    resp = cosigner.unwrap(outer=outer)
    assert resp.status_code == 403
    assert "no client certificate" in resp.json()[protocol.F_ERROR]
    assert audit.recent(1)[0]["reason"] == "no client certificate presented"


def test_dev_mode_refuses_to_run_on_a_provisioned_box(tmp_path, monkeypatch):
    """The stub is only ever allowed to be off in dev, and this is what makes
    that an assertion rather than an intention."""
    config = tmp_path / "allowlist.json"
    config.write_text(json.dumps({
        "mode": attest.DEV_INSECURE,
        "measurements": [{"name": "prod", "mr_td": "aa" * 48}],
    }))
    monkeypatch.delenv("COSIGNER_ATTESTATION", raising=False)
    attest.reset_for_test(config)
    with pytest.raises(AssertionError, match="provisioned for production"):
        attest.mode()

    config.write_text(json.dumps({"mode": attest.DEV_INSECURE, "measurements": []}))
    attest.reset_for_test(config)
    monkeypatch.setenv("TEE_REQUIRED", "1")
    with pytest.raises(AssertionError, match="TEE_REQUIRED"):
        attest.mode()


def test_allowlist_entry_must_pin_a_measurement(tmp_path, monkeypatch):
    """An entry that pins nothing authorizes every image."""
    config = tmp_path / "allowlist.json"
    config.write_text(json.dumps({
        "mode": attest.REQUIRED,
        "measurements": [{"name": "sloppy", "mr_td": None}],
    }))
    attest.reset_for_test(config)
    with pytest.raises(AssertionError, match="does not pin mr_td"):
        attest.match_allowlist({"mr_td": "aa"})


def test_health_reports_without_leaking(cosigner):
    body = cosigner.get(protocol.HEALTH_PATH).json()
    assert body == {"status": "ok", "attestation": attest.DEV_INSECURE,
                    "keys": "ok", "disabled": None}


def test_unknown_endpoint_and_oversized_body(cosigner):
    assert cosigner.post("/anything").status_code == 404
    assert cosigner.get("/anything").status_code == 404
    assert cosigner.wrap(inner=b"x" * protocol.MAX_BODY).status_code == 413
