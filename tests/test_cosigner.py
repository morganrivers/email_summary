"""Track J: the split-custody co-signer.

What is pinned here is the property the second box exists for, not the happy
path. Every test below fails if one of the four invariants in
`cosigner/__init__.py` is broken by a plausible-looking change:

  * layer order -- `unwrap` returns what was wrapped and nothing more, so an
    `inner` that came in sealed goes out still sealed;
  * no plaintext here -- the audit log is searched for every byte that crossed
    the wire;
  * no bypass -- the kill switch, the rate limits, the aggregate ceiling and
    the distinct-account sweep limit each refuse, and refusals never consume
    budget;
  * no stored ciphertext -- the schema has nowhere to put one, and `/wrap`
    refuses a second time for a uid using the log rather than a saved record.

The last group covers retention, which is the one thing here that deletes: what
it may remove is bounded by what the limiters read, and the tests pin that a
prune cannot change an answer the co-signer would have given.

The server is driven over a real socket so routing, status codes and the
client-certificate header are exercised as deployed, with Caddy's role played
by setting the header directly.
"""

import json
import time

import harness
import pytest
import requests

from backend.tee import quote_policy
from cosigner import attest, audit, policy, protocol, retention

# What the co-signer is given to call an account by: an opaque handle the
# enclave minted, never an address. This service does not parse it -- which is
# exactly why it was able to be an address for so long without anything failing.
UID = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
SEALED = b"\x01" * 12 + b"pretend this is AES-GCM output from the enclave"


@pytest.fixture
def cosigner(tmp_path, monkeypatch):
    """A running co-signer with fresh keys, a fresh log, and attestation off.

    The process itself comes from `harness.running_cosigner`, which the
    integration test in `test_custody_integration.py` also drives; what is local
    here is only the request builder that plays Caddy's part."""
    with harness.running_cosigner(tmp_path, monkeypatch) as proc:
        base = proc.base

        class Client:
            alerts = proc.alerts

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

            def unwrap_data(self, uid=UID, outer=None):
                return self.post(protocol.UNWRAP_PATH, uid=uid,
                                 outer=protocol.b64(outer))

            def rewrap(self, uid=UID, outer=None):
                return self.post(protocol.REWRAP_PATH, uid=uid,
                                 outer=protocol.b64(outer))

            def sign(self, htm="POST", htu=protocol.TOKEN_ENDPOINT, nonce=None, uid=None):
                return self.post(protocol.SIGN_DPOP_PATH, htm=htm, htu=htu, nonce=nonce,
                                 uid=uid)

        yield Client()


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
    resp = cosigner.unwrap(uid="f" * 32, outer=outer)
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


def test_the_wrap_once_check_is_decided_under_the_lock(tmp_path, monkeypatch):
    """Read the log, then write to it, with nothing in between: two wraps for
    one uid arriving together must not both read "not yet wrapped". Driven
    through `policy.authorize` rather than the running service because what is
    being asserted is where the decision happens, not what it answers."""
    audit.reset_for_test(tmp_path)
    holder = {}
    real = audit.ever_granted

    def spy(uid, action):
        holder["locked"] = policy._LOCK.locked()
        return real(uid, action)

    monkeypatch.setattr(policy.audit, "ever_granted", spy)
    allowed = attest.Verdict(True, "fp", attested=True)
    assert policy.authorize(UID, policy.ACTION_WRAP, allowed) is None
    assert holder["locked"], (
        "the wrap-once check ran outside policy._LOCK, so two concurrent wraps "
        "can both be granted"
    )
    second = policy.authorize(UID, policy.ACTION_WRAP, allowed)
    assert second is not None and "already wrapped" in second.reason
    audit.reset_for_test()


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


def test_a_sweep_across_accounts_is_refused(cosigner, monkeypatch):
    """The pattern every per-account rule reads as normal: one unwrap each,
    across the whole user base. Nobody exceeds their own ceiling, so breadth is
    the only thing that sees it."""
    monkeypatch.setenv("COSIGNER_RATE_DISTINCT_UIDS", "2")
    uids = ["a" * 32, "b" * 32, "c" * 32]
    outers = {uid: _outer(cosigner, uid=uid) for uid in uids}
    assert cosigner.unwrap(uid=uids[0], outer=outers[uids[0]]).status_code == 200
    assert cosigner.unwrap(uid=uids[1], outer=outers[uids[1]]).status_code == 200

    resp = cosigner.unwrap(uid=uids[2], outer=outers[uids[2]])
    assert resp.status_code == 429
    assert policy.SWEEP_REASON in resp.json()[protocol.F_ERROR]
    assert audit.recent(1)[0]["uid"] == uids[2], "the refused account is named in the log"


def test_the_sweep_limit_does_not_refuse_an_account_already_counted(cosigner, monkeypatch):
    """An account already inside the window has contributed its uid to the count
    already, so refusing it narrows no breach and only stops that user's mail."""
    monkeypatch.setenv("COSIGNER_RATE_DISTINCT_UIDS", "1")
    mine = _outer(cosigner, uid="a" * 32)
    theirs = _outer(cosigner, uid="b" * 32)
    assert cosigner.unwrap(uid="a" * 32, outer=mine).status_code == 200
    assert cosigner.unwrap(uid="b" * 32, outer=theirs).status_code == 429
    assert cosigner.unwrap(uid="a" * 32, outer=mine).status_code == 200


def test_a_sweep_alerts_once_rather_than_once_per_account(cosigner, monkeypatch):
    """A hundred identical alerts is how an operator learns to mute the channel,
    and a sweep produces one refusal per account it reaches for."""
    monkeypatch.setenv("COSIGNER_RATE_DISTINCT_UIDS", "1")
    outers = {uid: _outer(cosigner, uid=uid)
              for uid in ("a" * 32, "b" * 32, "c" * 32)}
    for uid, outer in outers.items():
        cosigner.unwrap(uid=uid, outer=outer)

    swept = [text for text in cosigner.alerts if policy.SWEEP_REASON in text]
    assert len(swept) == 1, cosigner.alerts


def test_aggregate_ceiling_bounds_a_live_breach(cosigner, monkeypatch):
    """The number that decides how long draining the user base takes."""
    monkeypatch.setenv("COSIGNER_RATE_PER_USER_HOUR", "100")
    monkeypatch.setenv("COSIGNER_RATE_TOTAL_HOUR", "2")
    first = _outer(cosigner, uid="a" * 32)
    second = _outer(cosigner, uid="b" * 32)
    third = _outer(cosigner, uid="c" * 32)
    assert cosigner.unwrap(uid="a" * 32, outer=first).status_code == 200
    assert cosigner.unwrap(uid="b" * 32, outer=second).status_code == 200
    resp = cosigner.unwrap(uid="c" * 32, outer=third)
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
    grants = {row[1] for row in audit.connect().execute("PRAGMA table_info(grants)")}
    assert grants == {"uid", "action", "first_granted_ts"}


def test_attestation_required_refuses_a_connection_without_a_certificate(
        cosigner, monkeypatch):
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
    with pytest.raises(quote_policy.AllowlistInvalid, match="provisioned for production"):
        attest.mode()

    config.write_text(json.dumps({"mode": attest.DEV_INSECURE, "measurements": []}))
    attest.reset_for_test(config)
    monkeypatch.setenv("TEE_REQUIRED", "1")
    with pytest.raises(attest.AttestationRefused, match="TEE_REQUIRED"):
        attest.mode()


def test_allowlist_entry_must_pin_a_measurement(tmp_path, monkeypatch):
    """An entry that pins nothing authorizes every image."""
    config = tmp_path / "allowlist.json"
    config.write_text(json.dumps({
        "mode": attest.REQUIRED,
        "measurements": [{"name": "sloppy", "mr_td": None}],
    }))
    attest.reset_for_test(config)
    with pytest.raises(quote_policy.AllowlistInvalid, match="does not pin mr_td"):
        attest.match_allowlist({"mr_td": "aa"})


def test_health_reports_without_leaking(cosigner):
    body = cosigner.get(protocol.HEALTH_PATH).json()
    assert body == {"status": "ok", "attestation": attest.DEV_INSECURE,
                    "keys": "ok", "disabled": None}


def test_unknown_endpoint_and_oversized_body(cosigner):
    assert cosigner.post("/anything").status_code == 404
    assert cosigner.get("/anything").status_code == 404
    assert cosigner.wrap(inner=b"x" * protocol.MAX_BODY).status_code == 413


# --- the second unwrap, and the sweep rule that spans both ----------------

def test_reading_documents_releases_the_key_without_a_proof(cosigner):
    """`/unwrap` exists so rendering a settings page does not mint a DPoP proof
    nobody asked for. Same ciphertext out, no capability attached."""
    outer = _outer(cosigner)
    resp = cosigner.unwrap_data(outer=outer)
    assert resp.status_code == 200, resp.text
    assert protocol.unb64(resp.json()[protocol.F_INNER]) == SEALED
    assert protocol.F_PROOF not in resp.json(), (
        "a proof was minted for a request that did not need one"
    )
    assert audit.recent(1)[0]["action"] == policy.ACTION_UNWRAP_DATA, (
        "a document read was logged as a mail refresh"
    )


def test_a_sweep_cannot_be_halved_across_the_two_unwrap_paths(cosigner, monkeypatch):
    """Two ways to obtain an account's key, so the breadth rule counts them as
    one. Metered separately, an attacker takes half their accounts down each
    path and stays under both ceilings while touching twice as many people."""
    monkeypatch.setenv("COSIGNER_RATE_DISTINCT_UIDS", "2")
    uids = ["a" * 32, "b" * 32, "c" * 32]
    outers = {uid: _outer(cosigner, uid=uid) for uid in uids}

    assert cosigner.unwrap(uid=uids[0], outer=outers[uids[0]]).status_code == 200
    assert cosigner.unwrap_data(uid=uids[1], outer=outers[uids[1]]).status_code == 200

    for third in (cosigner.unwrap(uid=uids[2], outer=outers[uids[2]]),
                  cosigner.unwrap_data(uid=uids[2], outer=outers[uids[2]])):
        assert third.status_code == 429
        assert policy.SWEEP_REASON in third.json()[protocol.F_ERROR]


# --- rotating the outer key -----------------------------------------------

def test_rewrap_moves_a_record_and_keeps_what_it_holds(cosigner):
    """The rotation primitive. What goes in opens to the enclave's sealed blob
    and what comes back still does; the record itself is a different value,
    because it is under a different key."""
    outer = _outer(cosigner)
    resp = cosigner.rewrap(outer=outer)
    assert resp.status_code == 200, resp.text
    fresh = protocol.unb64(resp.json()[protocol.F_OUTER])
    assert fresh != outer
    assert SEALED not in fresh

    reread = cosigner.unwrap(outer=fresh)
    assert reread.status_code == 200, reread.text
    assert protocol.unb64(reread.json()[protocol.F_INNER]) == SEALED


def test_rewrap_cannot_introduce_a_record_for_an_account_that_had_none(cosigner):
    """Why `/rewrap` needs no wrap-once rule of its own: it takes an `outer`
    rather than an `inner`, and the only way to hold one that opens is to have
    been given it. An attacker who can call this endpoint can move ciphertext
    they already had onto a new key, and nothing else."""
    resp = cosigner.rewrap(uid="e" * 32, outer=SEALED)
    assert resp.status_code == 400
    assert "did not open" in resp.json()[protocol.F_ERROR]


def test_rewrap_is_metered_and_logged_like_everything_else(cosigner, monkeypatch):
    monkeypatch.setenv("COSIGNER_RATE_REWRAP_HOUR", "1")
    outer = _outer(cosigner)
    assert cosigner.rewrap(outer=outer).status_code == 200
    refused = cosigner.rewrap(outer=outer)
    assert refused.status_code == 429
    assert "rewrap ceiling" in refused.json()[protocol.F_ERROR]
    assert audit.recent(1)[0]["action"] == policy.ACTION_REWRAP


def test_rewrap_spends_no_unwrap_budget(cosigner, monkeypatch):
    """A rotation touches every account by design, which is the exact shape the
    sweep rule calls an incident. It must not trip that rule, and it must not
    eat the budget mail processing needs."""
    monkeypatch.setenv("COSIGNER_RATE_PER_USER_HOUR", "1")
    monkeypatch.setenv("COSIGNER_RATE_DISTINCT_UIDS", "1")
    outer = _outer(cosigner)
    for _ in range(5):
        outer = protocol.unb64(
            cosigner.rewrap(outer=outer).json()[protocol.F_OUTER])
    assert cosigner.unwrap(outer=outer).status_code == 200


def test_a_record_survives_the_key_version_it_was_written_under(cosigner, monkeypatch):
    """The asymmetry that made the rotation comment a lie: the inner layer could
    read an old version and the outer could not, so bumping `KEY_VERSION` made
    every stored record unopenable and no re-wrap routine existed to move them.
    Now the version travels with the record, an old one still opens, and
    `/rewrap` is what moves it."""
    from cosigner import keys

    outer_v1 = _outer(cosigner)
    assert outer_v1[0] == 1

    keys.write_dev_credentials(keys.credentials_dir(), version=2)
    monkeypatch.setattr(keys, "KEY_VERSION", 2)
    keys._CACHE.clear()
    assert keys.known_versions() == (2, 1)

    reread = cosigner.unwrap(outer=outer_v1)
    assert reread.status_code == 200, reread.text
    assert protocol.unb64(reread.json()[protocol.F_INNER]) == SEALED

    outer_v2 = protocol.unb64(
        cosigner.rewrap(outer=outer_v1).json()[protocol.F_OUTER])
    assert outer_v2[0] == 2
    assert protocol.unb64(
        cosigner.unwrap(outer=outer_v2).json()[protocol.F_INNER]) == SEALED


def test_a_retired_key_version_fails_closed(cosigner, monkeypatch):
    """Deleting the old credential is the last step of a rotation, and it has to
    be a hard stop for anything still on that version rather than a silent
    fallback to whichever key happens to be loadable."""
    from cosigner import keys

    outer_v1 = _outer(cosigner)
    keys.write_dev_credentials(keys.credentials_dir(), version=2)
    monkeypatch.setattr(keys, "KEY_VERSION", 2)
    (keys.credentials_dir() / keys.master_name(1)).unlink()
    keys._CACHE.clear()

    assert keys.known_versions() == (2,)
    assert cosigner.unwrap(outer=outer_v1).status_code == 400


# --- retention ------------------------------------------------------------

@pytest.fixture
def log(tmp_path, monkeypatch):
    """The audit log alone, no server: retention is about what the rows mean,
    not about the wire."""
    monkeypatch.setenv("COSIGNER_STATE_DIR", str(tmp_path))
    audit.reset_for_test()
    yield audit
    audit.reset_for_test()


def _aged(uid, action, decision, days_ago):
    audit.record(uid, action, decision, reason="aged" if decision == audit.DENY else None,
                 ts=time.time() - days_ago * retention.DAY)


def test_wrap_once_survives_a_prune(log):
    """The landmine the split exists for: prune the wrap row and the uid becomes
    eligible for a second wrap, which is exactly what `/wrap` refuses."""
    _aged(UID, policy.ACTION_WRAP, audit.ALLOW, days_ago=400)
    assert audit.ever_granted(UID, policy.ACTION_WRAP)

    allowed, _ = retention.prune()
    assert allowed == 1
    assert audit.ever_granted(UID, policy.ACTION_WRAP), (
        "pruning the log re-opened a wrapped uid for a second wrap"
    )


def test_prune_keeps_denials_far_longer_than_grants(log):
    """Nothing enforcement-side reads a denial, and it is the best evidence in
    the table."""
    _aged(UID, policy.ACTION_UNWRAP, audit.ALLOW, days_ago=60)
    _aged(UID, policy.ACTION_UNWRAP, audit.DENY, days_ago=60)
    allowed, denied = retention.prune()
    assert (allowed, denied) == (1, 0)

    reasons = {row["decision"] for row in audit.recent()}
    assert reasons == {audit.DENY}


def test_prune_leaves_no_readable_row_behind(log):
    """A deleted row still sitting in the file's free list is a row that was not
    deleted, which for this table means an activity timeline outliving the
    period it was kept for."""
    _aged("d" * 32, policy.ACTION_UNWRAP, audit.DENY, days_ago=400)
    assert (b"d" * 32) in audit.db_path().read_bytes()

    assert retention.prune() == (0, 1)
    assert audit.connect().execute("PRAGMA freelist_count").fetchone()[0] == 0
    assert (b"d" * 32) not in audit.db_path().read_bytes()


@harness.needs_asserts
def test_prune_never_touches_a_row_a_limiter_still_counts(log, monkeypatch):
    """The floor is derived from the windows rather than restated, so a limiter
    with a longer window than the retention period refuses to prune at all.

    Both sides of that comparison are constants in this repository, so it is an
    invariant about our own configuration rather than a check on an input, and
    it stays an assert."""
    since = time.time() - policy.longest_window()
    audit.record(UID, policy.ACTION_UNWRAP, audit.ALLOW)
    assert retention.prune() == (0, 0)
    assert audit.granted_since(since, action=policy.ACTION_UNWRAP, uid=UID) == 1

    monkeypatch.setattr(policy, "WINDOW_SECONDS", retention.ALLOW_RETENTION_SECONDS)
    with pytest.raises(AssertionError, match="rate limiter still counts"):
        retention.prune()


def test_the_backfill_recovers_wrap_state_from_an_older_log(log):
    """A box whose audit.db predates the grants table has its wrap grants only
    as log rows; an empty grants table would say every user may wrap again."""
    audit.record(UID, policy.ACTION_WRAP, audit.ALLOW)
    with audit.transaction() as conn:
        conn.execute("DROP TABLE grants")
    audit.reset_for_test()
    assert audit.ever_granted(UID, policy.ACTION_WRAP)
