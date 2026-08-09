"""Both halves of custody, talking to each other over a socket.

`test_custody.py` proves the enclave's four invariants against a fake co-signer
and `test_cosigner.py` proves the co-signer's against a hand-built client.
Neither can catch the failure this design has already produced once: both suites
passed while the two halves disagreed about how bytes are spelled, because each
faked the other above the wire (docs/plan_token_custody.md §J8).

So here nothing between the two is faked. `backend.custody` runs against
`cosigner.server` on a loopback port, with real AES-GCM at both layers, a real
ES256 DPoP proof, and the real audit log. The only stub is Google's token
endpoint, which is the one party that cannot be run locally.

What that buys is the property the whole design rests on, checked end to end:
the token that goes in at onboarding comes back out of a refresh, and it comes
back only because both boxes acted.
"""

import base64
import json
from urllib.parse import parse_qs, urlparse

import harness
import pytest

from backend.accounts import account
from backend.custody import client as cosigner
from backend.custody import keyring, tokens, wrapping
from backend.integrations.gmail_gcal import gmail_api, oauth_app
from backend.onboarding import provisioning
from cosigner import audit
from cosigner import keys as cosigner_keys
from cosigner import policy, protocol

REFRESH_TOKEN = "1//0gSuperSecretRefreshTokenValue"
UID = "alice@example.com"
HANDLE = "a1b2c3d4e5f60718293a4b5c6d7e8f90"


ACCESS_TOKEN = "ya29.integration"


def acct(uid=UID, handle=HANDLE):
    """An account as custody sees one: the id names its directory on this box,
    the handle is the only thing the co-signer ever learns."""
    return type("A", (), {"id": uid, "handle": handle, "telegram": None})()


class FakeGoogle:
    """The token endpoint, and only that. Records the form and the DPoP header
    of every POST so the proof can be checked as it would arrive at Google."""

    def __init__(self):
        self.calls = []
        self.demand_nonce = None
        self.payload = {"access_token": ACCESS_TOKEN, "expires_in": 3600}

    def issues_a_refresh_token(self):
        """What the authorization-code exchange gets back, as opposed to a
        refresh grant: the refresh token itself, the identity claims, and the
        scopes the user actually granted, which provisioning refuses without."""
        self.payload = dict(self.payload, refresh_token=REFRESH_TOKEN,
                            id_token=id_token("Alice", "Anderson"),
                            scope=oauth_app.scope_param())
        return self

    def post(self, url, data=None, headers=None, timeout=None):
        assert url == oauth_app.TOKEN_ENDPOINT, f"posted to {url}"
        proof = (headers or {}).get("DPoP")
        assert proof, "the enclave posted a token request with no DPoP proof"
        self.calls.append({"form": dict(data or {}), "proof": proof})
        if self.demand_nonce and len(self.calls) == 1:
            return FakeResponse(400, {"error": "use_dpop_nonce"},
                                {"DPoP-Nonce": self.demand_nonce})
        return FakeResponse(200, self.payload)


class FakeResponse:
    def __init__(self, status, payload, headers=None):
        self.status_code = status
        self._payload = payload
        self.headers = headers or {}
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


def id_token(first, last):
    """An unsigned id_token, which is what provisioning reads: it arrives inside
    a TLS response to a code only this box holds, so the signature adds nothing
    there and nothing here."""
    body = base64.urlsafe_b64encode(
        json.dumps({"given_name": first, "family_name": last}).encode()
    ).decode().rstrip("=")
    return f"header.{body}.signature"


def claims_of(proof):
    """The payload of a DPoP JWT, without verifying the signature -- that the
    co-signer can sign is not in question here, only what it signed."""
    payload = proof.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


@pytest.fixture
def split_custody(tmp_path, monkeypatch):
    """An enclave and a co-signer, each real, wired to each other and to nothing
    else. Google is the only fake."""
    with harness.running_cosigner(tmp_path / "cosigner", monkeypatch) as proc:
        monkeypatch.setenv("LETTERLOCK_COSIGNER_URL", proc.base)
        monkeypatch.setenv(wrapping.DEV_SECRET_ENV, "dev-secret-for-tests-0123456789")
        monkeypatch.setattr(wrapping, "_app_secret_cache", None)
        monkeypatch.setattr(account, "ACCOUNTS_DIR", tmp_path / "database")
        monkeypatch.setattr(account, "MANIFEST",
                            tmp_path / "database" / "accounts.json")
        keys = tmp_path / "gcp-oauth.keys.json"
        keys.write_text(json.dumps({"web": {
            "client_id": "test-client-id", "client_secret": "test-client-secret"}}))
        monkeypatch.setenv(oauth_app.KEYS_ENV, str(keys))

        google = FakeGoogle()
        monkeypatch.setattr(tokens.requests, "post", google.post)
        monkeypatch.setattr(tokens, "_dpop_nonce", None)
        tokens.forget()
        cosigner.reset_cache()
        yield google
        tokens.forget()
        cosigner.reset_cache()
        monkeypatch.setattr(wrapping, "_app_secret_cache", None)


def test_a_token_survives_the_whole_round_trip(split_custody):
    """Onboarding to refresh, with a real socket in the middle. This is the test
    that would have failed on the codec disagreement that both halves' own
    suites passed."""
    tokens.take_custody(acct(), REFRESH_TOKEN)
    account_under_test = acct()

    assert tokens.access_token_for(account_under_test) == ACCESS_TOKEN
    assert split_custody.calls[0]["form"]["refresh_token"] == REFRESH_TOKEN
    assert split_custody.calls[0]["form"]["grant_type"] == "refresh_token"


def test_neither_box_holds_enough_alone(split_custody):
    """The stored record is openable by neither half on its own: the enclave's
    key does not fit the outer layer, and the co-signer's unwrap yields
    ciphertext. Invariant 1, checked against the real outer key rather than a
    fake one.

    What the co-signer's unwrap yields is a *data key*, and a data key without
    the account's files is worth nothing. That is the envelope: the layer order
    reads the same way after Track G, over a smaller and more valuable
    object."""
    token_path = tokens.take_custody(acct(), REFRESH_TOKEN)
    _, outer = keyring.decode_record(keyring.dek_path(UID).read_bytes())
    assert REFRESH_TOKEN.encode() not in outer

    with pytest.raises(wrapping.CustodyError):
        wrapping.open_dek(HANDLE, outer)

    inner = cosigner_keys.unwrap(HANDLE, outer)
    assert REFRESH_TOKEN.encode() not in inner, (
        "the co-signer's own unwrap produced a readable token; the layer order "
        "is inverted and that box can now read every mailbox"
    )
    dek = wrapping.open_dek(HANDLE, inner)
    assert len(dek) == wrapping.KEY_LEN
    stored = keyring.decrypt(dek, HANDLE, tokens.TOKEN_FILE, token_path.read_bytes())
    assert stored.decode() == REFRESH_TOKEN


def test_the_proof_google_receives_was_signed_by_the_cosigner(split_custody):
    """The enclave never holds the DPoP key, so the header it sends has to have
    come back over the wire. Its claims are checked as Google would see them."""
    tokens.take_custody(acct(), REFRESH_TOKEN)
    tokens.access_token_for(acct())

    claims = claims_of(split_custody.calls[0]["proof"])
    assert claims["htm"] == "POST"
    assert claims["htu"] == oauth_app.TOKEN_ENDPOINT
    assert claims["jti"] and claims["iat"]
    assert REFRESH_TOKEN not in json.dumps(claims), "a proof carried token material"


def test_the_thumbprint_the_enclave_sends_google_is_the_key_that_signs(split_custody):
    """`dpop_jkt` goes to Google at the code exchange and is what binds the
    refresh token. The enclave computes it from the published JWK rather than
    reading a stated field, so this equality is two independent derivations of
    the same key agreeing."""
    assert cosigner.dpop_jkt() == cosigner_keys.dpop_jkt()


def test_the_nonce_retry_costs_a_second_proof_and_no_second_unwrap(split_custody):
    """Google's first answer is `use_dpop_nonce`. The retry proof comes from
    `/sign-dpop`, which is why that endpoint exists and why it is metered
    separately: paying for a second unwrap here would double every refresh
    against the per-user limit."""
    split_custody.demand_nonce = "n-from-google"
    tokens.take_custody(acct(), REFRESH_TOKEN)

    assert tokens.access_token_for(acct()) == ACCESS_TOKEN
    assert len(split_custody.calls) == 2
    assert claims_of(split_custody.calls[1]["proof"])["nonce"] == "n-from-google"

    actions = [row["action"] for row in audit.recent() if row["decision"] == audit.ALLOW]
    assert actions.count(policy.ACTION_UNWRAP) == 1
    assert actions.count(policy.ACTION_SIGN) == 1


def test_the_cosigner_logs_the_refresh_and_stores_no_ciphertext(split_custody):
    """The audit log is the evidence half of the design (§J5). It has to show
    the refresh happened and must not show what crossed the wire."""
    tokens.take_custody(acct(), REFRESH_TOKEN)
    tokens.access_token_for(acct())

    rows = audit.recent()
    assert [(row["action"], row["decision"]) for row in rows] == [
        (policy.ACTION_UNWRAP, audit.ALLOW),
        (policy.ACTION_WRAP, audit.ALLOW),
    ]

    logged = audit.db_path().read_bytes()
    _, outer = keyring.decode_record(keyring.dek_path(UID).read_bytes())
    assert REFRESH_TOKEN.encode() not in logged
    assert outer not in logged
    assert protocol.b64(outer).encode() not in logged


def test_the_log_names_the_handle_and_never_the_person(split_custody):
    """Track F, checked where it is actually decided. The co-signer's own
    database is the artifact: a copy of it must not be a customer list, so the
    address must not appear in it anywhere -- not in a uid column, not in a
    reason string, not in a measurement."""
    tokens.take_custody(acct(), REFRESH_TOKEN)
    tokens.access_token_for(acct())

    rows = audit.recent()
    assert rows and all(row["uid"] == HANDLE for row in rows)
    assert UID.encode() not in audit.db_path().read_bytes(), (
        "the co-signer's log holds an address; compromising that box now yields "
        "the customer list its docstring says it does not have"
    )


def test_a_second_wrap_for_one_account_is_refused(split_custody):
    """`/wrap` is idempotent by refusal, decided from the log rather than from a
    stored record, so invariant 4 holds while it holds.

    Onboarding no longer reaches it -- a re-consent reuses the account's data
    key -- so this drives the wire directly. The rule still has to hold, because
    what it prevents is an attacker persuading the co-signer to wrap a key of
    their choosing for an account that already has one."""
    tokens.take_custody(acct(), REFRESH_TOKEN)
    inner = wrapping.seal_dek(HANDLE, wrapping.new_dek())
    with pytest.raises(cosigner.CoSignerUnavailable, match="already wrapped"):
        cosigner.wrap(HANDLE, inner)


def test_a_re_consent_costs_no_second_wrap(split_custody):
    """Google issues a fresh refresh token on every consent, so this is the
    ordinary path and not an edge case: signing in twice must work."""
    tokens.take_custody(acct(), REFRESH_TOKEN)
    tokens.take_custody(acct(), "1//0gADifferentTokenEntirely")

    wraps = [row for row in audit.recent()
             if row["action"] == policy.ACTION_WRAP and row["decision"] == audit.ALLOW]
    assert len(wraps) == 1
    assert tokens.access_token_for(acct()) == ACCESS_TOKEN
    assert split_custody.calls[-1]["form"]["refresh_token"] == "1//0gADifferentTokenEntirely"


def test_the_rate_limit_stops_mail_rather_than_being_worked_around(
        split_custody, monkeypatch):
    """The ceiling is what bounds a live enclave breach, so it has to reach the
    caller as a failure. Anything that answers with a token past the limit has
    found a way to read mail with one box."""
    monkeypatch.setenv("COSIGNER_RATE_PER_USER_HOUR", "1")
    tokens.take_custody(acct(), REFRESH_TOKEN)
    account_under_test = acct()

    assert tokens.access_token_for(account_under_test) == ACCESS_TOKEN
    tokens.forget()
    with pytest.raises(cosigner.CoSignerUnavailable, match="rate limit"):
        tokens.access_token_for(account_under_test)
    assert len(split_custody.calls) == 1, "a refused unwrap still reached Google"


def test_a_consent_provisions_an_account_across_both_boxes(split_custody, monkeypatch):
    """The other half of the wire: onboarding. It uses `/sign-dpop` rather than
    `/unwrap-and-sign`, because at the code exchange no uid exists yet -- which
    mailbox consented is unknown until Google answers -- and then `/wrap`.

    Driving it against the real co-signer is what pins those two calls to the
    contract; the rest of the onboarding suite fakes them at the function
    boundary and cannot see a path or a field name drift."""
    split_custody.issues_a_refresh_token()
    monkeypatch.setattr(gmail_api, "profile_address", lambda token: UID)
    monkeypatch.setattr(provisioning.watch_renew, "renew_account",
                        lambda acct, log=None: None)

    provisioned = provisioning.provision("the-code", "https://app.example/auth/callback",
                                         "the-state")

    assert provisioned.id == UID
    assert provisioned.identity.first == "Alice"
    assert account.HANDLE_RE.match(provisioned.handle)
    form = split_custody.calls[0]["form"]
    assert form["grant_type"] == "authorization_code"
    assert form["code_verifier"], "the exchange carried no PKCE verifier"
    assert claims_of(split_custody.calls[0]["proof"])["htu"] == oauth_app.TOKEN_ENDPOINT

    assert [(row["action"], row["decision"]) for row in audit.recent()] == [
        (policy.ACTION_WRAP, audit.ALLOW),
        (policy.ACTION_SIGN, audit.ALLOW),
    ]

    # And the account that came out of it can then refresh, which is the join
    # between the two halves of this file.
    split_custody.calls.clear()
    assert tokens.access_token_for(provisioned) == ACCESS_TOKEN
    # A fresh signup is inactive until it pays, so it is looked up the way
    # billing does rather than the way routing does.
    assert account.account_for_email(UID).token_file, "the manifest lost the token pointer"


def test_the_consent_binds_googles_token_to_the_key_the_enclave_cannot_use(split_custody):
    """`dpop_jkt` on the auth URL is what makes the co-signer permanent rather
    than one-shot: Google binds the refresh token to that key at consent, and
    the enclave never holds its private half."""
    url = provisioning.build_auth_url("the-state", "https://app.example/auth/callback")
    params = parse_qs(urlparse(url).query)
    assert params["dpop_jkt"] == [cosigner_keys.dpop_jkt()]
    assert params["code_challenge_method"] == ["S256"]


def test_a_dead_cosigner_stops_mail(split_custody, monkeypatch):
    """Invariant 3 across the real boundary: the enclave has no local key to
    fall back to and must not grow one."""
    tokens.take_custody(acct(), REFRESH_TOKEN)
    monkeypatch.setenv("LETTERLOCK_COSIGNER_URL", "http://127.0.0.1:1")
    tokens.forget()
    with pytest.raises(cosigner.CoSignerUnavailable):
        tokens.access_token_for(acct())
