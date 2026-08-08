"""The Polar webhook: what a public, unauthenticated endpoint accepts.

`process_webhook` is the whole decision path and the reason it is a function
rather than a method: the request handler around it does framing, and framing
is not what decides whether a stranger can flip an account's plan. So the
signature checks here run against the real `standardwebhooks` verifier with a
real secret, not a fake that returns True -- a fake would pass whether or not
the module remembered to verify at all.

The status codes are part of the contract with Polar, which retries a 5xx and
does not retry a 4xx. Getting that pair backwards either drops an entitlement
event permanently or asks Polar to replay a payload we will never accept.
"""

import base64
import datetime
import json

import pytest
from standardwebhooks import Webhook

import harness

from backend.accounts import account
from backend.billing import billing
from backend.billing import billing_webhook


SECRET = "polar-webhook-secret-not-real"
BUYER = "buyer@example.com"


@pytest.fixture
def verifier():
    """The real verifier, keyed the way main() keys it.

    Polar stores the secret raw and the library wants it base64, so this line
    is the quirk the module's docstring warns about. Building the verifier here
    the same way pins it: a test that base64-encoded on only one side would
    pass while production rejected every event."""
    return Webhook(base64.b64encode(SECRET.encode("utf-8")).decode("utf-8"))


@pytest.fixture
def signed(verifier):
    """Sign a payload into (raw, headers) exactly as Polar would."""
    def sign(event, msg_id="msg_1", timestamp=None):
        raw = json.dumps(event).encode("utf-8")
        when = timestamp or datetime.datetime.now(datetime.timezone.utc)
        signature = verifier.sign(msg_id, when, raw.decode("utf-8"))
        return raw, {
            "webhook-id": msg_id,
            "webhook-timestamp": str(int(when.timestamp())),
            "webhook-signature": signature,
        }
    return sign


@pytest.fixture
def billing_for(monkeypatch, tmp_path):
    """A PolarBilling over a manifest of our choosing."""
    def build(entries):
        monkeypatch.setattr(account, "ACCOUNTS_DIR", tmp_path)
        monkeypatch.setattr(account, "MANIFEST",
                            harness.write_manifest(tmp_path, entries))
        monkeypatch.setenv("POLAR_API_TOKEN", "tok")
        monkeypatch.setenv("POLAR_ORGANIZATION_ID", "org")
        monkeypatch.setenv("POLAR_SANDBOX", "0")
        return billing.PolarBilling()
    return build


def _paid(email=BUYER):
    return {"type": "order.paid", "data": {"customer": {"email": email}}}


def test_a_signed_event_activates_the_buyer(verifier, signed, billing_for):
    b = billing_for([harness.account_entry(BUYER, status="inactive")])
    assert account.get_account(BUYER) is None

    raw, headers = signed(_paid())
    status, body = billing_webhook.process_webhook(raw, headers, verifier, b)

    assert status == 200
    assert json.loads(body) == {"status": "ok"}
    assert account.get_account(BUYER).plan_status == "active"


def test_an_unsigned_body_flips_nothing(verifier, billing_for):
    """The whole point of the endpoint being safe to expose: anyone can POST to
    it, so an event that is not signed must not reach apply_event."""
    b = billing_for([harness.account_entry(BUYER, status="inactive")])

    raw = json.dumps(_paid()).encode("utf-8")
    status, body = billing_webhook.process_webhook(raw, {}, verifier, b)

    assert status == 400
    assert "invalid signature" in body
    assert account.get_account(BUYER) is None, "an unsigned event granted a plan"


def test_a_tampered_body_flips_nothing(verifier, signed, billing_for):
    """A valid signature over a different payload. This is the attack the
    signature exists for: replay a genuinely signed activation with the
    customer address swapped for your own."""
    b = billing_for([
        harness.account_entry(BUYER, status="inactive"),
        harness.account_entry("attacker@example.com", status="inactive"),
    ])

    _, headers = signed(_paid())
    tampered = json.dumps(_paid("attacker@example.com")).encode("utf-8")
    status, _ = billing_webhook.process_webhook(tampered, headers, verifier, b)

    assert status == 400
    assert account.get_account("attacker@example.com") is None
    assert account.get_account(BUYER) is None


def test_a_signature_from_the_wrong_secret_flips_nothing(verifier, billing_for):
    """A correctly formed Standard Webhooks signature, signed by somebody who
    does not hold our secret."""
    b = billing_for([harness.account_entry(BUYER, status="inactive")])
    other = Webhook(base64.b64encode(b"a-different-secret").decode("utf-8"))

    raw = json.dumps(_paid()).encode("utf-8")
    when = datetime.datetime.now(datetime.timezone.utc)
    headers = {
        "webhook-id": "msg_1",
        "webhook-timestamp": str(int(when.timestamp())),
        "webhook-signature": other.sign("msg_1", when, raw.decode("utf-8")),
    }
    status, _ = billing_webhook.process_webhook(raw, headers, verifier, b)

    assert status == 400
    assert account.get_account(BUYER) is None


def test_an_old_signature_is_refused(verifier, signed, billing_for):
    """Standard Webhooks bounds replay by timestamp. Without that a captured
    activation event stays spendable forever."""
    b = billing_for([harness.account_entry(BUYER, status="inactive")])

    stale = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
    raw, headers = signed(_paid(), timestamp=stale)
    status, _ = billing_webhook.process_webhook(raw, headers, verifier, b)

    assert status == 400
    assert account.get_account(BUYER) is None


def test_an_apply_failure_asks_polar_to_retry(verifier, signed, billing_for):
    """A 5xx is the retry request. An entitlement event is not replayable by
    the user, so swallowing a transient failure as 200 loses the subscription
    the buyer already paid for."""
    b = billing_for([harness.account_entry(BUYER, status="inactive")])

    def explode(event):
        raise RuntimeError("manifest write failed")

    b.apply_event = explode
    raw, headers = signed(_paid())
    status, body = billing_webhook.process_webhook(raw, headers, verifier, b)

    assert status == 500
    assert "apply failed" in body


def test_an_event_for_nobody_is_accepted_rather_than_retried(verifier, signed, billing_for):
    """Polar sends events for its whole organization, so an event naming a
    customer with no local account is ordinary. Answering 4xx or 5xx would have
    Polar retry a payload that will never resolve."""
    b = billing_for([harness.account_entry(BUYER)])

    raw, headers = signed(_paid("stranger@example.com"))
    status, _ = billing_webhook.process_webhook(raw, headers, verifier, b)

    assert status == 200


def test_an_unrelated_event_type_is_accepted_and_changes_nothing(verifier, signed, billing_for):
    b = billing_for([harness.account_entry(BUYER, status="inactive")])

    raw, headers = signed({"type": "checkout.created", "data": {}})
    status, _ = billing_webhook.process_webhook(raw, headers, verifier, b)

    assert status == 200
    assert account.get_account(BUYER) is None


def test_a_revocation_gates_the_account_off(verifier, signed, billing_for):
    b = billing_for([harness.account_entry(BUYER, status="active")])

    raw, headers = signed({
        "type": "subscription.revoked",
        "data": {"status": "canceled", "customer": {"email": BUYER}},
    })
    status, _ = billing_webhook.process_webhook(raw, headers, verifier, b)

    assert status == 200
    assert account.get_account(BUYER) is None


def test_the_body_ceiling_is_below_what_a_reader_would_buffer():
    """The endpoint is public and the declared length is read before the body,
    so the ceiling is what stops an unauthenticated caller from naming a size
    the process then allocates."""
    assert billing_webhook.MAX_BODY == 256 * 1024


def test_apply_event_is_reachable_only_from_behind_the_signature_check():
    """process_webhook verifies and then applies, in that order, and it is the
    only function in the module that applies at all. A second handler that
    called apply_event directly would make the signature check optional by
    construction, which is not a thing the other tests here could notice."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(billing_webhook))
    offenders = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if func.name == "process_webhook":
            continue
        for node in ast.walk(func):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "apply_event"):
                offenders.append(func.name)
    assert not offenders, (
        f"{offenders} call apply_event outside process_webhook; every event must "
        "pass the signature check first"
    )
