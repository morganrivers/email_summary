"""Track D billing: Polar entitlement events -> account plan gating.

Unit-level: pins the entitlement decision, the customer->account resolution
(by stored polar_customer_id and by email), the plan_status writer, and the
end-to-end gate that an inactive account is unroutable via account.get_account
while an activated one becomes routable. Polar's API is never hit: every path
tested resolves the account from data carried in the event itself.
"""

import json

from backend.accounts import account
from backend.billing import billing
from backend.billing import polar_api


def _manifest(tmp_path, entries):
    p = tmp_path / "accounts.json"
    p.write_text(json.dumps({"accounts": entries}))
    return p


def _entry(email, status="active", polar_customer_id=None, emails=None):
    e = {
        "id": email,
        "identity": {"first": "A", "last": "B",
                     "emails": emails if emails is not None else [email]},
        "telegram": {"chat_id": "c", "token": "t"},
        "plan_status": status,
    }
    if polar_customer_id:
        e["polar_customer_id"] = polar_customer_id
    return e


def _billing(monkeypatch):
    monkeypatch.setenv("POLAR_API_TOKEN", "tok")
    monkeypatch.setenv("POLAR_ORGANIZATION_ID", "org")
    monkeypatch.setenv("POLAR_SANDBOX", "0")
    return billing.PolarBilling()


def test_subscription_entitled_rule():
    assert billing.subscription_entitled("active")
    assert billing.subscription_entitled("trialing")
    for s in ("past_due", "canceled", "unpaid", "incomplete",
              "incomplete_expired", None, ""):
        assert not billing.subscription_entitled(s)


def test_order_paid_activates_lapsed_account(tmp_path, monkeypatch):
    monkeypatch.setattr(account, "MANIFEST",
                        _manifest(tmp_path, [_entry("alice@x.com", status="inactive")]))
    assert account.get_account("alice@x.com") is None            # gated off before pay
    b = _billing(monkeypatch)
    res = b.apply_event({"type": "order.paid",
                         "data": {"customer": {"email": "alice@x.com"}}})
    assert "inactive->active" in res
    assert account.get_account("alice@x.com").id == "alice@x.com"  # now routable (D2)


def test_subscription_revoked_deactivates(tmp_path, monkeypatch):
    monkeypatch.setattr(account, "MANIFEST",
                        _manifest(tmp_path, [_entry("bob@x.com", status="active")]))
    b = _billing(monkeypatch)
    res = b.apply_event({"type": "subscription.revoked",
                         "data": {"status": "canceled",
                                  "customer": {"email": "bob@x.com"}}})
    assert "active->inactive" in res
    assert account.get_account("bob@x.com") is None               # gated off


def test_scheduled_cancel_stays_active(tmp_path, monkeypatch):
    # cancel-at-period-end: status still active until the period closes.
    monkeypatch.setattr(account, "MANIFEST",
                        _manifest(tmp_path, [_entry("carol@x.com", status="active")]))
    b = _billing(monkeypatch)
    res = b.apply_event({"type": "subscription.canceled",
                         "data": {"status": "active",
                                  "customer": {"email": "carol@x.com"}}})
    assert "already active" in res
    assert account.get_account("carol@x.com") is not None


def test_result_explains_a_cancel_that_grants_access(tmp_path, monkeypatch):
    # The event name and the outcome disagree here, so the line must say why:
    # a lapsed account whose new subscription is cancel-at-period-end is still
    # entitled, and "canceled -> active" alone reads as a bug.
    monkeypatch.setattr(account, "MANIFEST",
                        _manifest(tmp_path, [_entry("carol@x.com", status="inactive")]))
    b = _billing(monkeypatch)
    res = b.apply_event({"type": "subscription.canceled",
                         "data": {"status": "active",
                                  "cancel_at_period_end": True,
                                  "customer": {"email": "carol@x.com"}}})
    assert "inactive->active" in res
    assert "status=active" in res
    assert "cancel_at_period_end=True" in res


def test_resolve_by_stored_customer_id(tmp_path, monkeypatch):
    # No email in the event: resolve via polar_customer_id (no Polar API call).
    monkeypatch.setattr(account, "MANIFEST", _manifest(tmp_path, [
        _entry("dan@x.com", status="inactive", polar_customer_id="cus_123"),
    ]))
    b = _billing(monkeypatch)
    res = b.apply_event({"type": "order.paid", "data": {"customer_id": "cus_123"}})
    assert "inactive->active" in res
    assert account.get_account("dan@x.com") is not None


def test_unknown_customer_no_flip(tmp_path, monkeypatch):
    monkeypatch.setattr(account, "MANIFEST",
                        _manifest(tmp_path, [_entry("dan@x.com")]))
    b = _billing(monkeypatch)
    res = b.apply_event({"type": "order.paid",
                         "data": {"customer": {"email": "stranger@x.com"}}})
    assert "no local account" in res


def test_apply_event_ignores_unrelated(tmp_path, monkeypatch):
    monkeypatch.setattr(account, "MANIFEST",
                        _manifest(tmp_path, [_entry("dan@x.com")]))
    b = _billing(monkeypatch)
    assert "ignored" in b.apply_event({"type": "checkout.created", "data": {}})


def test_set_plan_status_persists_and_reports_prior(tmp_path, monkeypatch):
    monkeypatch.setattr(account, "MANIFEST",
                        _manifest(tmp_path, [_entry("eve@x.com", status="active")]))
    assert account.set_plan_status("EVE@X.COM", "inactive") == "active"  # case-insensitive
    assert account.get_account("eve@x.com") is None
    # persisted across a fresh read
    assert [a.id for a in account.load_accounts()] == []
    assert [a.id for a in account.all_accounts()] == ["eve@x.com"]


def test_api_base_follows_the_toggle_without_a_billing_object(monkeypatch):
    """The base used to be module state assigned in PolarBilling.__init__, so a
    caller that never built one (checkout_url) hit production with a sandbox
    token and fell back to a static checkout link."""
    monkeypatch.setenv("POLAR_SANDBOX", "1")
    assert polar_api.api_base() == polar_api.SANDBOX_BASE
    monkeypatch.setenv("POLAR_SANDBOX", "0")
    assert polar_api.api_base() == polar_api.PROD_BASE


def test_checkout_url_mints_against_the_sandbox_when_toggled(monkeypatch):
    seen = {}

    def fake_create(product_id, success_url, email, token):
        seen["base"] = polar_api.api_base()
        seen["success_url"] = success_url
        return 201, {"url": "https://sandbox.polar.sh/checkout/abc"}

    monkeypatch.setenv("POLAR_SANDBOX", "1")
    monkeypatch.setenv("POLAR_PRODUCT_ID_SANDBOX", "prod_1")
    monkeypatch.setenv("POLAR_API_TOKEN_SANDBOX", "tok")
    monkeypatch.setattr(polar_api, "create_checkout", fake_create)
    url = billing.checkout_url("dan@x.com", fallback="/dashboard")
    assert url == "https://sandbox.polar.sh/checkout/abc"
    assert seen["base"] == polar_api.SANDBOX_BASE
    assert "{CHECKOUT_ID}" in seen["success_url"], "the return trip needs the id"
