"""Track D billing: Polar entitlement events -> account plan gating.

Unit-level: pins the entitlement decision, the customer->account resolution
(by stored polar_customer_id and by email), the plan_status writer, and the
end-to-end gate that an inactive account is unroutable via account.get_account
while an activated one becomes routable. Polar's API is never hit: every path
tested resolves the account from data carried in the event itself.
"""

import pytest
from harness import account_entry as _entry
from harness import write_manifest as _manifest

from backend.accounts import account
from backend.billing import billing, polar_api


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

    def fake_create(product_id, success_url, email, token, metadata=None):
        seen["base"] = polar_api.api_base()
        seen["success_url"] = success_url
        seen["metadata"] = metadata
        return 201, {"url": "https://sandbox.polar.sh/checkout/abc"}

    monkeypatch.setenv("POLAR_SANDBOX", "1")
    monkeypatch.setenv("POLAR_PRODUCT_ID_SANDBOX", "prod_1")
    monkeypatch.setenv("POLAR_API_TOKEN_SANDBOX", "tok")
    monkeypatch.setattr(polar_api, "create_checkout", fake_create)
    url, checkout_id = billing.checkout_url("dan@x.com", fallback="/dashboard")
    assert url == "https://sandbox.polar.sh/checkout/abc"
    assert checkout_id is None, "the fake response carries no id to bind to"
    assert seen["base"] == polar_api.SANDBOX_BASE
    assert "{CHECKOUT_ID}" in seen["success_url"], "the return trip needs the id"
    assert seen["metadata"] == {billing.CHECKOUT_ACCOUNT_KEY: "dan@x.com"}, (
        "the return trip is only verifiable if the checkout carries its account"
    )


def _checkout(monkeypatch, body, status=200):
    """Stand in for Polar's copy of a checkout, and record whether it was read."""
    seen = {}

    def fake_get(checkout_id, token):
        seen["checkout_id"] = checkout_id
        return status, body

    monkeypatch.setattr(polar_api, "get_checkout", fake_get)
    return seen


def test_confirm_checkout_refuses_another_accounts_checkout(tmp_path, monkeypatch):
    """The checkout id comes back in a query string the browser controls. Any
    signed-in account presenting a paid checkout id used to get the subscription
    it paid for, and the customer link then pointed portal_url() at that buyer's
    Polar customer."""
    monkeypatch.setattr(account, "MANIFEST", _manifest(tmp_path, [
        _entry("victim@x.com", status="active"),
        _entry("thief@x.com", status="inactive"),
    ]))
    _checkout(monkeypatch, {
        "id": "co_1",
        "status": "succeeded",
        "customer_id": "cus_victim",
        "customer_email": "victim@x.com",
        "metadata": {billing.CHECKOUT_ACCOUNT_KEY: "victim@x.com"},
    })
    b = _billing(monkeypatch)
    thief = account.account_for_email("thief@x.com")
    paid, detail = b.confirm_checkout("co_1", thief)
    assert paid is False
    assert "does not belong" in detail
    assert account.get_account("thief@x.com") is None, "no free subscription"
    assert account.account_for_email("thief@x.com").polar_customer_id is None, (
        "and no link to someone else's Polar customer"
    )


def test_confirm_checkout_activates_and_links_the_buyer(tmp_path, monkeypatch):
    monkeypatch.setattr(account, "MANIFEST", _manifest(tmp_path, [
        _entry("dan@x.com", status="inactive"),
    ]))
    seen = _checkout(monkeypatch, {
        "id": "co_2",
        "status": "succeeded",
        "customer_id": "cus_dan",
        "metadata": {billing.CHECKOUT_ACCOUNT_KEY: "dan@x.com"},
    })
    b = _billing(monkeypatch)
    dan = account.account_for_email("dan@x.com")
    paid, detail = b.confirm_checkout("co_2", dan)
    assert paid is True
    assert "inactive->active" in detail
    assert seen["checkout_id"] == "co_2"
    assert account.get_account("dan@x.com").polar_customer_id == "cus_dan"


def test_confirm_checkout_falls_back_to_the_email_binding(tmp_path, monkeypatch):
    """A checkout minted before the metadata stamp existed still resolves, by the
    same ordering the webhook uses. It has to: those are in flight across a
    deploy."""
    monkeypatch.setattr(account, "MANIFEST", _manifest(tmp_path, [
        _entry("dan@x.com", status="inactive"),
    ]))
    _checkout(monkeypatch, {"id": "co_3", "status": "confirmed",
                            "customer": {"email": "dan@x.com"}})
    b = _billing(monkeypatch)
    paid, _ = b.confirm_checkout("co_3", account.account_for_email("dan@x.com"))
    assert paid is True
    assert account.get_account("dan@x.com") is not None


def test_confirm_checkout_refuses_an_unresolvable_checkout(tmp_path, monkeypatch):
    """Nobody to bind it to means it is not this buyer's either. The webhook
    settles that case and the return page says pending, not failed."""
    monkeypatch.setattr(account, "MANIFEST", _manifest(tmp_path, [
        _entry("dan@x.com", status="inactive"),
    ]))
    _checkout(monkeypatch, {"id": "co_4", "status": "succeeded"})
    b = _billing(monkeypatch)
    paid, detail = b.confirm_checkout("co_4", account.account_for_email("dan@x.com"))
    assert paid is False
    assert "does not belong" in detail
    assert account.get_account("dan@x.com") is None


def test_confirm_checkout_refuses_an_unpaid_checkout_of_the_buyers_own(
        tmp_path, monkeypatch):
    monkeypatch.setattr(account, "MANIFEST", _manifest(tmp_path, [
        _entry("dan@x.com", status="inactive"),
    ]))
    _checkout(monkeypatch, {"id": "co_5", "status": "open", "customer_id": "cus_dan",
                            "metadata": {billing.CHECKOUT_ACCOUNT_KEY: "dan@x.com"}})
    b = _billing(monkeypatch)
    paid, detail = b.confirm_checkout("co_5", account.account_for_email("dan@x.com"))
    assert paid is False
    assert "status=open" in detail
    assert account.get_account("dan@x.com") is None


def test_an_unpaid_checkout_links_no_polar_customer(tmp_path, monkeypatch):
    """The customer link happens after the paid check, never before it.

    The attack it closes: mint a checkout through /billing/checkout so it is
    stamped with your own account and the ownership test passes, then type a
    victim's address on Polar's page so Polar attaches their existing customer
    to it, then come back. Linking first put the victim's customer on the
    attacker's account, and `portal_url()` mints a Polar customer-portal session
    for whatever this field names -- payment methods, invoices, cancellation."""
    monkeypatch.setattr(account, "MANIFEST", _manifest(tmp_path, [
        _entry("thief@x.com", status="inactive"),
    ]))
    _checkout(monkeypatch, {"id": "co_6", "status": "open",
                            "customer_id": "cus_victim",
                            "metadata": {billing.CHECKOUT_ACCOUNT_KEY: "thief@x.com"}})
    b = _billing(monkeypatch)
    paid, _ = b.confirm_checkout("co_6", account.account_for_email("thief@x.com"))
    assert paid is False
    assert account.account_for_email("thief@x.com").polar_customer_id is None


def test_a_polar_customer_belongs_to_one_account(tmp_path, monkeypatch):
    """Two accounts holding one customer id makes `account_for_customer_id`
    answer with whichever the manifest lists first, so the reconcile then
    decides a third party's entitlement."""
    monkeypatch.setattr(account, "MANIFEST", _manifest(tmp_path, [
        _entry("victim@x.com", status="active", polar_customer_id="cus_shared"),
        _entry("thief@x.com", status="inactive"),
    ]))
    with pytest.raises(account.InvalidAccountData, match="already linked"):
        account.set_polar_customer_id("thief@x.com", "cus_shared")
    assert account.account_for_email("thief@x.com").polar_customer_id is None
    # Re-linking an account to the customer it already holds is not a conflict.
    assert account.set_polar_customer_id(
        "victim@x.com", "cus_shared").polar_customer_id == "cus_shared"


def test_a_manifest_that_already_drifted_is_caught_at_load(tmp_path, monkeypatch):
    """Refused on read as well as on write, the same way duplicate handles are:
    a store that got into this state before the writer refused it should fail
    where it is loaded rather than silently at resolve time.

    `InvalidAccountData` rather than `AssertionError` because the subject is the
    manifest file and not an argument our own caller passed, so `-O` must not
    delete it."""
    monkeypatch.setattr(account, "MANIFEST", _manifest(tmp_path, [
        _entry("a@x.com", polar_customer_id="cus_1"),
        _entry("b@x.com", polar_customer_id="cus_1"),
    ]))
    with pytest.raises(account.InvalidAccountData, match="share a Polar customer id"):
        account.all_accounts()


def test_an_unstamped_object_may_introduce_a_link_but_never_move_one(
        tmp_path, monkeypatch):
    """`customer_email` is a form field the buyer edits at Polar, and only an
    unstamped object ever reaches the email branch. An account already linked to
    a different customer was linked by something exact, so a buyer-typed address
    must not override it."""
    monkeypatch.setattr(account, "MANIFEST", _manifest(tmp_path, [
        _entry("dan@x.com", status="active", polar_customer_id="cus_dan"),
        _entry("erin@x.com", status="active"),
    ]))
    b = _billing(monkeypatch)
    hostile = {"customer_id": "cus_other", "customer_email": "dan@x.com"}
    assert b.resolve_account(hostile) is None
    # An account with no link at all still resolves: this refuses a move, not
    # an introduction.
    assert b.resolve_account(
        {"customer_id": "cus_other", "customer_email": "erin@x.com"}).id == "erin@x.com"


def test_the_enclave_mints_no_unstamped_checkout(monkeypatch):
    """The static dashboard link carries no CHECKOUT_ACCOUNT_KEY -- there is no
    API call to stamp -- so everything downstream falls back to resolving by an
    address the buyer edits. Inside the enclave there is no operator to notice
    the difference, and /billing/checkout already renders "unavailable"."""
    monkeypatch.setenv("POLAR_CHECKOUT_URL", "https://buy.polar.sh/prod")
    monkeypatch.delenv("POLAR_PRODUCT_ID", raising=False)
    monkeypatch.delenv("POLAR_SANDBOX", raising=False)

    monkeypatch.delenv("TEE_REQUIRED", raising=False)
    url, checkout_id = billing.checkout_url("dan@x.com", fallback="/billing")
    assert url.startswith("https://buy.polar.sh/prod") and checkout_id is None

    monkeypatch.setenv("TEE_REQUIRED", "1")
    assert billing.checkout_url("dan@x.com", fallback="/billing") == ("/billing", None)


def test_checkout_url_falls_back_when_polar_is_unconfigured(monkeypatch):
    """No product to mint a session against and no dashboard link to fall back
    to. The caller's own landing spot is the answer, and there is no id."""
    monkeypatch.delenv("POLAR_SANDBOX", raising=False)
    monkeypatch.delenv("POLAR_PRODUCT_ID", raising=False)
    monkeypatch.delenv("TEE_REQUIRED", raising=False)
    monkeypatch.setenv("POLAR_CHECKOUT_URL", "")

    assert billing.checkout_url("z@x.com", fallback="/dashboard") == ("/dashboard", None)


def test_the_static_link_follows_the_sandbox_toggle(monkeypatch):
    """The suffix switch applies to the dashboard link too, not only to the API
    token: a sandbox box sending buyers to the production checkout charges
    them."""
    monkeypatch.setenv("POLAR_SANDBOX", "1")
    monkeypatch.delenv("POLAR_PRODUCT_ID_SANDBOX", raising=False)
    monkeypatch.delenv("TEE_REQUIRED", raising=False)
    monkeypatch.setenv("POLAR_CHECKOUT_URL", "https://buy.polar.sh/prod")
    monkeypatch.setenv("POLAR_CHECKOUT_URL_SANDBOX", "https://sandbox.polar.sh/dev")

    loc, checkout_id = billing.checkout_url("z@x.com")
    assert loc == "https://sandbox.polar.sh/dev?customer_email=z%40x.com"
    # The static link mints no session, so there is no id to bind to a browser.
    assert checkout_id is None


def test_stamped_metadata_resolves_a_webhook_event(tmp_path, monkeypatch):
    """Polar copies checkout metadata onto the order, so the exact binding is
    available to the webhook too, ahead of the pay-email guess."""
    monkeypatch.setattr(account, "MANIFEST", _manifest(tmp_path, [
        _entry("dan@x.com", status="inactive"),
        _entry("stranger@x.com", status="inactive"),
    ]))
    b = _billing(monkeypatch)
    res = b.apply_event({"type": "order.paid", "data": {
        "customer": {"email": "stranger@x.com"},
        "metadata": {billing.CHECKOUT_ACCOUNT_KEY: "dan@x.com"},
    }})
    assert "account=dan@x.com inactive->active" in res
    assert account.get_account("stranger@x.com") is None


def test_order_paid_without_a_subscription_says_it_is_unreconcilable(
        tmp_path, monkeypatch, capsys):
    """Every other grant is re-derivable from Polar. This one is not: reconcile
    reads subscriptions, and this customer has none, so the event is the only
    record that the account should be active. It still activates -- a one-off
    product is a decision someone may make in the dashboard -- but it says so."""
    monkeypatch.setattr(account, "MANIFEST", _manifest(tmp_path, [
        _entry("eve@x.com", status="inactive"),
        _entry("frank@x.com", status="inactive"),
    ]))
    b = _billing(monkeypatch)

    res = b.apply_event({"type": "order.paid", "data": {
        "customer": {"email": "eve@x.com"}}})
    assert "inactive->active" in res
    assert "not reconcilable" in capsys.readouterr().err

    res = b.apply_event({"type": "order.paid", "data": {
        "customer": {"email": "frank@x.com"}, "subscription_id": "sub_1"}})
    assert "inactive->active" in res
    assert "not reconcilable" not in capsys.readouterr().err


def _subscriptions(monkeypatch, pages):
    """Stand in for Polar's paginated subscription list. `pages` is a list of
    lists, one per page, so the pagination is exercised rather than assumed."""
    def fake(organization_id, token, page=1, limit=100):
        assert organization_id == "org" and token == "tok"
        return 200, {"items": pages[page - 1],
                     "pagination": {"max_page": len(pages)}}
    monkeypatch.setattr(polar_api, "list_subscriptions", fake)


def test_reconcile_settles_lapses_and_leaves_accounts_polar_never_named(
        tmp_path, monkeypatch):
    """The scope that matters twice over: this sweep is the only thing checking
    entitlement against Polar for an event that was never delivered, and inside
    the enclave it is the only thing checking entitlement at all. It must
    deactivate a lapsed subscriber and must not touch an account Polar has never
    heard of, which is what the seeded owner is."""
    monkeypatch.setattr(account, "MANIFEST", _manifest(tmp_path, [
        _entry("paid@x.com", status="inactive", polar_customer_id="cus_paid"),
        _entry("lapsed@x.com", status="active", polar_customer_id="cus_lapsed"),
        _entry("owner@x.com", status="active"),
    ]))
    _subscriptions(monkeypatch, [
        [{"customer_id": "cus_paid", "status": "active"}],
        [{"customer_id": "cus_lapsed", "status": "canceled"},
         {"customer_id": "cus_gone", "status": "active"}],
    ])

    stats = _billing(monkeypatch).reconcile()

    assert stats == {"customers": 3, "activated": 1, "deactivated": 1,
                     "skipped": 0, "unmatched": 1}
    assert account.get_account("paid@x.com") is not None
    assert account.get_account("lapsed@x.com") is None
    assert account.get_account("owner@x.com") is not None


def test_reconcile_reads_a_customers_subscriptions_together(tmp_path, monkeypatch):
    """One customer, two subscriptions, one of them entitled: entitled wins.
    Deciding per row instead would let whichever row came last flip an account
    that is paying for a second plan."""
    monkeypatch.setattr(account, "MANIFEST", _manifest(tmp_path, [
        _entry("gina@x.com", status="inactive", polar_customer_id="cus_g"),
    ]))
    _subscriptions(monkeypatch, [[
        {"customer_id": "cus_g", "status": "canceled"},
        {"customer_id": "cus_g", "status": "active"},
    ]])

    stats = _billing(monkeypatch).reconcile()

    assert stats["activated"] == 1
    assert account.get_account("gina@x.com") is not None
