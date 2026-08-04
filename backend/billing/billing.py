"""Polar subscription entitlement -> account plan gating (Track D).

Ported from hetzner_signing_server's cert machinery with the action swapped:
instead of signing an entitlement cert into Polar customer metadata, we flip the
local account's plan_status active/inactive. account.load_accounts() drops
inactive accounts, so a lapsed subscription makes the user unroutable end to end
(webhook drops their pushes, daemon skips them) -- that is the Gmail-processing
gate (D2).

Two entry points share this, mirroring the source poller/webhook split:
  * billing_webhook.py -- instant flip on a Polar order.paid / subscription.* event
  * billing_poller.py  -- periodic full reconcile over every Polar subscription

Entitlement is one decision (subscription_entitled), used by both paths, so the
webhook and the reconcile can never disagree about what "paid" means.
"""

import os
import sys
import urllib.parse

from dotenv import load_dotenv

from backend import paths
from backend import site
from backend.accounts import account
from backend.billing import polar_api

load_dotenv(paths.ENV_FILE)

ENTITLED_SUB_STATUSES = frozenset({"active", "trialing"})

# What the Polar product charges, in euros. Every page that quotes a price reads
# this one name: the landing copy, the pricing page, the comparison table, the
# sign-up button and the billing table each carried their own literal, and they
# drifted from the product until a buyer was quoted one figure and charged
# another. Polar remains the authority that actually bills; changing the product
# there means changing this line too.
PLAN_PRICE_EUR = 25


def log(msg):
    sys.stderr.write(f"billing {msg}\n")
    sys.stderr.flush()


def select_env(name, sandbox):
    """Pick NAME_SANDBOX or NAME_PROD by the POLAR_SANDBOX toggle, falling back to
    the unsuffixed NAME. One switch flips the whole surface between environments
    while both value sets sit side by side in .env. Same pattern as the source."""
    suffix = "SANDBOX" if sandbox else "PROD"
    val = os.environ.get(f"{name}_{suffix}")
    return val if val is not None else os.environ.get(name)


# The toggle is read in polar_api, next to the two base URLs it selects between,
# and re-exported here because the tokens, the webhook secret and the checkout
# link all switch on the same answer.
sandbox_enabled = polar_api.sandbox_enabled


def product_id():
    """The Polar product being sold, for API-minted checkouts. Optional: without
    it we fall back to a static dashboard checkout link."""
    return select_env("POLAR_PRODUCT_ID", sandbox_enabled())


def _static_checkout_url(email, fallback):
    """A checkout link created in the Polar dashboard, prefilled with the buyer's
    address. Where the buyer lands after paying is a field on the link, so this
    path cannot guarantee they come back to us."""
    base = select_env("POLAR_CHECKOUT_URL", sandbox_enabled())
    if not base:
        return fallback
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}customer_email={urllib.parse.quote(email)}"


def checkout_url(email, fallback="/dashboard"):
    """Where to send a user to pay. Shared by the web app and the onboarding
    flow; both used to carry their own copy of this.

    Prefers a checkout session minted through the API, because that carries
    site.checkout_success_url() and so brings the buyer back to us afterwards. A
    static dashboard link ends on Polar's own receipt page unless someone
    remembers to fill in a success-URL field, which is exactly how a paid buyer
    got stranded there. Falls back to the static link when no product id is
    configured or the API call fails: a checkout the user can complete beats no
    checkout at all, even without the return trip."""
    pid = product_id()
    if not pid:
        return _static_checkout_url(email, fallback)
    try:
        token = select_env("POLAR_API_TOKEN", sandbox_enabled())
        status, body = polar_api.create_checkout(
            pid, site.checkout_success_url(), email, token,
        )
    except AssertionError as err:
        log(f"checkout session unavailable ({err}); using the static link")
        return _static_checkout_url(email, fallback)
    if status not in (200, 201) or not isinstance(body, dict) or not body.get("url"):
        log(f"create_checkout failed: {status} {body}; using the static link")
        return _static_checkout_url(email, fallback)
    return body["url"]


def webhook_secret():
    """The Polar webhook signing secret for the active environment. Read through
    the same suffix switch as the API token, so the verifier and the API client
    can never end up on opposite sides of the sandbox toggle. The webhook service
    and the deploy preflight both call this."""
    return select_env("POLAR_WEBHOOK_SECRET", sandbox_enabled())


def subscription_entitled(status):
    """The one rule for 'this subscription grants access', shared by the webhook
    and the poller. Entitled while active or trialing; past_due / canceled /
    unpaid / incomplete all gate off. Polar fires subscription.revoked (status
    canceled) when access truly ends, so driving off status also handles
    cancel-at-period-end correctly: a scheduled cancellation keeps status active
    until the period closes, then revoked flips it."""
    return status in ENTITLED_SUB_STATUSES


class PolarBilling:
    """Loads Polar backend config from the environment and reconciles a customer's
    subscription state into their local account's plan_status."""

    def __init__(self):
        self.sandbox = sandbox_enabled()
        self.token = select_env("POLAR_API_TOKEN", self.sandbox)
        self.org = select_env("POLAR_ORGANIZATION_ID", self.sandbox)
        assert self.token and self.org, (
            f"missing POLAR_API_TOKEN / POLAR_ORGANIZATION_ID for "
            f"{'SANDBOX' if self.sandbox else 'PROD'}"
        )

    def log_startup(self, who):
        tok = self.token
        masked = f"{tok[:10]}...{tok[-4:]}" if len(tok) > 16 else "****"
        log(f"{who} env={'SANDBOX' if self.sandbox else 'PRODUCTION'} "
            f"base={polar_api.api_base()} org={self.org} token={masked}")

    @staticmethod
    def _customer_id(data):
        return data.get("customer_id") or (data.get("customer") or {}).get("id")

    @staticmethod
    def _event_email(data):
        cust = data.get("customer") or {}
        return (cust.get("email") or data.get("customer_email")
                or (data.get("user") or {}).get("email"))

    def _customer_email(self, customer_id):
        status, body = polar_api.get_customer(customer_id, self.token)
        if status != 200 or not isinstance(body, dict):
            log(f"get_customer {customer_id} failed: {status}")
            return None
        return body.get("email")

    def resolve_account(self, data):
        """Map a Polar event's customer to a local account (including inactive):
        by stored polar_customer_id first (exact link set at checkout), else by
        email carried in the event, else by an email fetched from Polar."""
        cid = self._customer_id(data)
        if cid:
            acct = account.account_for_customer_id(cid)
            if acct is not None:
                return acct
        email = self._event_email(data)
        if not email and cid:
            email = self._customer_email(cid)
        if not email:
            return None
        return account.account_for_email(email, include_inactive=True)

    def _apply(self, acct, target):
        assert target in ("active", "inactive")
        if acct.plan_status == target:
            return f"account={acct.id} already {target}"
        prior = account.set_plan_status(acct.id, target)
        return f"account={acct.id} {prior}->{target}"

    def apply_event(self, event):
        """Decide active/inactive from one webhook event and flip the account.
        Returns a human-readable result string (also the webhook log line)."""
        etype = event.get("type")
        data = event.get("data") or {}
        if etype == "order.paid":
            target = "active"
        elif etype and etype.startswith("subscription."):
            target = "active" if subscription_entitled(data.get("status")) else "inactive"
        else:
            return f"ignored type={etype}"
        acct = self.resolve_account(data)
        if acct is None:
            return f"no local account for event type={etype}"
        return self._apply(acct, target)

    # A checkout Polar considers finished. `confirmed` is the moment payment
    # succeeded; `succeeded` is the terminal state once the order is written.
    PAID_CHECKOUT_STATUSES = frozenset({"confirmed", "succeeded"})

    def confirm_checkout(self, checkout_id, acct):
        """Settle entitlement for the buyer who just came back from checkout, and
        link their Polar customer to the account.

        This does not replace the webhook; it removes the dependency on it for the
        one case the user is watching. The buyer is signed in and standing in front
        of us, so asking Polar directly whether that checkout was paid is both
        faster and immune to a webhook that is misrouted, unregistered, or
        retrying. Returns (paid, detail).
        """
        assert acct is not None, "confirm_checkout needs the signed-in account"
        if not checkout_id:
            return False, "no checkout id on the return"
        status, body = polar_api.get_checkout(checkout_id, self.token)
        if status != 200 or not isinstance(body, dict):
            log(f"get_checkout {checkout_id} failed: {status}")
            return False, f"could not read checkout {checkout_id}"
        state = body.get("status")
        customer_id = self._customer_id(body)
        if customer_id and acct.polar_customer_id != customer_id:
            acct = account.set_polar_customer_id(acct.id, customer_id)
        if state not in self.PAID_CHECKOUT_STATUSES:
            return False, f"checkout status={state}"
        return True, self._apply(acct, "active")

    def portal_url(self, acct):
        """Polar-hosted customer-portal link for one account, or None when the
        account has no linked Polar customer or the session call fails. The web
        UI only ever renders this; entitlement truth stays with the webhook and
        the poller."""
        assert acct is not None, "portal_url needs an account"
        if not acct.polar_customer_id:
            return None
        status, body = polar_api.create_customer_session(
            acct.polar_customer_id, self.token
        )
        if status not in (200, 201) or not isinstance(body, dict):
            log(f"create_customer_session for {acct.id} failed: {status}")
            return None
        return body.get("customer_portal_url")

    def entitlement_by_customer(self):
        """customer_id -> True if any of their subscriptions is entitled."""
        entitled = {}
        page = 1
        while True:
            status, body = polar_api.list_subscriptions(self.org, self.token, page=page)
            assert status == 200, f"list_subscriptions failed: {status} {body}"
            for sub in body.get("items", []):
                cid = sub.get("customer_id")
                if not cid:
                    continue
                ok = subscription_entitled(sub.get("status"))
                entitled[cid] = entitled.get(cid, False) or ok
            pag = body.get("pagination") or {}
            if page >= (pag.get("max_page") or 1):
                break
            page += 1
        return entitled

    def reconcile(self):
        """Full sweep: bring every local account's plan_status in line with Polar.
        The periodic safety net behind the instant webhook flip (catches missed
        webhooks and lapsed subscriptions)."""
        entitled = self.entitlement_by_customer()
        activated = deactivated = skipped = unmatched = 0
        for customer_id, is_entitled in entitled.items():
            acct = self.resolve_account({"customer_id": customer_id})
            if acct is None:
                unmatched += 1
                continue
            target = "active" if is_entitled else "inactive"
            if acct.plan_status == target:
                skipped += 1
                continue
            account.set_plan_status(acct.id, target)
            if target == "active":
                activated += 1
            else:
                deactivated += 1
        log(f"customers={len(entitled)} activated={activated} "
            f"deactivated={deactivated} skipped={skipped} unmatched={unmatched}")
        return {"customers": len(entitled), "activated": activated,
                "deactivated": deactivated, "skipped": skipped, "unmatched": unmatched}
