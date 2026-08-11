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

from backend import secrets, site
from backend.accounts import account
from backend.billing import polar_api

secrets.load()

ENTITLED_SUB_STATUSES = frozenset({"active", "trialing"})

# What the Polar product charges, in euros. Every page that quotes a price reads
# this one name: the landing copy, the pricing page, the comparison table, the
# sign-up button and the billing table each carried their own literal, and they
# drifted from the product until a buyer was quoted one figure and charged
# another. Polar remains the authority that actually bills; changing the product
# there means changing this line too.
PLAN_PRICE_EUR = 25

# The metadata key every checkout we mint is stamped with, naming the account it
# was created for. It is the exact binding the rest of the billing surface lacked:
# customer_email is a form field the buyer edits at Polar, and the checkout id
# travels back in a query string the buyer controls, so neither says whose
# checkout it is. Polar copies checkout metadata onto the resulting order and
# subscription, so the webhook resolves through the same key as the return trip.
CHECKOUT_ACCOUNT_KEY = "account_id"


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
    path cannot guarantee they come back to us.

    It also carries no CHECKOUT_ACCOUNT_KEY stamp -- there is no API call to
    stamp -- so everything downstream falls back to resolving by
    `customer_email`, a field the buyer edits at Polar. That is exactly the
    surface the stamp was added to close, reached automatically on any transient
    Polar failure.

    So it is refused inside the enclave, where there is no operator to notice
    the difference and `/billing/checkout` already renders "checkout unavailable,
    try again". On the box it stays, because a checkout the user can complete
    beats no checkout at all and `resolve_account` will not let an unstamped
    object move a link that already exists."""
    if secrets.tee_required():
        log("no API checkout; refusing the unstamped static link under TEE_REQUIRED")
        return fallback
    base = select_env("POLAR_CHECKOUT_URL", sandbox_enabled())
    if not base:
        return fallback
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}customer_email={urllib.parse.quote(email)}"


def checkout_url(email, fallback="/dashboard"):
    """Where to send a user to pay, and the id of the checkout minted for them.
    Shared by the web app and the onboarding flow; both used to carry their own
    copy of this.

    Returns `(url, checkout_id)`. The id is None on the static fallback, which
    mints nothing to name; a caller uses it to record in the buyer's browser
    which checkout it started, so the return trip can be bound to the browser
    rather than only to the account.

    Prefers a checkout session minted through the API, because that carries
    site.checkout_success_url() and so brings the buyer back to us afterwards. A
    static dashboard link ends on Polar's own receipt page unless someone
    remembers to fill in a success-URL field, which is exactly how a paid buyer
    got stranded there.

    The session is stamped with CHECKOUT_ACCOUNT_KEY, which is what makes the
    return trip verifiable: PolarBilling.confirm_checkout resolves the checkout
    back to an account and refuses one that is not the buyer's."""
    assert email, "checkout_url needs the account the checkout is minted for"
    pid = product_id()
    if not pid:
        return _static_checkout_url(email, fallback), None
    try:
        token = select_env("POLAR_API_TOKEN", sandbox_enabled())
        status, body = polar_api.create_checkout(
            pid, site.checkout_success_url(), email, token,
            metadata={CHECKOUT_ACCOUNT_KEY: email},
        )
    except AssertionError as err:
        log(f"checkout session unavailable ({err}); using the static link")
        return _static_checkout_url(email, fallback), None
    if status not in (200, 201) or not isinstance(body, dict) or not body.get("url"):
        log(f"create_checkout failed: {status} {body}; using the static link")
        return _static_checkout_url(email, fallback), None
    return body["url"], body.get("id")


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
        """The one line that says which Polar this process is talking to and
        which secrets it captured. Both values are fingerprinted rather than
        masked: a prefix and four trailing characters identify a token no
        better than a digest does, and the digest also covers the webhook
        secret, whose absence from this line is what made a stale ``.env``
        indistinguishable from a bad signature at the endpoint."""
        log(f"{who} env={'SANDBOX' if self.sandbox else 'PRODUCTION'} "
            f"base={polar_api.api_base()} org={self.org} "
            f"token={secrets.fingerprint(self.token)} "
            f"webhook_secret={secrets.fingerprint(webhook_secret())}")

    @staticmethod
    def _customer_id(data):
        return data.get("customer_id") or (data.get("customer") or {}).get("id")

    @staticmethod
    def _event_email(data):
        cust = data.get("customer") or {}
        return (cust.get("email") or data.get("customer_email")
                or (data.get("user") or {}).get("email"))

    @staticmethod
    def _order_subscription(data):
        """The subscription a paid order belongs to, or None for a one-off
        purchase. Only `reconcile` cares: entitlement it can re-derive is
        entitlement a lost event costs nothing."""
        return data.get("subscription_id") or (data.get("subscription") or {}).get("id")

    def _customer_email(self, customer_id):
        status, body = polar_api.get_customer(customer_id, self.token)
        if status != 200 or not isinstance(body, dict):
            log(f"get_customer {customer_id} failed: {status}")
            return None
        return body.get("email")

    @staticmethod
    def _stamped_account(data):
        """The account named in the object's CHECKOUT_ACCOUNT_KEY metadata, or
        None. Exact by construction: we wrote it when we minted the checkout."""
        stamped = (data.get("metadata") or {}).get(CHECKOUT_ACCOUNT_KEY)
        if not stamped:
            return None
        return account.account_for_email(str(stamped), include_inactive=True)

    def resolve_account(self, data):
        """Map a Polar object (webhook event data, or a checkout read back) to a
        local account, including inactive ones.

        Ordered most exact first: the account id we stamped into the checkout's
        metadata, then the stored polar_customer_id link, then an email carried
        in the object, then an email fetched from Polar. Every step resolves
        *from* Polar's copy *to* an account and never the reverse, which is what
        lets confirm_checkout use the answer as an ownership test rather than
        trusting the id the browser handed it."""
        stamped = self._stamped_account(data)
        if stamped is not None:
            return stamped
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
        by_email = account.account_for_email(email, include_inactive=True)
        # The email branch is the weak one: `customer_email` is a form field the
        # buyer edits at Polar, and only an unstamped object ever reaches here
        # (the static checkout link, which mints nothing to stamp). It may
        # introduce a link, never move one. An account that already names a
        # different Polar customer was linked by something exact, and letting a
        # buyer-typed address override that is how one person's checkout claims
        # another's subscription.
        if (by_email is not None and cid and by_email.polar_customer_id
                and by_email.polar_customer_id != cid):
            log(f"refusing to resolve customer={cid} to {by_email.id} by email: "
                f"that account is already linked to another Polar customer")
            return None
        return by_email

    def _apply(self, acct, target):
        assert target in ("active", "inactive")
        if acct.plan_status == target:
            return f"account={acct.id} already {target}"
        prior = account.set_plan_status(acct.id, target)
        return f"account={acct.id} {prior}->{target}"

    def apply_event(self, event):
        """Decide active/inactive from one webhook event and flip the account.
        Returns a human-readable result string (also the webhook log line).

        The result carries *why* the target was chosen, because the event name
        and the outcome routinely disagree: Polar fires ``subscription.canceled``
        the moment a cancellation is scheduled, while the subscription stays
        entitled until the period closes, so that event legitimately reads
        ``inactive->active``. A log line saying only "canceled -> active" is the
        kind of thing that gets read as a bug, or worse, trusted as a
        deactivation that never happened."""
        assert isinstance(event, dict), "apply_event needs the parsed event"
        etype = event.get("type")
        data = event.get("data") or {}
        if etype == "order.paid":
            target, why = "active", "order.paid"
            if not self._order_subscription(data):
                # Every other grant this system makes is re-derivable from
                # Polar: `reconcile` reads subscription status and fixes an
                # event that was lost, misrouted or never sent. A paid order
                # with no subscription is the one grant that is not, because
                # `entitlement_by_customer` lists subscriptions and this
                # customer has none, so the event is the only record that this
                # account should be active. Said out loud rather than refused:
                # a one-off product is a decision someone may make in the Polar
                # dashboard, and the thing to know is that its entitlement
                # rests on one delivery instead of on a periodic sweep.
                log("order.paid carries no subscription; the grant for "
                    f"customer={self._customer_id(data)} is not reconcilable")
        elif etype and etype.startswith("subscription."):
            status = data.get("status")
            target = "active" if subscription_entitled(status) else "inactive"
            why = (f"status={status} "
                   f"cancel_at_period_end={bool(data.get('cancel_at_period_end'))}")
        else:
            return f"ignored type={etype}"
        acct = self.resolve_account(data)
        if acct is None:
            return f"no local account for event type={etype} ({why})"
        return f"{self._apply(acct, target)} ({why})"

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

        `checkout_id` arrives in a query string the browser controls, so the
        first thing done with it is an ownership test: Polar's copy of that
        checkout must resolve back to the signed-in account. Without it any
        signed-in user who learned a paid checkout id took its subscription for
        free, and the customer link below then pointed portal_url() at someone
        else's Polar customer. A checkout that resolves to nobody is refused
        too: the webhook settles that case, and the return page already tells a
        buyer whose flip is still in flight to wait rather than that they failed.
        """
        assert acct is not None, "confirm_checkout needs the signed-in account"
        if not checkout_id:
            return False, "no checkout id on the return"
        if not polar_api.valid_id(checkout_id):
            # A refusal by name and not an assert: this value came off a query
            # string, so a bad one is a hostile or mistyped input rather than a
            # bug of ours. It goes into the path of a request carrying an
            # organization-wide token, and the reason it is refused here rather
            # than left to the encoding in `polar_api._segment` is that the
            # honest answer to a malformed id is "that is not a checkout",
            # answered without spending an API call to hear Polar say so.
            log(f"refusing malformed checkout id from {acct.id}")
            return False, "that is not a checkout id"
        status, body = polar_api.get_checkout(checkout_id, self.token)
        if status != 200 or not isinstance(body, dict):
            log(f"get_checkout {checkout_id} failed: {status}")
            return False, f"could not read checkout {checkout_id}"
        owner = self.resolve_account(body)
        if owner is None or owner.id != acct.id:
            log(f"checkout {checkout_id} resolves to "
                f"{owner.id if owner else 'no account'}, not {acct.id}; refusing")
            return False, "that checkout does not belong to this account"
        state = body.get("status")
        if state not in self.PAID_CHECKOUT_STATUSES:
            return False, f"checkout status={state}"
        # After the paid check, never before it. An open checkout is enough to
        # reach this function -- mint one through /billing/checkout so the
        # ownership test above passes, then type a victim's address on Polar's
        # page so Polar attaches its existing customer to it, then come back.
        # Linking first moved that customer onto the attacker's account, and
        # `portal_url()` then mints a Polar customer-portal session for it:
        # payment methods, invoices, cancellation. `set_polar_customer_id`
        # refuses a customer another account already holds, which is the other
        # half; this ordering is what stops an unpaid checkout being a way to
        # claim an unlinked one.
        customer_id = self._customer_id(body)
        if customer_id and acct.polar_customer_id != customer_id:
            try:
                acct = account.set_polar_customer_id(acct.id, customer_id)
            except account.InvalidAccountData as err:
                log(f"checkout {checkout_id}: {err}")
                return False, "that Polar customer belongs to another account"
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
        """Full sweep: bring plan_status in line with Polar for every customer
        Polar names. The periodic safety net behind the two paths that settle a
        single account -- `confirm_checkout` for the buyer on the return page,
        and a webhook event the daemon applies -- catching a webhook that was
        never delivered, one dropped after its retries, and a lapse that fires
        no event anyone is listening for.

        Scope, because it is narrower than "every local account": this iterates
        Polar's subscriptions, so an account Polar has never heard of is left
        exactly as it is. That is what keeps the sweep from deactivating the
        accounts entitled by something other than a purchase -- the seeded owner
        above all -- and it is also why a grant with no subscription behind it
        is not repaired here. `list_subscriptions` passes no status filter, so a
        canceled subscription is still returned and still deactivates."""
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
