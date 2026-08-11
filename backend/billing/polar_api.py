"""Thin Polar API client.

Backend endpoints require an organization API token. Billing needs two reads --
resolve a customer's email (map a Polar customer to a local account) and list
subscriptions (poller reconcile) -- plus one write: mint a customer session so
the web UI can link a signed-in user into the Polar-hosted portal. Ported from
hetzner_signing_server/polar_api.py and trimmed to the subscription-billing
surface (no license-key endpoints).

The transport is `backend/http_client.py` rather than `urlopen`, which is also
where the certifi bundle now comes from: this module used to build its own SSL
context, which was the better of the two CA policies on the box and still one of
two.
"""

import os
import re
import urllib.parse

from backend import http_client

# The shape of every Polar object id this client puts in a request path. Polar
# mints UUIDs today, but the point is not the format: it is that an id is one
# path segment and nothing else. Deliberately wider than a UUID so a future id
# format does not break billing, and narrow enough that `/`, `?`, `#`, `..` and
# whitespace are all out -- the three ids below are interpolated into a URL, and
# one of them arrives in a query string the buyer's browser controls.
ID = re.compile(r"\A[A-Za-z0-9_-]{1,128}\Z")

PROD_BASE = "https://api.polar.sh"
SANDBOX_BASE = "https://sandbox-api.polar.sh"
_TIMEOUT = 15


def sandbox_enabled():
    """The one read of the POLAR_SANDBOX toggle, so the API base, the tokens,
    the webhook secret, and the checkout link can never disagree about which
    Polar environment this box is talking to."""
    return os.environ.get("POLAR_SANDBOX", "0") == "1"


def api_base():
    """Which Polar deployment a request goes to, answered per call.

    This used to be a module global assigned in PolarBilling.__init__, which
    made every request depend on whether anyone had constructed one yet.
    checkout_url() does not, so it minted checkouts against production with a
    sandbox token, took the 403 as "Polar is unavailable", and quietly handed
    the buyer a static link with no success URL."""
    return SANDBOX_BASE if sandbox_enabled() else PROD_BASE


def valid_id(value):
    """Whether `value` is usable as a Polar object id. The one definition, so
    the caller refusing browser input and the client building the path agree
    about what an id is."""
    return isinstance(value, str) and bool(ID.match(value))


def _segment(value, what):
    """One percent-encoded path segment, asserted into shape first.

    Both halves, and neither is redundant. The assert is the invariant: every
    caller here is handed an id by Polar or by our own manifest, so a value
    that is not one is our bug. The encoding is what makes the assert the only
    thing standing between a malformed id and a request to some other endpoint
    -- ``f"/v1/checkouts/{checkout_id}"`` with a `?` in it appends a query to a
    call carrying an organization-wide token, and with a `../` in it names a
    different resource entirely. Callers taking the value from outside refuse
    it by name first; this is the floor under all of them."""
    assert valid_id(value), f"{what} is not a Polar id"
    return urllib.parse.quote(value, safe="")


def _request(method, endpoint, payload=None, token=None):
    """`(status, body)`, with a status of None when the request never happened.

    A refused call is a status and a body here rather than an exception, because
    every caller in `billing.py` decides on the status: a 404 for a customer is
    an answer, and only an outage is not."""
    headers = {"Accept": "application/json", "User-Agent": "tee-email-billing"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = http_client.request(
            method, f"{api_base()}{endpoint}", timeout=_TIMEOUT,
            headers=headers, json=payload,
        )
    except (http_client.TransportError, http_client.InsecureRequest) as e:
        return None, {"_transport_error": str(e)}
    try:
        return resp.status_code, resp.json()
    except ValueError:
        # An endpoint that answers with no body at all (a 204, a session that
        # returns headers only) is a success with nothing in it; a body that
        # does not parse is not, and stays None the way a refusal's does.
        return resp.status_code, ({} if not resp.content else None)


def get_customer(customer_id, token):
    assert token, "backend API token required to read a customer"
    return _request("GET", f"/v1/customers/{_segment(customer_id, 'customer_id')}",
                    token=token)


def create_checkout(product_id, success_url, customer_email, token, metadata=None):
    """Mint a hosted checkout session. Preferred over a static dashboard checkout
    link because the success URL then comes from backend/site.py rather than a
    field in the Polar dashboard, so the app and the place Polar returns the buyer
    to cannot drift apart. The response carries `url` (where to send the buyer)
    and `id`.

    `metadata` is echoed on the checkout when it is read back and copied onto the
    order and subscription it produces. The buyer never sees it, unlike
    customer_email, which is an editable field on Polar's own form."""
    assert token, "backend API token required to create a checkout"
    assert product_id, "product_id required to create a checkout"
    assert success_url, "success_url required to create a checkout"
    payload = {"products": [product_id], "success_url": success_url}
    if customer_email:
        payload["customer_email"] = customer_email
    if metadata:
        assert all(isinstance(v, str) for v in metadata.values()), (
            "Polar metadata values must be strings"
        )
        payload["metadata"] = metadata
    return _request("POST", "/v1/checkouts/", payload=payload, token=token)


def get_checkout(checkout_id, token):
    """Read a checkout back after the buyer returns, for its status and the
    customer it created.

    The id reaches this call from `?checkout_id=` on the return page, so
    `confirm_checkout` refuses one that is not `valid_id` before getting here
    and `_segment` is the second check of the same fact."""
    assert token, "backend API token required to read a checkout"
    return _request("GET", f"/v1/checkouts/{_segment(checkout_id, 'checkout_id')}",
                    token=token)


def create_customer_session(customer_id, token):
    """Mint a short-lived customer session. The response carries
    customer_portal_url, the only link that authenticates a user into the
    Polar-hosted portal without us holding their billing credentials."""
    assert token, "backend API token required to create a customer session"
    assert customer_id, "customer_id required to create a customer session"
    return _request("POST", "/v1/customer-sessions/",
                    payload={"customer_id": customer_id}, token=token)


def list_subscriptions(organization_id, token, page=1, limit=100):
    """One page of the organization's subscriptions. The query is built with
    `urlencode` rather than an f-string for the same reason the path segments
    are quoted: an id is a value, not a fragment of URL syntax."""
    assert token, "backend API token required to list subscriptions"
    assert valid_id(organization_id), "organization_id is not a Polar id"
    query = urllib.parse.urlencode({"organization_id": organization_id,
                                    "page": int(page), "limit": int(limit)})
    return _request("GET", f"/v1/subscriptions/?{query}", token=token)
