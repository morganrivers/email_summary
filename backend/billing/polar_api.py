"""Thin Polar API client (stdlib only).

Backend endpoints require an organization API token. Billing needs two reads --
resolve a customer's email (map a Polar customer to a local account) and list
subscriptions (poller reconcile) -- plus one write: mint a customer session so
the web UI can link a signed-in user into the Polar-hosted portal. Ported from
hetzner_signing_server/polar_api.py and trimmed to the subscription-billing
surface (no license-key endpoints).
"""

import json
import ssl
import urllib.error
import urllib.request

import certifi

_ctx = ssl.create_default_context(cafile=certifi.where())

PROD_BASE = "https://api.polar.sh"
SANDBOX_BASE = "https://sandbox-api.polar.sh"
API_BASE = PROD_BASE
_TIMEOUT = 15


def _request(method, endpoint, payload=None, token=None):
    url = f"{API_BASE}{endpoint}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json", "User-Agent": "tee-email-billing"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT, context=_ctx) as resp:
            raw = resp.read().decode("utf-8") or "{}"
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = None
        return e.code, body
    except Exception as e:
        return None, {"_transport_error": str(e)}


def get_customer(customer_id, token):
    assert token, "backend API token required to read a customer"
    return _request("GET", f"/v1/customers/{customer_id}", token=token)


def create_customer_session(customer_id, token):
    """Mint a short-lived customer session. The response carries
    customer_portal_url, the only link that authenticates a user into the
    Polar-hosted portal without us holding their billing credentials."""
    assert token, "backend API token required to create a customer session"
    assert customer_id, "customer_id required to create a customer session"
    return _request("POST", "/v1/customer-sessions/",
                    payload={"customer_id": customer_id}, token=token)


def list_subscriptions(organization_id, token, page=1, limit=100):
    assert token, "backend API token required to list subscriptions"
    ep = (f"/v1/subscriptions/?organization_id={organization_id}"
          f"&page={page}&limit={limit}")
    return _request("GET", ep, token=token)
