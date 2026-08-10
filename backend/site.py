"""Public hostnames and loopback ports of this deployment, in one place.

Every externally visible URL has to agree in three places at once: the app that
builds the link, the Caddy site block that terminates TLS for it, and whatever
third party has it registered (Google's authorized redirect URIs, the Polar
webhook endpoint, the Pub/Sub push audience). A hostname edited in two of the
three is an outage, so they all derive from here.

Two hosts, because they are provisioned separately:
  APP_HOST  -- the product: web UI, sign-in, customer-facing links.
  API_HOST  -- the original box: Gmail Pub/Sub push and the Polar webhook.

Ports live here for the same reason: Caddy proxies to them and the servers bind
them, and deploy/render_caddyfile.py renders the Caddy config from these values,
so the proxy cannot end up pointing at a port nothing is listening on.

Override any of it from .env (LETTERLOCK_HOST, LETTERLOCK_API_HOST,
LETTERLOCK_ALIAS_HOSTS) and re-render the Caddyfile.
"""

import os

from backend import secrets
from cosigner import protocol as cosigner_protocol

secrets.load()

# The Hetzner deployment, compiled in. Named rather than inlined because a
# second deployment has to be able to tell "nobody set this" from "this is the
# value someone chose": `tee_boot._host_overridden()` refuses to start an
# enclave role still minting URLs that point at the box.
DEFAULT_APP_HOST = "letterlock.morganrivers.com"
DEFAULT_API_HOST = "hezner.morganrivers.com"

APP_HOST = os.environ.get("LETTERLOCK_HOST", DEFAULT_APP_HOST)
API_HOST = os.environ.get("LETTERLOCK_API_HOST", DEFAULT_API_HOST)

# The split-custody co-signer. Its own hostname, not a path on one of the two
# above, because its site block is the only one that demands a client
# certificate: folding it into API_HOST would make Caddy ask Google's Pub/Sub
# push for one too. Today it resolves to the same box; the hostname is what
# lets it move to a different one without the enclave's client changing.
COSIGNER_HOST = os.environ.get("LETTERLOCK_COSIGNER_HOST", "cosigner.morganrivers.com")

# Hosts that only redirect to APP_HOST (a bought misspelling, an old brand).
# Comma-separated; empty until there is one to point at us.
ALIAS_HOSTS = tuple(
    h.strip() for h in os.environ.get("LETTERLOCK_ALIAS_HOSTS", "").split(",") if h.strip()
)

# Loopback ports each service binds. Caddy is the only thing in front of them.
# 8788 is deliberately skipped: another product on this box (the Kitchen Search
# license signer, /opt/ks_signer) has bound it since long before Letterlock, and
# taking it made billing-webhook crash-loop on EADDRINUSE with no entitlement
# ever reaching an account.
GMAIL_PUSH_PORT = 8787
BILLING_WEBHOOK_PORT = 8789
WEB_PORT = 8790
# The split-custody co-signer (docs/plan_token_custody.md Track J). It is the
# one service the app talks to rather than serves, and the only one that must
# not be reachable as plain HTTPS: it authenticates the enclave by client
# certificate, so its site block terminates mTLS rather than proxying anonymous
# traffic. LETTERLOCK_COSIGNER_URL overrides the whole URL for a dev box
# running it on loopback.
#
# Defined in cosigner/protocol.py, where the server that binds it lives, and
# re-exported here so render_caddyfile.py still reads every port from one
# module. The import runs backend -> cosigner and never the other way, so the
# co-signer can be deployed without backend/ present.
COSIGNER_PORT = cosigner_protocol.PORT
# The egress allowlist proxy (backend/daemons/egress_proxy.py). Caddy is not in
# front of this one and never will be: it is the only loopback port the units
# dial *outward*, not one Caddy dials inward. It is listed here anyway, because
# what this block is really for is being the one place a free port can be
# picked from -- see the 8788 collision above, which cost an entitlement path
# before anyone noticed.
EGRESS_PROXY_PORT = 8792

# The address Caddy proxies from, and so the only peer whose X-Forwarded-For an
# app server may believe. One fact, two readers: render_caddyfile.py renders the
# reverse_proxy upstreams from upstream() below, and frontend/web_server.py both
# binds this address and checks incoming peers against TRUSTED_PROXIES before
# reading the header. Kept together because they are the two halves of one
# claim -- Caddy is in front of us, over loopback, and nothing else is.
LOOPBACK = "127.0.0.1"

# Anything else in front of the app, named by address, because on the box there
# is nothing else and in the enclave there is: dstack's ingress reaches the web
# container over a docker network rather than over loopback, so the peer is that
# proxy's address and every audit row would record it instead of the browser's.
# Empty by default, and loopback is always in the set below, so this can only
# add a peer somebody named -- which is the point. An unnamed proxy costs a
# useless log entry; naming one that is not really in front of us costs a
# forgeable one, and that is a decision an operator makes deliberately.
EXTRA_TRUSTED_PROXIES = tuple(
    a.strip() for a in os.environ.get("LETTERLOCK_TRUSTED_PROXIES", "").split(",")
    if a.strip()
)
TRUSTED_PROXIES = frozenset({LOOPBACK, "::1"} | set(EXTRA_TRUSTED_PROXIES))


def upstream(port):
    """The `reverse_proxy` target for a service on `port`.

    The assert is the coupling: a peer Caddy proxies from that the app does not
    trust means every audit row records the proxy's own address instead of the
    browser's, silently and forever. Trusting the header is a decision about who
    sent it, so the two lists cannot be allowed to drift apart."""
    assert LOOPBACK in TRUSTED_PROXIES, (
        f"Caddy proxies from {LOOPBACK}, which is not in TRUSTED_PROXIES "
        f"({sorted(TRUSTED_PROXIES)}); the app would discard its X-Forwarded-For"
    )
    return f"{LOOPBACK}:{port}"


OAUTH_CALLBACK_PATH = "/auth/callback"

# Namespaced for the same reason as the port. The other product's signer serves
# the bare /polar/webhook on this host, and both products sell from one Polar
# organization, so an unqualified path means whichever service Caddy happens to
# route wins and the other silently never hears about a payment. Changing this
# means re-registering the endpoint in the Polar dashboard.
POLAR_WEBHOOK_PATH = "/letterlock/polar/webhook"

# Where Polar returns a buyer after a successful checkout. Without a success URL
# the hosted checkout ends on Polar's own receipt page and the buyer never comes
# back, which is what it did.
CHECKOUT_RETURN_PATH = "/billing/return"

# Paths on this box that belong to a different product. They are here because
# deploy/render_caddyfile.py renders the *whole* /etc/caddy/Caddyfile: anything
# absent from this module is absent from the installed config, so a route left
# out here is a route deleted from a service that has nothing to do with
# Letterlock. The Kitchen Search license signer was reachable only through the
# hezner block's /polar/webhook, meaning Letterlock's renderer was serving it by
# coincidence; naming it makes that deliberate and survives the next regenerate.
# (path, loopback port, who owns it)
CO_TENANT_ROUTES = (
    ("/polar/webhook", 8788, "Kitchen Search license signer (/opt/ks_signer)"),
)


def _url(host, path):
    assert path.startswith("/"), f"path must be absolute, got {path!r}"
    return f"https://{host}{path}"


def app_url(path="/"):
    return _url(APP_HOST, path)


def api_url(path="/"):
    return _url(API_HOST, path)


def oauth_callback_url():
    """Where Google returns the user after web sign-in. Must be registered
    verbatim as an authorized redirect URI on the OAuth client."""
    return app_url(OAUTH_CALLBACK_PATH)


def checkout_success_url():
    """Where Polar sends the buyer after payment. `{CHECKOUT_ID}` is interpolated
    by Polar, so the return handler can read the checkout back and link the
    customer without waiting for the webhook."""
    return app_url(f"{CHECKOUT_RETURN_PATH}?checkout_id={{CHECKOUT_ID}}")


def cosigner_url(path="/"):
    """Where the enclave's custody client reaches the co-signer. mTLS: the
    enclave presents its RA-TLS certificate and Caddy passes it through for
    cosigner/attest.py to verify.

    The co-signer is meant to be a different box under a different operator, so
    this is a public host and not a loopback port. LETTERLOCK_COSIGNER_URL
    overrides it on a dev box, where the co-signer is a local process with no
    Caddy in front of it."""
    assert path.startswith("/"), f"path must be absolute, got {path!r}"
    override = os.environ.get("LETTERLOCK_COSIGNER_URL", "").strip()
    if override:
        return f"{override.rstrip('/')}{path}"
    return _url(COSIGNER_HOST, path)


def pubsub_audience():
    """The `aud` claim gmail_hook_server requires of the Pub/Sub OIDC token.
    Fixed by the push subscription's configuration in Google Cloud, so changing
    API_HOST means repointing that subscription too."""
    return api_url("/")
