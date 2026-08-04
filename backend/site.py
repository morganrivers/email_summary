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

from dotenv import load_dotenv

from backend import paths

load_dotenv(paths.ENV_FILE)

APP_HOST = os.environ.get("LETTERLOCK_HOST", "letterlock.morganrivers.com")
API_HOST = os.environ.get("LETTERLOCK_API_HOST", "hezner.morganrivers.com")

# Hosts that only redirect to APP_HOST (a bought misspelling, an old brand).
# Comma-separated; empty until there is one to point at us.
ALIAS_HOSTS = tuple(
    h.strip() for h in os.environ.get("LETTERLOCK_ALIAS_HOSTS", "").split(",") if h.strip()
)

# Loopback ports each service binds. Caddy is the only thing in front of them.
GMAIL_PUSH_PORT = 8787
BILLING_WEBHOOK_PORT = 8788
WEB_PORT = 8790

OAUTH_CALLBACK_PATH = "/auth/callback"
POLAR_WEBHOOK_PATH = "/polar/webhook"


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


def polar_webhook_url():
    """Endpoint to register in the Polar dashboard. Caddy routes this path on
    both hosts, so either works; API_HOST is the one with DNS today."""
    return api_url(POLAR_WEBHOOK_PATH)


def pubsub_audience():
    """The `aud` claim gmail_hook_server requires of the Pub/Sub OIDC token.
    Fixed by the push subscription's configuration in Google Cloud, so changing
    API_HOST means repointing that subscription too."""
    return api_url("/")
