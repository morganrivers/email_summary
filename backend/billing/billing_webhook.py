"""Polar subscription webhook -> spooled account activation/deactivation.

Ported from hetzner_signing_server/webhook.py. Verifies the Standard Webhooks
signature, then hands the event to `billing_queue` for the daemon to apply. It
used to call billing.PolarBilling.apply_event here and flip plan_status itself;
read that module's docstring for why a signature verifier does not write the
account store, and what deferring costs.

Runs as a long-lived loopback http.server under its own account
(deploy/hetzner/billing-webhook.service.d); Caddy terminates TLS and
reverse-proxies /polar/webhook here. Per CLAUDE.md, the Caddy config is updated
by hand, not by deploy.sh.

Polar quirk (same as the source): the dashboard webhook secret must be
base64-encoded before handing it to the standardwebhooks verifier (Polar stores
it raw, the library expects a base64 secret).
"""

import base64
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from standardwebhooks import Webhook

from backend import site
from backend.billing.billing import log, webhook_secret
from backend.billing.billing_queue import DeferredBilling

WEBHOOK_PATH = site.POLAR_WEBHOOK_PATH
_SIG_HEADERS = ("webhook-id", "webhook-timestamp", "webhook-signature")

# A Polar event payload is small; the endpoint is public and unauthenticated
# until the signature check, so the declared length is bounded before the read.
MAX_BODY = 256 * 1024


def process_webhook(raw, headers, verifier, billing):
    """Pure decision path for one webhook POST, shared by do_POST and the tests.
    Returns (http_status, json_body_str). Verifies the signature, then hands the
    event to `billing`, which spools it for the daemon.

    Still exactly one call after the verify, which is the property the AST test
    in tests/test_billing_webhook.py pins: an event reaches the rest of the
    system through this function or not at all."""
    try:
        # verify() raises on a bad/absent signature and returns the payload.
        event = verifier.verify(raw, headers)
    except Exception as e:
        log(f"webhook rejected: bad signature ({e})")
        return 400, '{"error":"invalid signature"}'

    if not isinstance(event, dict):
        try:
            event = json.loads(raw)
        except Exception:
            event = {}

    try:
        result = billing.apply_event(event)
    except Exception as e:
        # 5xx tells Polar to retry. The only failure left here is the spool
        # write itself, since applying the event moved to the daemon; a retry
        # is the right answer to a full disk and costs nothing otherwise.
        log(f"webhook spool failed type={event.get('type')}: {e}")
        return 500, '{"error":"apply failed"}'

    log(f"webhook {event.get('type')} -> {result}")
    return 200, '{"status":"ok"}'


class Handler(BaseHTTPRequestHandler):
    billing = None      # DeferredBilling, set in main()
    verifier = None     # standardwebhooks.Webhook, set in main()

    def _reply(self, code, msg="{}"):
        body = msg.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # silence default stderr access logging; we log deliberately

    def do_POST(self):
        if self.path.rstrip("/") != WEBHOOK_PATH:
            return self._reply(404, '{"error":"not found"}')

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._reply(400, '{"error":"bad content-length"}')
        if length < 0 or length > MAX_BODY:
            return self._reply(413, '{"error":"body too large"}')
        raw = self.rfile.read(length) if length else b""

        headers = {h: self.headers.get(h, "") for h in _SIG_HEADERS}
        status, body = process_webhook(raw, headers, self.verifier, self.billing)
        return self._reply(status, body)


def main():
    Handler.billing = DeferredBilling()
    Handler.billing.log_startup("billing-webhook")
    secret = webhook_secret()
    if not secret:
        # A startup refusal, not an invariant: without it the verifier is built
        # over an empty secret and every unsigned body verifies. SystemExit so
        # the unit fails to start; deploy/preflight.py already reports it.
        raise SystemExit("POLAR_WEBHOOK_SECRET required")
    Handler.verifier = Webhook(base64.b64encode(secret.encode("utf-8")).decode("utf-8"))

    host = os.environ.get("BILLING_WEBHOOK_HOST", "127.0.0.1")
    port = int(os.environ.get("BILLING_WEBHOOK_PORT", str(site.BILLING_WEBHOOK_PORT)))
    server = ThreadingHTTPServer((host, port), Handler)
    log(f"billing-webhook listening on {host}:{port}{WEBHOOK_PATH}")
    server.serve_forever()


if __name__ == "__main__":
    main()
