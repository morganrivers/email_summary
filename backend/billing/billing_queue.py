"""The spool between the Polar receiver and the process that applies an event.

`billing_webhook.py` used to flip an account's plan_status itself. That made a
program whose whole job is verifying one signature also a writer of
`database/accounts.json`, from a uid reachable through the open internet.

Not a path to mail content: the one field that was, the telegram target, is
behind `accounts/chat_link.py` and its proof from the chat being replaced. What
a manifest writer still has is every account's plan (activate itself, deactivate
everyone else), the Polar customer link, and the ability to corrupt the store
outright. None of that is any part of settling a subscription, and the write is
cheap to remove because the receiver does not need one.

So the receiver verifies and appends, and `daemon_loop` applies. The receiver
now touches no account data at all, holds no Polar API token, and reads one
secret: the webhook signing key in `.env.billing`.

What this costs, stated because it is a change in behaviour and not only in
permissions:

  * Polar is acked once the event is spooled, not once it is applied. A failure
    after that point no longer produces the 5xx that makes Polar retry. The
    3-hourly `billing-poller` reconcile is the backstop, and it always was: it
    reads entitlement from Polar's own API rather than from an event body.
  * Activation is no longer instant. The daemon applies on its next pass, which
    is at most WAKE_POLL_SECONDS away. The buyer standing in front of a
    checkout return page is unaffected -- `PolarBilling.confirm_checkout()`
    settles that case synchronously and deliberately does not depend on this
    path.

The receiver cannot poke the wake FIFO and this spool is not in WAKE_GROUP, so
a compromised billing receiver cannot drive mail processing. It can write
entries the daemon will read, and the daemon answers each by asking Polar what
is true rather than believing the body.
"""

from backend import paths, secrets
from backend.billing.billing import log, webhook_secret
from backend.spool import Spool

_SPOOL = Spool("billing_queue", paths.billing_queue_gid)


def enqueue(event):
    assert isinstance(event, dict), "a spooled event is the parsed body"
    _SPOOL.append({"event": event})


def drain():
    """Every event spooled since the last drain, oldest first.

    Not deduped: two events for one customer are two facts about a timeline,
    and the second is not a repeat of the first."""
    return [e["event"] for e in _SPOOL.drain() if isinstance(e.get("event"), dict)]


class DeferredBilling:
    """What the receiver holds where it used to hold a `PolarBilling`.

    Same `apply_event` name because `process_webhook` is the one verified path
    and must keep calling exactly one thing; what changed is that the call now
    ends at a file instead of at the account store."""

    def log_startup(self, who):
        log(f"{who} deferring events to the daemon; "
            f"webhook_secret={secrets.fingerprint(webhook_secret())}")

    def apply_event(self, event):
        enqueue(event)
        return f"spooled type={event.get('type')}"
