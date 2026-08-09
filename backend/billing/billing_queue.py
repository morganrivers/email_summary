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
    after that point no longer produces the 5xx that makes Polar retry, so this
    module retries instead: `retry()` puts a failed event back with its attempt
    count until MAX_ATTEMPTS, and the drop after that is alerted rather than
    logged. The 3-hourly `billing-poller` reconcile is still the backstop, and
    it always was: it reads entitlement from Polar's own API rather than from an
    event body. What that backstop covers is subscription status, so a dropped
    `subscription.*` event self-heals within one reconcile and a dropped
    `order.paid` for a product with no subscription does not -- see
    `PolarBilling.apply_event`.
  * Activation is no longer instant. The daemon applies on its next pass, which
    is at most WAKE_POLL_SECONDS away. The buyer standing in front of a
    checkout return page is unaffected -- `PolarBilling.confirm_checkout()`
    settles that case synchronously and deliberately does not depend on this
    path.

The receiver cannot poke the wake FIFO and this spool is not in WAKE_GROUP, so
a compromised billing receiver cannot drive mail processing.

What it can still do, and the point is that this is unchanged rather than
introduced: an entry here is applied by `PolarBilling.apply_event()`, which
reads the target out of the body. `order.paid` means active and a
`subscription.*` status decides the rest; Polar is consulted only to find
*which* account, and only in one fallback branch. So spooling
`{"type": "order.paid", ...}` flips an account active without a signature. That
was equally true when the receiver called `apply_event` itself -- the capability
moved with the code and did not grow. The thing that does check entitlement
against Polar's API is the 3-hourly `billing-poller` reconcile, and it is the
only backstop here. Do not read this module as a verification boundary.
"""

from backend import paths, secrets
from backend.billing.billing import log, webhook_secret
from backend.spool import Spool

_SPOOL = Spool("billing_queue", paths.billing_queue_gid)

# How many passes an event gets before it is dropped. The failures this covers
# are transient -- a Polar call that timed out resolving which account an event
# names, a manifest write that lost a race -- so the count is about outlasting
# one of those, not about eventually succeeding against a permanent error.
MAX_ATTEMPTS = 5


def enqueue(event):
    assert isinstance(event, dict), "a spooled event is the parsed body"
    _SPOOL.append({"event": event, "attempts": 0})


def pending():
    """Whether anything is waiting to be applied. Consumes nothing, so the
    daemon can build a `PolarBilling` before it drains and leave the events
    where they are if it cannot."""
    return _SPOOL.pending()


def drain():
    """Every event spooled since the last drain, oldest first, each paired with
    how many passes have already failed on it.

    Not deduped: two events for one customer are two facts about a timeline,
    and the second is not a repeat of the first.

    The count is paired with the event rather than kept in a table beside the
    spool, because the spool is the only thing a crash leaves behind: a counter
    anywhere else is a counter that disagrees with the file after a restart."""
    out = []
    for entry in _SPOOL.drain():
        event = entry.get("event")
        if not isinstance(event, dict):
            continue
        attempts = entry.get("attempts")
        out.append((event, attempts if isinstance(attempts, int) and attempts >= 0 else 0))
    return out


def retry(event, attempts):
    """Put a failed event back for the next pass, unless it is out of attempts.

    Returns whether it was re-spooled, so the caller alerts on the drop and not
    on every failure -- a transient failure that the next pass settles is not
    something to wake anyone for, and one that never settles must not be a log
    line nobody reads.

    The event goes to the tail, so a retry is applied after anything spooled
    while it was failing. That reordering is deliberate rather than unnoticed:
    holding a failed event at the head would stall every later event behind the
    one thing that cannot be applied, and the events that reorder here are, by
    construction, ones already known not to have taken effect."""
    assert isinstance(event, dict), "retry takes the event, not the spool entry"
    assert isinstance(attempts, int) and attempts >= 0, "attempts comes from drain()"
    if attempts + 1 >= MAX_ATTEMPTS:
        return False
    _SPOOL.append({"event": event, "attempts": attempts + 1})
    return True


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
