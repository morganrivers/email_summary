"""Periodic Polar -> account reconcile, every three hours.

Called by backend/daemons/scheduler.py on a thread in the mail daemon, in both
deployments. billing-poller.service is the same entry point for an operator
running it by hand.

The buyer watching a checkout return page is settled synchronously by
`PolarBilling.confirm_checkout`, and a webhook event is applied by the daemon
within one pass of its loop; this sweep is the safety net under both, catching a
webhook never delivered, one dropped after its retries, and a lapse that fires
no event we receive. In the enclave it is more than a safety net: no image
starts a Polar receiver, so a renewal and a cancellation reach an account here
or not at all. Ported from hetzner_signing_server/poller.py, with the
license-key reconcile swapped for a subscription reconcile. The per-customer
decision lives in billing.PolarBilling.
"""

import execguard
from backend import secrets
from backend.billing.billing import PolarBilling


def main():
    b = PolarBilling()
    b.log_startup("billing-poller")
    b.reconcile()


if __name__ == "__main__":
    # This block runs only when an operator starts the job by hand; the schedule
    # calls main() in a process that already has both. No procwatch, because a
    # hand-started job is a second process in whatever it is started in and
    # would refuse itself; the guard is still installed, because it is a process
    # an attacker would rather be inside than a watched one.
    execguard.lock_down(secrets.tee_required())
    main()
