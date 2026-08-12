"""Periodic Polar -> account reconcile. Runs on the billing-poller.timer on the
box and on the mail role's crontab in the enclave.

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
    # No procwatch: this is one of the mail container's scheduled jobs and the
    # daemon beside it is what watches that container. The guard is still
    # installed, because a scheduled job is a process an attacker would rather
    # be inside than the one being watched.
    execguard.lock_down(secrets.tee_required())
    main()
