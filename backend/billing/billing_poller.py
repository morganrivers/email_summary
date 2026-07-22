"""Periodic Polar -> account reconcile. Runs on the billing-poller.timer.

Instant activation on purchase is handled by billing_webhook.py; this poller is
the periodic safety net that catches missed webhooks and lapsed subscriptions,
bringing every local account's plan_status in line with Polar. Ported from
hetzner_signing_server/poller.py, with the license-key reconcile swapped for a
subscription reconcile. The per-customer decision lives in billing.PolarBilling.
"""

from backend.billing.billing import PolarBilling


def main():
    b = PolarBilling()
    b.log_startup("billing-poller")
    b.reconcile()


if __name__ == "__main__":
    main()
