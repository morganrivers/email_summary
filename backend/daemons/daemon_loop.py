#!/usr/bin/env python3
"""Always-on email-drafter daemon.

Blocks on a FIFO for wake signals from gmail_hook_server. On wake, fetches new
emails via state.lastHistoryId and runs them through manual_draft /
draft_replies.

The webhook runs under its own uid, so the FIFO goes through paths.wake_file():
0660 to paths.WAKE_GROUP, whose only members are this unit and that one. It was
0666 back when the webhook was PHP, and 0600 while both ran as one account.
Neither is right now, and neither is the group holding the rest of state/ --
waking this daemon starts work against a named account and the web tier is in
that wider group.

A re-wake during processing is fine: the webhook spools the address to
wake_queue before poking the FIFO, and the read end stays open for the whole
process lifetime so a poke during processing is never refused.
"""

import os
import select
import signal
import stat
import sys
import time
import traceback

from backend import audit, paths, secrets
from backend.accounts import account as account_mod
from backend.billing import billing_queue
from backend.billing.billing import PolarBilling
from backend.custody import handoff_server
from backend.daemons import pipeline, wake_queue
from backend.integrations.telegram import notify_error

secrets.load()

FIFO_PATH = paths.RUN_DIR / "wake.fifo"
RESTART_FLAG = paths.RUN_DIR / "restart.flag"

WAKE_POLL_SECONDS = 300


def log(msg):
    sys.stdout.write(f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] {msg}\n")
    sys.stdout.flush()


def ensure_fifo():
    paths.ensure_run_dir()
    if FIFO_PATH.exists():
        if not stat.S_ISFIFO(FIFO_PATH.stat().st_mode):
            FIFO_PATH.unlink()
    if not FIFO_PATH.exists():
        os.mkfifo(str(FIFO_PATH), paths.FILE_MODE_PRIVATE)
    paths.wake_file(FIFO_PATH)


def _run_account(acct):
    """One account's pass, and one account's failure. Whatever goes wrong for
    this mailbox must not end the sweep: on a multi-tenant box that would let
    one lapsed grant or one Gmail outage stop drafting for everybody else."""
    try:
        pipeline.process_account(
            acct,
            log=log,
            notify_err=lambda ctx, err, a=acct: notify_error(ctx, err, a.telegram),
        )
    except Exception as err:
        log(f"{acct.id}: {err}\n{traceback.format_exc()}")
        notify_error(f"processing failed for {acct.id}", err, acct.telegram)


def process_all():
    for acct in account_mod.load_accounts():
        _run_account(acct)


def process_billing():
    """Apply whatever the Polar receiver spooled since the last pass.

    Here rather than in that receiver because flipping a plan means writing the
    account manifest, and the process verifying signatures from the open
    internet must not hold that. `PolarBilling` is constructed only when there
    is something to apply, so a box with no Polar token configured pays nothing
    for this call. One event's failure does not stop the rest, for the same
    reason one mailbox's does not.

    The client is built before the drain and not after. `drain()` clears the
    spool, so a `PolarBilling()` that raises on the far side of it discards
    every event it was about to apply -- silently, since the exception lands in
    the loop's outer handler, and permanently on a box where the poller cannot
    run either because it needs the same absent token.

    An event that raises is put back rather than dropped. Polar was acked when
    the receiver spooled it, so nothing upstream will send it again: without the
    retry, one timed-out Polar call while resolving which account an event names
    was a subscription that stayed unapplied until the next reconcile, and one
    that the reconcile does not cover was a subscription that stayed unapplied.
    Only the drop after MAX_ATTEMPTS alerts, because a failure the next pass
    settles is not one to wake anybody for."""
    if not billing_queue.pending():
        return
    try:
        billing = PolarBilling()
    except AssertionError as err:
        log(f"billing events waiting but Polar is not configured: {err}")
        return
    for event, attempts in billing_queue.drain():
        try:
            log(f"billing: {billing.apply_event(event)}")
        except Exception as err:
            log(f"billing event {event.get('type')!r} failed "
                f"(attempt {attempts + 1}/{billing_queue.MAX_ATTEMPTS}): {err}")
            if not billing_queue.retry(event, attempts):
                notify_error(
                    f"billing event {event.get('type')!r} dropped after "
                    f"{billing_queue.MAX_ATTEMPTS} attempts", err)


def prune_audit():
    """Age out the web tier's audit rows on this pass, at most once an hour.

    Here because the rows age out on a clock and the only thing that pruned
    them was writing another one, so a box nobody signed in to kept a departed
    user's address past the retention period that module documents. This loop
    runs whether or not a person does anything.

    A failure logs and does not propagate, for the same reason
    `cosigner/retention.py` never takes that service down: a log that grew too
    long is a smaller problem than a drafting pass that stopped, and nothing
    here decides anything."""
    try:
        removed = audit.maybe_prune()
        if removed:
            log(f"audit: pruned {removed} row(s) older than "
                f"{audit.RETENTION_DAYS}d")
    except Exception as err:
        log(f"audit prune failed: {type(err).__name__}: {err}")


def process_accounts(ids):
    for aid in ids:
        acct = account_mod.get_account(aid)
        if acct is None:
            log(f"queued account {aid!r} not registered/active; skipping")
            continue
        _run_account(acct)


def open_fifo_reader():
    """Open the read end once, for the lifetime of the process.

    A writer's O_WRONLY|O_NONBLOCK open fails ENXIO whenever no process holds
    the FIFO open for reading, so opening it per-wake silently refused every
    push that arrived while process_once() was running. Holding it open removes
    that window entirely. The extra write fd is never written to; it exists so
    poll() cannot see POLLHUP (and spin) when the webhook closes its own end."""
    fd = os.open(str(FIFO_PATH), os.O_RDONLY | os.O_NONBLOCK)
    keepalive = os.open(str(FIFO_PATH), os.O_WRONLY | os.O_NONBLOCK)
    assert stat.S_ISFIFO(os.fstat(fd).st_mode), f"{FIFO_PATH} is not a FIFO"
    return fd, keepalive


def wait_for_wake(fd, timeout=WAKE_POLL_SECONDS):
    """Wait for a wake byte, giving up after timeout seconds. Returns True when
    woken by a signal, False on timeout. All pending bytes are drained so a
    burst of pokes coalesces into a single processing pass. The timeout is the
    backstop: it re-checks the spool and restart.flag even if no poke lands."""
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    if not poller.poll(timeout * 1000):
        return False
    while True:
        try:
            if not os.read(fd, 4096):
                break
        except BlockingIOError:
            break
    return True


def main():
    ensure_fifo()
    fd, _keepalive = open_fifo_reader()
    # Before the sweep, not after: the sweep can run for minutes and the web
    # tier cannot complete a sign-in until this socket exists.
    handoff_server.start(log)
    log(f"daemon started; FIFO={FIFO_PATH} poll={WAKE_POLL_SECONDS}s")
    # Bootstrap at startup: drain any queued pushes, then sweep all accounts
    # in case a push arrived while the daemon was down.
    try:
        process_billing()
        process_accounts(wake_queue.drain())
        process_all()
    except Exception as err:
        log(f"startup sweep failed: {err}")
        traceback.print_exc(file=sys.stdout)
        notify_error("startup sweep failed", err)
    while True:
        try:
            woken = wait_for_wake(fd)
            if RESTART_FLAG.exists():
                log("restart.flag present, exiting for clean restart")
                try:
                    RESTART_FLAG.unlink()
                except FileNotFoundError:
                    pass
                sys.exit(0)
            # Before the mail work, so an activation that arrived while the
            # last pass ran is in force for this one: an account flipped to
            # active is an account this sweep should process.
            process_billing()
            prune_audit()
            ids = wake_queue.drain()
            if ids:
                log(f"routed wake for {len(ids)} account(s): {ids}")
                process_accounts(ids)
            elif woken:
                log("wake with empty queue; sweeping all accounts")
                process_all()
        except SystemExit:
            raise
        except Exception as err:
            log(f"loop error: {err}")
            traceback.print_exc(file=sys.stdout)
            notify_error("daemon loop error", err)
            time.sleep(1)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    main()
