#!/usr/bin/env python3
"""Always-on email-drafter daemon.

Blocks on a FIFO for wake signals from gmail_hook_server. On wake, fetches new
emails via state.lastHistoryId and runs them through manual_draft /
draft_replies.

The webhook runs as the same user under systemd, so the FIFO is 0600. It was
0666 back when the webhook was PHP running as a different user; leaving it world
-writable now just lets any local account wake the daemon.

A re-wake during processing is fine: the webhook spools the account id to
wake_queue before poking the FIFO, and the read end stays open for the whole
process lifetime so a poke during processing is never refused.
"""

import os
import sys
import stat
import time
import select
import signal
import traceback
from pathlib import Path

from backend import paths
from backend import secrets
from backend.accounts import account as account_mod
from backend.daemons import pipeline
from backend.daemons import wake_queue
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
        os.mkfifo(str(FIFO_PATH), 0o600)
    os.chmod(str(FIFO_PATH), 0o600)


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
    log(f"daemon started; FIFO={FIFO_PATH} poll={WAKE_POLL_SECONDS}s")
    # Bootstrap at startup: drain any queued pushes, then sweep all accounts
    # in case a push arrived while the daemon was down.
    try:
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
