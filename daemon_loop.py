#!/usr/bin/env python3
"""Always-on email-drafter daemon.

Blocks on a FIFO for wake signals from gmail-hook.php. On wake, fetches new
emails via state.lastHistoryId and runs them through manual_draft / draft_replies.

Runs as morganrivers (NFSN daemon), so no permission hacks. The webhook PHP
(running as 'web') only opens the FIFO for write and writes one byte — that
unblocks our read and we process the delta.

A re-wake during processing is fine: we drain the FIFO once before processing
so multiple wakes coalesce into a single run.
"""

import os
import sys
import stat
import time
import signal
import traceback
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))

from dotenv import load_dotenv
load_dotenv(SCRIPT_DIR / ".env")

import account as account_mod
import pipeline
import wake_queue
from notify import notify_error

FIFO_PATH = SCRIPT_DIR / "wake.fifo"
RESTART_FLAG = SCRIPT_DIR / "restart.flag"


def log(msg):
    sys.stdout.write(f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] {msg}\n")
    sys.stdout.flush()


def ensure_fifo():
    if FIFO_PATH.exists():
        if not stat.S_ISFIFO(FIFO_PATH.stat().st_mode):
            FIFO_PATH.unlink()
    if not FIFO_PATH.exists():
        os.mkfifo(str(FIFO_PATH), 0o666)
    os.chmod(str(FIFO_PATH), 0o666)


def _run_account(acct):
    pipeline.process_account(
        acct,
        log=log,
        notify_err=lambda ctx, err, a=acct: notify_error(ctx, err, a.telegram),
    )


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


def drain_fifo():
    """Read all pending bytes (coalesce multiple wakes). Blocks until at least one byte."""
    fd = os.open(str(FIFO_PATH), os.O_RDONLY)
    try:
        # Block on first read
        os.read(fd, 4096)
        # Drain anything else that arrived
        os.set_blocking(fd, False)
        while True:
            try:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
            except BlockingIOError:
                break
    finally:
        os.close(fd)


def main():
    ensure_fifo()
    log(f"daemon started; FIFO={FIFO_PATH}")
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
            drain_fifo()
            log("wake")
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
            else:
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
