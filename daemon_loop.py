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

import state
import manual_draft
import schedule_from_sent
from draft_replies import process_emails
from notify import notify_error

import subprocess
import json

FETCH_SCRIPT = SCRIPT_DIR / "fetch_emails.mjs"
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


def fetch_since(history_id):
    result = subprocess.run(
        ["node", str(FETCH_SCRIPT), "--since-history", str(history_id)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
    )
    assert result.returncode == 0, (
        f"fetch_emails.mjs exited {result.returncode}: {result.stderr.decode()}"
    )
    return json.loads(result.stdout)


def process_once():
    s = state.load()
    last = s.get("lastHistoryId")
    if not last:
        log("No lastHistoryId in state; run watch_register.mjs first.")
        return
    payload = fetch_since(last)
    emails = payload.get("emails", [])
    sent = payload.get("sent", [])
    new_history_id = payload.get("historyId")
    stale = payload.get("stale", False)
    log(f"fetched {len(emails)} email(s), {len(sent)} sent since historyId={last}")
    if stale:
        log(f"history.list 404 (startHistoryId={last} too old); bootstrapping to {new_history_id}")
    bot_requests = [e for e in emails if manual_draft.is_bot_request(e)]
    auto_emails = [e for e in emails if not manual_draft.is_bot_request(e)]
    for req in bot_requests:
        try:
            manual_draft.process_draft_request(req)
        except Exception as err:
            log(f"manual_draft failed for {req.get('id')}: {err}")
            traceback.print_exc(file=sys.stdout)
            notify_error(f"manual_draft failed for email {req.get('id')}", err)
    if auto_emails:
        try:
            process_emails(auto_emails)
        except Exception as err:
            log(f"process_emails failed: {err}")
            traceback.print_exc(file=sys.stdout)
            notify_error("process_emails failed", err)
    if sent:
        try:
            schedule_from_sent.run(sent)
        except Exception as err:
            log(f"schedule_from_sent failed: {err}")
            traceback.print_exc(file=sys.stdout)
            notify_error("schedule_from_sent failed", err)
    if new_history_id:
        state.update(lastHistoryId=str(new_history_id))


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
    # Process once at startup in case anything is pending
    try:
        process_once()
    except Exception as err:
        log(f"startup process_once failed: {err}")
        traceback.print_exc(file=sys.stdout)
        notify_error("startup process_once failed", err)
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
            process_once()
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
