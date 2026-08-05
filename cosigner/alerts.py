"""Operator alerts, and the one place this package touches `backend/`.

A refusal here is either a bug or a breach in progress, and both want a human
looking within minutes. The box already has a Telegram channel for exactly this
class of event -- `telegram.operator_target()`, which reads the operator's own
chat from the environment and is explicitly not the per-account path -- so this
sends through it rather than growing a second copy of the Bot API.

`backend.integrations.telegram` is imported inside the function, not at module
scope, for two reasons. The service must import (and therefore start) on a box
where `backend/` is not deployed at all, which is what this package is shaped
for. And when the co-signer does move to its own host under its own operator,
this function is the only thing to rewrite: swap the body for that host's
notifier and nothing else in the package changes.

Never raises. An alert that fails must not take down the decision path that
triggered it.
"""

import sys


def log(msg):
    sys.stderr.write(f"cosigner {msg}\n")
    sys.stderr.flush()


def notify_operator(text):
    """Send to the box owner's chat. Returns whether it was delivered."""
    assert text, "notify_operator needs something to say"
    try:
        from backend.integrations import telegram

        return telegram.send_telegram(text, telegram.operator_target())
    except Exception as err:
        log(f"operator alert not delivered ({err}): {text}")
        return False
