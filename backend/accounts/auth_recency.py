"""When an account last proved control of its mailbox to *this* process.

Google's consent is the only thing on the box that proves a person holds a
mailbox, and `onboarding.provisioning.handle_callback` is where that proof
lands. This module is the daemon's own note of having seen it.

Whose note it is is the whole point. `chat_link` skips the emailed code when
mailbox control was just proven, and if the web tier could assert "they signed
in a moment ago" then a compromised web tier would assert it every time and the
proof would be back to being a claim from the process the rule is aimed at. The
callback runs in the daemon over the handoff socket, so the daemon records what
it did itself and answers from that.

In-process and never a file, for the reasons `chat_link._pending` is not one: a
few minutes of meaning, and a restart that loses it costs an extra email rather
than an opening. Fail-closed by construction -- forgetting means asking for the
proof, never skipping it.
"""

from __future__ import annotations

import threading
import time

# How long a sign-in stands as proof of mailbox control. Long enough to arrive
# at Settings from the callback and press a button, short enough that it is not
# a window somebody can come back to.
FRESH_SECONDS = 600

_lock = threading.Lock()
_proven = {}


def _prune(now):
    for key in [k for k, at in _proven.items() if at + FRESH_SECONDS <= now]:
        del _proven[key]


def record(account_id):
    """Note that this account just completed a Google sign-in."""
    assert account_id, "an authentication with no account is not one"
    now = time.time()
    with _lock:
        _prune(now)
        _proven[account_id] = now


def proven_recently(account_id, within=FRESH_SECONDS):
    """Whether this process saw this account authenticate inside `within`."""
    with _lock:
        at = _proven.get(account_id)
    return at is not None and time.time() - at < within


def forget(account_id):
    """Drop the note. Called when an account is deleted, and by tests."""
    with _lock:
        _proven.pop(account_id, None)
