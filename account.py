"""Per-account context threaded through every processing path.

An Account bundles everything that varies per user: the masking identity, the
state cursor, the notification target, and the Gmail creds directory. A shared
process holds one Account per user without any ambient single-tenant globals.

default_account() reproduces the historical single-tenant config (Morgan's
identity, state.json, env-based Telegram, default Gmail creds), so a caller that
passes the default behaves exactly as the pre-refactor code did.
"""

import os

import pseudonymizer
import state


class TelegramTarget:
    def __init__(self, token, chat_id):
        assert token and chat_id, "telegram target needs token and chat_id"
        self.token = token
        self.chat_id = chat_id


class Account:
    def __init__(self, id, identity, state, telegram, creds_dir=None):
        assert id and identity and state and telegram, "account requires id, identity, state, telegram"
        self.id = id
        self.identity = identity
        self.state = state
        self.telegram = telegram
        self.creds_dir = creds_dir


def default_account():
    telegram = TelegramTarget(
        os.environ["TELEGRAM_BOT_TOKEN"],
        os.environ["TELEGRAM_CHAT_ID"],
    )
    return Account(
        id="default",
        identity=pseudonymizer.DEFAULT_IDENTITY,
        state=state.StateStore(state.DEFAULT_STATE_FILE),
        telegram=telegram,
        creds_dir=os.environ.get("GMAIL_MCP_DIR"),
    )


def load_accounts():
    return [default_account()]
