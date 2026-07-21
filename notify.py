"""Single source of truth for Telegram notifications.

A target (TelegramTarget: token + chat_id) routes the message to one account's
chat. When target is None the bot token / chat id are read from the environment
at call time, the historical single-tenant behavior.
"""

import html
import os
import sys
import traceback

import requests


def send_telegram(message, target=None):
    if target is not None:
        token, chat_id = target.token, target.chat_id
    else:
        token = os.environ["TELEGRAM_BOT_TOKEN"]
        chat_id = os.environ["TELEGRAM_CHAT_ID"]
    resp = requests.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"},
        timeout=10,
    )
    resp.raise_for_status()


def notify_error(context, err=None, target=None):
    """Surface a failure to Telegram. Never raises: a broken notification
    must not crash the caller's except block."""
    try:
        text = f"⚠️ <b>email_summary error</b>\n{html.escape(context)}"
        if err is not None:
            detail = "".join(
                traceback.format_exception(type(err), err, err.__traceback__)
            )
            text += f"\n<pre>{html.escape(detail[-3000:])}</pre>"
        send_telegram(text, target)
    except Exception as notify_err:
        sys.stderr.write(f"notify_error failed to send: {notify_err}\n")
