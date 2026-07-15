"""Single source of truth for Telegram notifications.

Env (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID) is read at call time, so callers
only need to have loaded .env before invoking send_telegram.
"""

import os

import requests


def send_telegram(message):
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    chat_id = os.environ["TELEGRAM_CHAT_ID"]
    resp = requests.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"},
        timeout=10,
    )
    resp.raise_for_status()
