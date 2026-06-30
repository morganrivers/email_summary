#!/usr/bin/env python3
"""

re-auth:
node /home/protected/email_summary/manual_auth.mjs


Fetch today's emails, summarise with DeepSeek, send via Telegram.

(py311) dmrivers@lenny:~/.system_files$ history | grep scp
sudo scp .env morganrivers_morganrivers@ssh.nyc1.nearlyfreespeech.net:/home/protected/
sudo scp email_summary.py  morganrivers_morganrivers@ssh.nyc1.nearlyfreespeech.net:/home/protected/
sudo scp fetch_emails.mjs   morganrivers_morganrivers@ssh.nyc1.nearlyfreespeech.net:/home/protected/
sudo scp gcp-oauth.keys.json   morganrivers_morganrivers@ssh.nyc1.nearlyfreespeech.net:/home/protected/
sudo scp credentials.json    morganrivers_morganrivers@ssh.nyc1.nearlyfreespeech.net:/home/protected/
sudo scp email_summary.py  morganrivers_morganrivers@ssh.nyc1.nearlyfreespeech.net:/home/protected/
sudo scp fetch_emails.mjs   morganrivers_morganrivers@ssh.nyc1.nearlyfreespeech.net:/home/protected/
sudo scp fetch_emails.mjs   morganrivers_morganrivers@ssh.nyc1.nearlyfreespeech.net:/home/protected/
sudo scp prompt_for_email    morganrivers_morganrivers@ssh.nyc1.nearlyfreespeech.net:/home/private/.system_files/

"""

import os
import json
import subprocess
import datetime
from pathlib import Path

from dotenv import load_dotenv
import requests
from openai import OpenAI

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent
ENV_FILE = SCRIPT_DIR / ".env"
FETCH_SCRIPT = SCRIPT_DIR / "fetch_emails.mjs"
PROMPT_FILE = Path.home() / ".system_files" / "prompt_for_email"

load_dotenv(ENV_FILE)

TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
TELEGRAM_CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]
DEEPSEEK_API_KEY = os.environ["DEEPSEEK_API_KEY"]


# ── Gmail (via Node.js helper) ────────────────────────────────────────────────

def fetch_todays_emails_and_events() -> dict:
    result = subprocess.run(
        ["node", str(FETCH_SCRIPT)],
        capture_output=False,
        stdout=subprocess.PIPE,
        stderr=None,   # stderr passes through so re-auth prompts are visible
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"fetch_emails.mjs exited with code {result.returncode}")
    return json.loads(result.stdout)


# ── DeepSeek ─────────────────────────────────────────────────────────────────

def summarise(emails: list[dict], events: list[dict]) -> str:
    prompt = PROMPT_FILE.read_text().strip()
    client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url="https://api.deepseek.com")

    email_text = "\n\n".join(
        f"From: {e['from']}\nSubject: {e['subject']}\n{e['body']}"
        for e in emails
    )

    event_text = "\n\n".join(
        f"Event: {e['summary']}\nStart: {e['start']}\nEnd: {e['end']}" +
        (f"\nLocation: {e['location']}" if e['location'] else "") +
        (f"\nDescription: {e['description']}" if e['description'] else "")
        for e in events
    )

    user_content = f"Here are today's emails:\n\n{email_text}"
    if events:
        user_content += f"\n\nHere are your calendar events for the next 24 hours:\n\n{event_text}"

    resp = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": user_content},
        ],
        max_tokens=600,
    )
    return resp.choices[0].message.content.strip()


# ── Telegram ─────────────────────────────────────────────────────────────────

def send_telegram(message: str) -> None:
    resp = requests.post(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        json={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"},
        timeout=10,
    )
    resp.raise_for_status()


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("Fetching today's emails and calendar events...")
    data = fetch_todays_emails_and_events()
    emails = data.get("emails", [])
    events = data.get("events", [])

    if not emails and not events:
        send_telegram("No new emails or calendar events for the next 24 hours.")
        print("No emails or events — sent notification.")
        return

    print(f"Found {len(emails)} email(s) and {len(events)} event(s). Summarising...")
    summary = summarise(emails, events)

    today_str = datetime.date.today().strftime("%a %d %b")
    message = f"📬 <b>Daily summary for {today_str}</b>\n\n{summary}"

    print("Sending to Telegram...")
    send_telegram(message)
    print("Done.")


if __name__ == "__main__":
    main()
