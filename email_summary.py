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

import llm_client
from draft_replies import gmail_thread_link

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
    client = llm_client.make_client(DEEPSEEK_API_KEY)

    email_text = "\n\n".join(
        f"From: {e['from']}\nSubject: {e['subject']}\n"
        f"Link: {gmail_thread_link(e['threadId'])}\n"
        f"{e['body']}"
        for e in emails
    )

    event_text = "\n\n".join(
        f"Event: {e['summary']}\nStart: {e['start']}\nEnd: {e['end']}" +
        (f"\nLocation: {e['location']}" if e['location'] else "") +
        (f"\nDescription: {e['description']}" if e['description'] else "")
        for e in events
    )

    today_iso = datetime.date.today().isoformat()
    today_pretty = datetime.date.today().strftime("%A %d %b %Y")
    user_content = (
        f"Today's date: {today_iso} ({today_pretty}).\n\n"
        f"Here are today's emails:\n\n{email_text}"
    )
    if events:
        user_content += (
            "\n\nHere are your calendar events for the next 24 hours "
            "(may span today into tomorrow morning):\n\n"
            f"{event_text}"
        )

    resp = llm_client.complete(
        client,
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": user_content},
        ],
        max_tokens=16000,
    )
    msg = resp.choices[0].message
    content = (msg.content or "").strip()
    reasoning = getattr(msg, "reasoning_content", None) or ""
    print(
        f"model returned content_len={len(content)} reasoning_len={len(reasoning)} "
        f"finish_reason={resp.choices[0].finish_reason}"
    )
    return content


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

    if not summary:
        email_line = (
            "Nothing for today on email." if not emails
            else "Nothing worth surfacing for today on email."
        )
        event_line = (
            "Nothing for today on calendar." if not events
            else "See calendar for today's events."
        )
        summary = f"{email_line}\n{event_line}"
        print("empty model output; using fallback summary")

    today_str = datetime.date.today().strftime("%a %d %b")
    message = f"📬 <b>Daily summary for {today_str}</b>\n\n{summary}"

    print("Sending to Telegram...")
    send_telegram(message)
    print("Done.")


if __name__ == "__main__":
    main()
