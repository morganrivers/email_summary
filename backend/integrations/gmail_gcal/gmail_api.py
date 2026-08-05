"""Gmail, in process. The Python replacement for gmail_lib.mjs.

Every Gmail call in the app goes through this module, and every one of them
starts from an Account: there is no ambient mailbox any more, the way there was
when a per-user directory was passed to a Node subprocess through an
environment variable.

Credentials are the interesting part. `Credentials` is constructed with no
refresh token at all, which routes every token acquisition through the
`refresh_handler` in backend.custody.tokens -- the case google-auth's own
docstring describes as "tokens are obtained by calling some external process on
demand". The external process here is a co-signer on another machine. Everything
below this line is stock google-api-python-client; nothing about split custody
leaks into the API calls themselves.
"""

from __future__ import annotations

import base64
import re
import sys
import threading

import requests
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from backend.custody import tokens
from backend.integrations.gmail_gcal import oauth_app

PROFILE_URL = "https://gmail.googleapis.com/gmail/v1/users/me/profile"
HTTP_TIMEOUT = 30

MAX_SEARCH_BODY = 2000
MAX_THREAD_BODY = 3000

# httplib2, under the Google client, is not thread-safe, and the web UI builds
# voice profiles on a background thread while the daemon drafts. One service per
# thread per account costs a discovery parse and removes the whole question.
_local = threading.local()


def log(msg):
    sys.stderr.write(f"gmail {msg}\n")
    sys.stderr.flush()


def credentials_for(account):
    """Credentials that hold no refresh token, only a way to ask for a token.

    That is not a limitation being worked around; it is the design. A refresh
    token in this object would be a refresh token in this process's memory for
    as long as the object lives, which is what split custody exists to prevent.
    """
    return Credentials(
        None,
        scopes=list(oauth_app.SCOPES),
        refresh_handler=tokens.refresh_handler_for(account),
    )


def _service(account, api, version):
    assert getattr(account, "id", None), "gmail_api needs a loaded Account"
    cache = getattr(_local, "services", None)
    if cache is None:
        cache = _local.services = {}
    key = (account.id, api, version)
    if key not in cache:
        cache[key] = build(
            api, version, credentials=credentials_for(account),
            cache_discovery=False,
        )
    return cache[key]


def gmail(account):
    return _service(account, "gmail", "v1")


def calendar(account):
    return _service(account, "calendar", "v3")


def forget_services(account_id=None):
    """Drop cached service objects for this thread. A re-consent changes which
    credentials a service carries, so the cached one must not outlive it."""
    cache = getattr(_local, "services", None)
    if not cache:
        return
    if account_id is None:
        cache.clear()
        return
    for key in [k for k in cache if k[0] == account_id]:
        cache.pop(key)


def profile_address(access_token):
    """The mailbox address a bare access token belongs to.

    Onboarding's one Gmail call, made before any Account exists, so it takes a
    token rather than an account. It stays here because this module is where
    Gmail's HTTP surface is allowed to be named."""
    assert access_token, "profile_address needs an access token"
    resp = requests.get(
        PROFILE_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=HTTP_TIMEOUT,
    )
    resp.raise_for_status()
    address = (resp.json().get("emailAddress") or "").strip().lower()
    assert address, "Gmail getProfile returned no emailAddress"
    return address


# --- pure helpers ---------------------------------------------------------

def extract_text(part):
    """First text/plain body in a MIME tree, decoded."""
    if not part:
        return ""
    body = part.get("body") or {}
    if part.get("mimeType") == "text/plain" and body.get("data"):
        return _b64_body(body["data"])
    for child in part.get("parts") or []:
        text = extract_text(child)
        if text:
            return text
    return ""


def _b64_body(data):
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode(
        "utf-8", errors="replace"
    )


def normalize_body(text):
    text = text.replace("\r\n", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def headers_of(payload):
    return {h["name"].lower(): h.get("value", "")
            for h in (payload or {}).get("headers", [])}


# --- messages and threads -------------------------------------------------

def fetch_message(account, message_id):
    full = gmail(account).users().messages().get(
        userId="me", id=message_id, format="full").execute()
    head = headers_of(full.get("payload"))
    return {
        "id": message_id,
        "threadId": full.get("threadId"),
        "from": head.get("from", "unknown"),
        "to": head.get("to", ""),
        "subject": head.get("subject", "(no subject)"),
        "messageIdHeader": head.get("message-id", ""),
        "referencesHeader": head.get("references", ""),
        "date": head.get("date", ""),
        "body": normalize_body(extract_text(full.get("payload"))),
    }


def search_messages(account, query, max_results=5):
    service = gmail(account)
    listing = service.users().messages().list(
        userId="me", q=query, maxResults=max_results).execute()
    results = []
    for m in listing.get("messages", []):
        full = service.users().messages().get(
            userId="me", id=m["id"], format="full").execute()
        head = headers_of(full.get("payload"))
        body = normalize_body(extract_text(full.get("payload")))
        results.append({
            "id": m["id"],
            "threadId": full.get("threadId"),
            "from": head.get("from", ""),
            "to": head.get("to", ""),
            "subject": head.get("subject", ""),
            "date": head.get("date", ""),
            "snippet": full.get("snippet", ""),
            "body": body[:MAX_SEARCH_BODY],
        })
    return results


def get_thread(account, thread_id):
    res = gmail(account).users().threads().get(
        userId="me", id=thread_id, format="full").execute()
    messages = []
    for msg in res.get("messages", []):
        head = headers_of(msg.get("payload"))
        messages.append({
            "id": msg.get("id"),
            "from": head.get("from", ""),
            "to": head.get("to", ""),
            "subject": head.get("subject", ""),
            "date": head.get("date", ""),
            "body": normalize_body(extract_text(msg.get("payload")))[:MAX_THREAD_BODY],
        })
    return {"threadId": thread_id, "messages": messages}


def thread_has_user_message(account, thread_id, exclude_message_id=None):
    """Sole source of the reply-triage participation signal. Gmail's own SENT
    label records that the account owner wrote in the thread, so this needs no
    address matching and cannot disagree with what the mailbox shows."""
    res = gmail(account).users().threads().get(
        userId="me", id=thread_id, format="minimal").execute()
    for msg in res.get("messages", []):
        if msg.get("id") == exclude_message_id:
            continue
        if "SENT" in (msg.get("labelIds") or []):
            return True
    return False


def annotate_thread_participation(account, emails):
    """Annotate inbound emails in place with userParticipated. One failed lookup
    degrades that email to the pre-existing "no participation signal" behavior
    rather than losing the whole batch."""
    for e in emails:
        if not e.get("threadId"):
            e["userParticipated"] = False
            continue
        try:
            e["userParticipated"] = thread_has_user_message(
                account, e["threadId"], e.get("id"))
        except HttpError as err:
            log(f"thread participation lookup failed for {e.get('id')}: {err}")
            e["userParticipated"] = False
    return emails


def find_thread_by_from_subject(account, from_email, subject):
    clean = re.sub(r"^(re:|fwd:|fw:)\s*", "", (subject or "").strip(),
                   flags=re.IGNORECASE).strip()
    query = f"from:{from_email}"
    if clean:
        escaped = clean.replace('"', '\\"')
        query += f' subject:"{escaped}"'
    service = gmail(account)
    listing = service.users().messages().list(
        userId="me", q=query, maxResults=5).execute()
    messages = listing.get("messages", [])
    if not messages:
        return {"found": False}
    full = service.users().messages().get(
        userId="me", id=messages[0]["id"], format="full").execute()
    head = headers_of(full.get("payload"))
    return {
        "found": True,
        "threadId": full.get("threadId"),
        "messageIdHeader": head.get("message-id", ""),
        "referencesHeader": head.get("references", ""),
        "subject": head.get("subject", ""),
        "from": head.get("from", ""),
    }


# --- history and watch ----------------------------------------------------

def history_list(account, start_history_id):
    """Message ids added since a cursor, split by INBOX vs SENT.

    A 404 means the cursor is older than Gmail's history window; the caller
    bootstraps from the current id rather than trying to recover mail that is no
    longer enumerable."""
    service = gmail(account)
    added, sent = [], []
    page_token = None
    latest = start_history_id
    while True:
        try:
            res = service.users().history().list(
                userId="me", startHistoryId=start_history_id,
                historyTypes=["messageAdded"], pageToken=page_token).execute()
        except HttpError as err:
            if err.resp.status == 404:
                return {"addedMessageIds": [], "sentMessageIds": [],
                        "historyId": None, "stale": True}
            raise
        for h in res.get("history", []):
            for ma in h.get("messagesAdded", []):
                msg = ma.get("message", {})
                labels = msg.get("labelIds") or []
                if "INBOX" in labels:
                    added.append(msg["id"])
                elif "SENT" in labels:
                    sent.append(msg["id"])
        if res.get("historyId"):
            latest = res["historyId"]
        page_token = res.get("nextPageToken")
        if not page_token:
            break
    return {
        "addedMessageIds": list(dict.fromkeys(added)),
        "sentMessageIds": list(dict.fromkeys(sent)),
        "historyId": latest,
        "stale": False,
    }


def current_history_id(account):
    return gmail(account).users().getProfile(userId="me").execute().get("historyId")


def register_watch(account, topic_name):
    """Sole users.watch call. Both the renewal driver and onboarding route
    through here, so the topic/label registration shape is defined once."""
    assert topic_name, "register_watch needs a Pub/Sub topic"
    res = gmail(account).users().watch(userId="me", body={
        "topicName": topic_name,
        "labelIds": ["INBOX"],
        "labelFilterAction": "include",
    }).execute()
    return {"historyId": res.get("historyId"), "expiration": res.get("expiration")}
