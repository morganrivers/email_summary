"""Gmail, in process. The Python replacement for the mail half of gmail_lib.mjs.

Every Gmail call in the app goes through this module, and every one of them
starts from an Account: there is no ambient mailbox any more, the way there was
when a per-user directory was passed to a Node subprocess through an
environment variable.

Credentials and the service cache are not here; they are shared with Calendar
and live in `google_client`. Everything below is stock
google-api-python-client, holding no state of its own.
"""

from __future__ import annotations

import base64
import re
import sys

import requests
from googleapiclient.errors import HttpError

from backend.integrations.gmail_gcal.google_client import service


PROFILE_URL = "https://gmail.googleapis.com/gmail/v1/users/me/profile"
HTTP_TIMEOUT = 30

MAX_SEARCH_BODY = 2000
MAX_THREAD_BODY = 3000

# The one header value that reaches a Gmail search query, and the shape it has
# to have first: a bare address, with nothing in it that a query could read as
# whitespace, a quote, or a second operator.
ADDRESS_QUERY_RE = re.compile(r"^[^\s<>\"'(){}:@]+@[^\s<>\"'(){}:@]+\.[^\s<>\"'(){}:@]+$")

REPLY_PREFIX_RE = re.compile(r"^\s*(re|fwd|fw)\s*:\s*", re.IGNORECASE)

# How far back to look for the thread a forwarded email came from, and which
# headers that costs. Candidates are read as metadata, so a miss is cheap and
# the loop stops at the first match.
THREAD_LOOKUP_CANDIDATES = 25
THREAD_LOOKUP_HEADERS = ["Subject", "Message-ID", "References", "From"]

# A forwarded subject is matched exactly, unless the sending client wrapped the
# Subject line of the header block it quoted, in which case what arrives is a
# prefix of the real one. A prefix is accepted only when it is long enough to
# identify a thread rather than every thread.
MIN_SUBJECT_PREFIX = 12


def log(msg):
    sys.stderr.write(f"gmail {msg}\n")
    sys.stderr.flush()


def gmail(account):
    return service(account, "gmail", "v1")


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


def strip_reply_prefixes(subject):
    """Subject with every leading Re:/Fwd:/Fw: removed. Repeatedly, because a
    forwarded reply carries more than one and stripping only the outermost left
    the rest in whatever the caller went on to build."""
    text = (subject or "").strip()
    while True:
        shorter = REPLY_PREFIX_RE.sub("", text, count=1).strip()
        if shorter == text:
            return text
        text = shorter


def comparable_subject(subject):
    """The form two subjects are compared in: no reply prefixes, one space
    between words, case folded. Applied to both sides, so 'Fwd: Re: Lunch  plan'
    and 'lunch plan' are the same thread."""
    return re.sub(r"\s+", " ", strip_reply_prefixes(subject)).casefold()


def _subject_matches(candidate, target):
    if not target:
        return True
    found = comparable_subject(candidate)
    return found == target or (
        len(target) >= MIN_SUBJECT_PREFIX and found.startswith(target)
    )


def find_thread_by_from_subject(account, from_email, subject):
    """Locate the original thread of a forwarded email.

    Both arguments come off headers an outside sender wrote, and Gmail's search
    has no parameterized form: a query is one string, a space in it starts a new
    operator, and there is no escape character. Quoting a phrase is documented
    nowhere as a boundary you can rely on, so the subject does not go into the
    query at all. Only the sender does, and only after being checked into the
    shape of a bare address; a sender that is not one is refused, and the caller
    drafts on a new thread the same way it does when nothing is found.

    The subject is then matched here, over candidate metadata, where a string is
    a string and cannot become a second operator. That also matches more
    tightly than the query did: `subject:"lunch"` was a phrase search that would
    take any thread mentioning lunch, and this takes the one whose subject is
    the forwarded subject."""
    sender = (from_email or "").strip().strip("<>")
    if not ADDRESS_QUERY_RE.match(sender):
        log(f"thread lookup refused: {sender[:80]!r} is not a bare address")
        return {"found": False}
    target = comparable_subject(subject)
    service = gmail(account)
    listing = service.users().messages().list(
        userId="me", q=f"from:{sender}",
        maxResults=THREAD_LOOKUP_CANDIDATES).execute()
    for message in listing.get("messages", []):
        meta = service.users().messages().get(
            userId="me", id=message["id"], format="metadata",
            metadataHeaders=THREAD_LOOKUP_HEADERS).execute()
        head = headers_of(meta.get("payload"))
        if not _subject_matches(head.get("subject", ""), target):
            continue
        return {
            "found": True,
            "threadId": meta.get("threadId"),
            "messageIdHeader": head.get("message-id", ""),
            "referencesHeader": head.get("references", ""),
            "subject": head.get("subject", ""),
            "from": head.get("from", ""),
        }
    return {"found": False}


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
