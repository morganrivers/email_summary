"""The Google API client layer both Gmail and Calendar sit on.

One consent covers both APIs, so both are reached with the same credentials and
the same cache. That shared part lives here rather than in `gmail_api`, so
`calendar_api` does not have to import the mail module to build a calendar
service: the two API modules are siblings over this one, not a chain.

Credentials are the interesting part. `Credentials` is constructed with no
refresh token at all, which routes every token acquisition through the
`refresh_handler` in backend.custody.tokens -- the case google-auth's own
docstring describes as "tokens are obtained by calling some external process on
demand". The external process here is a co-signer on another machine. Nothing
about split custody leaks past this module into the API calls themselves.
"""

from __future__ import annotations

import threading

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from backend.custody import tokens
from backend.integrations.gmail_gcal import oauth_app

# httplib2, under the Google client, is not thread-safe, and the web UI builds
# voice profiles on a background thread while the daemon drafts. One service per
# thread per account costs a discovery parse and removes the whole question.
_local = threading.local()

# The Google APIs this module ever builds a client for, named here rather than
# only at the two call sites, because something else now has to enumerate them:
# googleapiclient takes each API's root URL out of the discovery document
# bundled in the library, so those two hostnames are the only entries in
# backend/egress.py that no constant of ours produces. tests/test_egress.py
# reads the documents for these pairs and fails if a root the client would dial
# is absent from the allowlist.
GMAIL = ("gmail", "v1")
CALENDAR = ("calendar", "v3")
APIS = (GMAIL, CALENDAR)


def credentials_for(account):
    """Credentials that hold no refresh token, only a way to ask for a token.

    That is not a limitation being worked around; it is the design. A refresh
    token in this object would be a refresh token in this process's memory for
    as long as the object lives, which is what split custody exists to prevent.
    """
    assert getattr(account, "id", None), "credentials_for needs a loaded Account"
    return Credentials(
        None,
        scopes=list(oauth_app.scopes()),
        refresh_handler=tokens.refresh_handler_for(account),
    )


def service(account, api, version):
    """A discovery-built client for one Google API, cached per thread."""
    assert getattr(account, "id", None), "service needs a loaded Account"
    assert api and version, "service needs an API name and version"
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
