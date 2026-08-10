"""The only place this tree makes an outbound HTTP request.

`backend/egress.py` is the one list of hostnames anything here may connect to.
This is the same idea one layer down: one place that decides how a connection is
made, so the answer cannot differ per call site. Before it there were six of
them in four spellings -- two `urlopen`, four `requests` -- two CA policies, and
every one of them followed redirects to wherever the response pointed. The
weakest settings were on `gmail_hook_server.download_certs()`, which fetches the
keys deciding whether an inbound Pub/Sub push is genuine.

Four rules, and each one is here because it is the kind of thing that is right
in five call sites and forgotten in the sixth:

  * **https only.** `urllib.request.urlopen` opens `file://`, `ftp://` and
    `data:` as readily as `https://` and hands back a file-like object either
    way, so a URL that ever becomes caller-influenced turns a fetch into a local
    file read. The scheme is checked rather than assumed, and `InsecureRequest`
    is a refusal because a URL is an input.
  * **certifi on every call.** One CA policy, not two, and not one that moves
    when somebody edits the box's trust store.
  * **an explicit timeout.** Keyword-only and required: a default is a value
    that gets forgotten, and the forgotten case is a hung socket holding a
    drafting pass open.
  * **no redirects unless asked.** A 303 from an allowlisted host to
    `http://169.254.169.254/` is the classic version of this, and every call
    site accepted it before. A caller that needs a hop passes `redirects=` and
    each hop is re-checked against the same rules, so a redirect cannot be the
    way around them.

What this deliberately does not do is check the host against
`backend/egress.py`. That belongs here and would be what makes the allowlist
mean something inside the enclave, where there is no proxy; it is
`bug_fixes_fourthbatch.md` §3, and the fix there is a compose partition change
rather than a client change.

`backend/custody/client.py` is the one outbound call that is not here yet: it
pins the co-signer's certificate (`bug_fixes_secondbatch.md` §A3), which decides
TLS verification per call in a way this module deliberately does not offer.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

import certifi
import requests

# What a caller catches when the request did not happen. Re-exported so a call
# site can handle a dead socket without importing `requests` itself, which is
# what `tests/test_http_boundary.py` reads the tree for.
TransportError = requests.RequestException

SCHEME = "https"


class InsecureRequest(ValueError):
    """A URL this client will not open.

    A refusal and not an assert: the subject is a URL, and the whole reason to
    check one is the day it stops being a constant."""


def check_url(url):
    """The URL, or `InsecureRequest`. Sole definition of what is fetchable."""
    parsed = urlparse(str(url))
    if parsed.scheme != SCHEME:
        raise InsecureRequest(
            f"refusing a {parsed.scheme or 'schemeless'} URL: this client opens "
            f"{SCHEME} only, and {url!r} is not it"
        )
    if not parsed.hostname:
        raise InsecureRequest(f"refusing a URL with no host: {url!r}")
    return url


def request(method, url, *, timeout, redirects=0, **kwargs):
    """One request. Returns the `requests.Response`, raising nothing for a 4xx
    or 5xx -- the status is the caller's to read.

    `redirects` is a hop budget rather than a boolean, and each hop goes back
    through `check_url`. `requests` follows redirects itself with one flag, but
    it does so without re-applying anything above, which is the behaviour this
    replaces."""
    assert redirects >= 0, f"a redirect budget cannot be negative, got {redirects}"
    assert "allow_redirects" not in kwargs, (
        "redirects are followed here, one checked hop at a time; pass redirects="
    )
    assert "verify" not in kwargs, "the CA bundle is certifi on every call and is not a parameter"
    check_url(url)
    while True:
        response = requests.request(
            method, url, timeout=timeout, allow_redirects=False,
            verify=certifi.where(), **kwargs,
        )
        location = response.headers.get("Location")
        if not (response.is_redirect and location):
            return response
        if redirects <= 0:
            return response
        redirects -= 1
        url = check_url(urljoin(response.url, location))


def get(url, *, timeout, redirects=0, **kwargs):
    return request("GET", url, timeout=timeout, redirects=redirects, **kwargs)


def post(url, *, timeout, redirects=0, **kwargs):
    return request("POST", url, timeout=timeout, redirects=redirects, **kwargs)


def head(url, *, timeout, redirects=0, **kwargs):
    return request("HEAD", url, timeout=timeout, redirects=redirects, **kwargs)
