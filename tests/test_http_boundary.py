"""One way out, with one set of rules.

Outbound HTTP was six call sites in four spellings, two CA policies and
redirects followed everywhere. The weakest settings were on the fetch that
decides whether an inbound Pub/Sub push is genuine. `backend/http_client.py` is
now the only place a request is made, in the sense `backend/egress.py` is the
only place a hostname is allowed, and this reads the tree for the second one
that gets added -- the same way `tests/test_llm_boundary.py` reads it for a call
to `/v1/responses`.

Two exemptions, both named here rather than left to be inferred:

  * `backend/custody/client.py` verifies the co-signer's TLS per call and will
    pin its certificate (`bug_fixes_secondbatch.md` §A3), which is a decision
    `http_client` deliberately does not offer. It moves across when that lands.
  * `backend/tee/dstack_client.py` speaks HTTP over a unix socket to the guest
    agent. There is no URL, no TLS and no CA bundle in that conversation, so
    none of the rules above have anything to say about it.
"""

import ast
from types import SimpleNamespace

import pytest
from harness import python_sources, relative

from backend import http_client, paths

# Every way to make an outbound request that is not this client. `urlopen` is
# the one bandit names (B310) and the one that opens file:// and data:// as
# readily as https.
FORBIDDEN_CALLS = ("urlopen", "urlretrieve")
REQUESTS_VERBS = ("get", "post", "head", "put", "patch", "delete", "request")

CLIENT = "backend/http_client.py"
COSIGNER_CLIENT = "backend/custody/client.py"
UNIX_SOCKET_CLIENT = "backend/tee/dstack_client.py"


def _calls(path):
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Call):
            yield node


def _dotted(func):
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def test_nothing_opens_a_url_with_urllib():
    offenders = []
    for path in python_sources():
        for call in _calls(path):
            name = _dotted(call.func).rsplit(".", 1)[-1]
            if name in FORBIDDEN_CALLS:
                offenders.append(f"{relative(path)}:{call.lineno} calls {name}()")
    assert not offenders, (
        "urlopen opens file://, ftp:// and data: as happily as https, and "
        "returns a file-like object either way. Go through backend/http_client:"
        "\n" + "\n".join(offenders)
    )


def test_nothing_calls_requests_directly():
    allowed = {CLIENT, COSIGNER_CLIENT}
    offenders = []
    for path in python_sources():
        if relative(path) in allowed:
            continue
        for call in _calls(path):
            dotted = _dotted(call.func)
            head, _, verb = dotted.rpartition(".")
            if head == "requests" and verb in REQUESTS_VERBS:
                offenders.append(f"{relative(path)}:{call.lineno} calls {dotted}()")
    assert not offenders, (
        "a second HTTP call site is a second CA policy, a second timeout rule "
        "and a second answer about redirects:\n" + "\n".join(offenders)
    )


def test_nothing_speaks_http_by_hand():
    allowed = {CLIENT, UNIX_SOCKET_CLIENT}
    offenders = []
    for path in python_sources():
        if relative(path) in allowed:
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            if any(n == "http.client" or n.startswith("http.client.") for n in names):
                offenders.append(f"{relative(path)}:{node.lineno} imports http.client")
    assert not offenders, "\n".join(offenders)


def test_the_exemption_expires_with_the_reason_for_it():
    """An exemption nobody re-reads is an exemption that outlives its reason.

    The co-signer client is off this list until it pins that box's certificate,
    which decides TLS verification per call. When that lands, the file stops
    calling `requests` and this fails -- which is the moment to delete the
    exemption above rather than the moment to notice it years later."""
    text = (paths.REPO_ROOT / COSIGNER_CLIENT).read_text()
    assert "requests.request(" in text, (
        f"{COSIGNER_CLIENT} no longer calls requests directly, so it belongs on "
        f"backend/http_client.py and off the allowed set in this file"
    )


# --- the rules themselves -------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://example.com/certs",
    "file:///etc/passwd",
    "data:text/plain,hello",
    "ftp://example.com/x",
    "example.com/x",
    "https:///no-host",
])
def test_only_https_is_fetchable(url):
    with pytest.raises(http_client.InsecureRequest):
        http_client.check_url(url)


def _fake_transport(monkeypatch, script):
    """`requests.request` replaced by a scripted sequence of responses."""
    seen = []

    def fake(method, url, **kwargs):
        seen.append((method, url, kwargs))
        status, location = script[len(seen) - 1]
        return SimpleNamespace(
            status_code=status, url=url,
            is_redirect=location is not None,
            headers={"Location": location} if location else {},
        )

    monkeypatch.setattr(http_client.requests, "request", fake)
    return seen


def test_a_redirect_is_not_followed_unless_it_was_asked_for(monkeypatch):
    """The default matters more than the option. A 303 from an allowlisted host
    to `http://169.254.169.254/` is the shape this is for, and every call site
    accepted it before there was a client."""
    seen = _fake_transport(monkeypatch, [(303, "http://169.254.169.254/")])
    response = http_client.get("https://api.example.com/x", timeout=5)
    assert response.status_code == 303
    assert len(seen) == 1
    assert seen[0][2]["allow_redirects"] is False


def test_a_followed_hop_goes_through_the_same_check(monkeypatch):
    _fake_transport(monkeypatch, [(302, "http://169.254.169.254/")])
    with pytest.raises(http_client.InsecureRequest):
        http_client.get("https://api.example.com/x", timeout=5, redirects=1)


def test_a_followed_hop_is_spent_and_the_budget_bounds_it(monkeypatch):
    seen = _fake_transport(monkeypatch, [
        (302, "https://second.example.com/x"),
        (302, "https://third.example.com/x"),
    ])
    response = http_client.get("https://first.example.com/x", timeout=5, redirects=1)
    assert [url for _, url, _ in seen] == [
        "https://first.example.com/x", "https://second.example.com/x",
    ]
    assert response.status_code == 302


def test_a_relative_redirect_resolves_against_the_page_it_came_from(monkeypatch):
    seen = _fake_transport(monkeypatch, [(302, "/moved"), (200, None)])
    http_client.get("https://api.example.com/x", timeout=5, redirects=1)
    assert seen[1][1] == "https://api.example.com/moved"


def test_the_ca_bundle_is_not_a_caller_choice(monkeypatch):
    seen = _fake_transport(monkeypatch, [(200, None)])
    http_client.get("https://api.example.com/x", timeout=5)
    assert seen[0][2]["verify"].endswith(".pem"), seen[0][2]["verify"]


def test_a_timeout_is_required():
    with pytest.raises(TypeError):
        http_client.get("https://api.example.com/x")
