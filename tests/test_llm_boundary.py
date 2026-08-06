"""The shape of the one call that leaves this box.

`complete()` being the single LLM boundary is only worth anything if nothing
routes around it, so these are checks on the tree rather than on behaviour.
The source is read as an AST, not as text: prose about the responses API (there
is some, in llm_client's own docstring) is not a use of it.
"""

import ast
from pathlib import Path
from urllib.parse import urlparse

import pytest

from backend.integrations import llm_client
from backend.integrations import telegram

REPO_ROOT = Path(__file__).parent.parent
SEARCHED = ("backend", "frontend", "cosigner", "tools")


def python_sources():
    for top in SEARCHED:
        for path in sorted((REPO_ROOT / top).rglob("*.py")):
            if "__pycache__" not in path.parts:
                yield path


def attribute_chains(path):
    """Every dotted attribute access in a file, as `a.b.c` strings."""
    for node in ast.walk(ast.parse(path.read_text())):
        if not isinstance(node, ast.Attribute):
            continue
        parts = [node.attr]
        current = node.value
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        yield ".".join(reversed(parts))


def test_nothing_uses_the_responses_api():
    """The responses API persists conversation content server-side. An account
    that chose a confidential provider chose the opposite of that, so the
    endpoint is banned outright rather than avoided by habit."""
    offenders = sorted({
        str(path.relative_to(REPO_ROOT)) for path in python_sources()
        for chain in attribute_chains(path)
        if chain.endswith("responses.create") or chain.endswith("responses.parse")
    })
    assert not offenders, (
        f"{offenders} reach for the responses API; use chat completions through "
        f"llm_client.complete(), which does not persist content server-side"
    )


def test_chat_completions_is_called_in_exactly_one_place():
    hits = sorted({
        str(path.relative_to(REPO_ROOT)) for path in python_sources()
        for chain in attribute_chains(path)
        if chain.endswith("chat.completions.create")
    })
    assert hits == ["backend/integrations/llm_client.py"], (
        f"chat.completions.create is called from {hits}; route it through "
        f"llm_client.complete() so masking and provider choice cannot be skipped"
    )


class FakeStatusError(Exception):
    def __init__(self, status_code):
        super().__init__(f"HTTP {status_code}")
        self.status_code = status_code


@pytest.fixture
def refusing(monkeypatch):
    """A client whose one call fails with a status we choose, plus a record of
    every operator alert it caused."""
    sent = []
    monkeypatch.setattr(telegram, "notify_error",
                        lambda text, err=None, target=None: sent.append(text))
    llm_client.reset_alerts_for_test()

    def build(status):
        class Completions:
            def create(self, **kwargs):
                raise FakeStatusError(status)

        client = type("C", (), {})()
        client.chat = type("Chat", (), {"completions": Completions()})()
        client._ll_provider = llm_client.PROVIDERS["nearai-glm"]
        client._ls_wrapped = False
        return client

    yield build, sent
    llm_client.reset_alerts_for_test()


def call(client):
    return llm_client.complete(client, [{"role": "user", "content": "hi"}],
                               max_tokens=10)


@pytest.mark.parametrize("status", llm_client.PROVISIONING_STATUSES)
def test_a_provisioning_failure_is_named_not_left_as_a_status(refusing, status):
    build, _ = refusing
    with pytest.raises(llm_client.ProviderUnavailable) as err:
        call(build(status))
    assert str(status) in str(err.value)
    assert "nothing will be sent to a different provider" in str(err.value)


def test_a_transient_failure_is_not_dressed_up_as_a_provisioning_one(refusing):
    build, sent = refusing
    for status in (429, 500, 503):
        with pytest.raises(FakeStatusError):
            call(build(status))
    assert sent == [], "a rate limit is not an operator provisioning problem"


def test_the_operator_is_told_once_not_once_per_email(refusing):
    build, sent = refusing
    client = build(402)
    for _ in range(25):
        with pytest.raises(llm_client.ProviderUnavailable):
            call(client)
    assert len(sent) == 1, f"sent {len(sent)} alerts for one drained balance"
    assert "out of credits" in sent[0]


def test_a_different_failure_on_the_same_provider_still_alerts(refusing):
    build, sent = refusing
    with pytest.raises(llm_client.ProviderUnavailable):
        call(build(402))
    with pytest.raises(llm_client.ProviderUnavailable):
        call(build(401))
    assert len(sent) == 2


def test_an_undeliverable_alert_does_not_replace_the_error(monkeypatch, refusing):
    build, _ = refusing

    def broken(*args, **kwargs):
        raise RuntimeError("telegram is down")

    monkeypatch.setattr(telegram, "notify_error", broken)
    llm_client.reset_alerts_for_test()
    with pytest.raises(RuntimeError) as err:
        call(build(402))
    assert "telegram is down" not in str(err.value)


def test_no_provider_bakes_an_endpoint_into_its_base_url():
    """The SDK appends the endpoint. A base_url carrying one of its own would
    either 404 or, worse, pin a provider to an endpoint nobody chose."""
    for provider in llm_client.PROVIDERS.values():
        path = urlparse(provider.base_url).path.rstrip("/")
        assert path in ("", "/v1"), (
            f"{provider.name} base_url {provider.base_url!r} carries the path "
            f"{path!r}; it should be an API root"
        )
