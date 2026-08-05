"""The shape of the one call that leaves this box.

`complete()` being the single LLM boundary is only worth anything if nothing
routes around it, so these are checks on the tree rather than on behaviour.
The source is read as an AST, not as text: prose about the responses API (there
is some, in llm_client's own docstring) is not a use of it.
"""

import ast
from pathlib import Path
from urllib.parse import urlparse

from backend.integrations import llm_client

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


def test_no_provider_bakes_an_endpoint_into_its_base_url():
    """The SDK appends the endpoint. A base_url carrying one of its own would
    either 404 or, worse, pin a provider to an endpoint nobody chose."""
    for provider in llm_client.PROVIDERS.values():
        path = urlparse(provider.base_url).path.rstrip("/")
        assert path in ("", "/v1"), (
            f"{provider.name} base_url {provider.base_url!r} carries the path "
            f"{path!r}; it should be an API root"
        )
