"""Single source of truth for the inference client + completion calls.

All callers route through `make_client(account)` and `complete()`, so which
provider an account talks to, the model, the thinking toggle, the reasoning
effort, and the masking boundary all live in exactly one place.

Two providers ship. `deepseek` calls DeepSeek directly and is the default.
`tresor` calls the same upstream model through Tresor's confidential gateway,
where inference runs inside a hardware TEE and the request terminates TLS
inside the attested runtime, so neither Tresor nor the model provider sees
plaintext. Users pick per account in Settings; masking applies either way,
because a gateway that is trusted today is still a party we do not control.
"""

import json
import os
import sys

from openai import OpenAI

from backend.masking import pseudonymizer


class Provider:
    """One inference endpoint. `key_env` names the .env variable holding its
    API key; a provider whose key is absent is not offered and not selectable,
    rather than silently standing in for another one."""

    def __init__(self, name, label, base_url, model, key_env, confidential,
                 blurb, reasoning_effort="max", thinking=None):
        assert name and base_url and model and key_env, "provider is underspecified"
        self.name = name
        self.label = label
        self.base_url = base_url
        self.model = model
        self.key_env = key_env
        self.confidential = confidential
        self.blurb = blurb
        self.reasoning_effort = reasoning_effort
        self.thinking = thinking if thinking is not None else {"type": "enabled"}

    def api_key(self):
        return os.environ.get(self.key_env, "").strip()

    def configured(self):
        return bool(self.api_key())


PROVIDERS = {
    p.name: p for p in (
        Provider(
            name="deepseek",
            label="DeepSeek (standard)",
            base_url="https://api.deepseek.com",
            model="deepseek-v4-pro",
            key_env="DEEPSEEK_API_KEY",
            confidential=False,
            blurb=("Drafts go straight to DeepSeek. Identifiers are replaced with "
                   "tags before the text leaves this server, but DeepSeek can read "
                   "what remains."),
        ),
        Provider(
            name="tresor",
            label="Tresor (confidential)",
            base_url="https://api.trytresor.com/v1",
            model="deepseek-v4-pro",
            key_env="TRESOR_API_KEY",
            confidential=True,
            blurb=("Same model, reached through a hardware enclave. TLS terminates "
                   "inside the attested runtime, so neither Tresor nor DeepSeek can "
                   "read the request. Masking still applies."),
        ),
    )
}

DEFAULT_PROVIDER = "deepseek"

# Reasoning tokens count against max_tokens, so a budget sized for the answer
# alone truncates before any answer is emitted. Sized for the largest batch a
# caller sends (40 emails) rather than the typical one.
JSON_MAX_TOKENS = 16000

# Off unless deliberately switched on. Tracing ships every prompt and tool
# result to a third-party observability service, which is a claim the product
# pages do not make; an API key happening to be present in the environment is
# not consent to send other people's mail there. It also lands outside whatever
# enclave the chosen provider runs in, so it defeats `tresor` when enabled.
LANGSMITH_ENABLED = os.environ.get("LANGSMITH_TRACING", "0") == "1"


def available_providers():
    """The providers this box can actually reach, in catalog order. The web UI
    offers a choice only when there is more than one."""
    return [p for p in PROVIDERS.values() if p.configured()]


def resolve(account=None):
    """Which provider serves this account.

    A stated preference is honored or it fails: an account that chose a provider
    whose key is missing raises, because standing in another provider would send
    that user's mail somewhere they did not agree to. Only an account with no
    preference gets a substitute, and only the box's sole remaining option."""
    chosen = getattr(account, "inference_provider", None)
    if chosen:
        provider = PROVIDERS.get(chosen)
        assert provider is not None, (
            f"unknown inference provider {chosen!r}; known: {sorted(PROVIDERS)}"
        )
        assert provider.configured(), (
            f"account selected provider {provider.name!r} but {provider.key_env} "
            f"is not set in .env"
        )
        return provider

    default = PROVIDERS[DEFAULT_PROVIDER]
    if default.configured():
        return default
    available = available_providers()
    assert available, (
        "no inference provider is configured; set one of "
        f"{sorted(p.key_env for p in PROVIDERS.values())} in .env"
    )
    assert len(available) == 1, (
        f"{default.key_env} is not set and more than one provider is available "
        f"({[p.name for p in available]}); pick one in Settings rather than "
        f"letting the box choose"
    )
    return available[0]


def _traced(client):
    if not LANGSMITH_ENABLED:
        return client
    ls_key = os.environ.get("LANGSMITH_API_KEY") or os.environ.get("LANGCHAIN_API_KEY")
    if not ls_key:
        sys.stderr.write("no LANGSMITH/LANGCHAIN_API_KEY in env; tracing disabled\n")
        return client
    os.environ.setdefault("LANGCHAIN_API_KEY", ls_key)
    os.environ.setdefault("LANGSMITH_API_KEY", ls_key)
    os.environ.setdefault("LANGCHAIN_TRACING_V2", "true")
    proj = os.environ.get("LANGSMITH_PROJECT") or os.environ.get("LANGCHAIN_PROJECT")
    if proj:
        os.environ.setdefault("LANGCHAIN_PROJECT", proj)
    try:
        from langsmith.wrappers import wrap_openai
    except ImportError:
        sys.stderr.write("langsmith not installed; tracing disabled\n")
        return client
    sys.stderr.write(f"langsmith tracing enabled, project={proj or 'default'}\n")
    wrapped = wrap_openai(client)
    wrapped._ls_wrapped = True
    return wrapped


def make_client(account=None):
    """Build the client for this account's provider. Pass None only where there
    is no account in hand (one-off tooling); everything on a mail path has one."""
    provider = resolve(account)
    client = OpenAI(api_key=provider.api_key(), base_url=provider.base_url)
    client._ls_wrapped = False
    client = _traced(client)
    client._ll_provider = provider
    return client


def _mask_messages(messages, state):
    masked = []
    for m in messages:
        content = m.get("content")
        if isinstance(content, str):
            m = {**m, "content": pseudonymizer.pseudonymize(content, state)}
        masked.append(m)
    return masked


def _restore_response(resp, state):
    for choice in resp.choices:
        msg = getattr(choice, "message", None)
        if msg is not None and getattr(msg, "content", None):
            msg.content = pseudonymizer.restore(msg.content, state)


def complete(client, messages, max_tokens, pseudonymize=True, identity=None, **kwargs):
    """Single LLM boundary. By default, PII is masked out of every message
    before the call (so external traces carry only tags) and restored in the
    response afterward. identity is the account owner whose own name/email get
    fixed tags; defaults to the single-tenant identity. Multi-turn callers that
    manage their own pseudonymizer state (agentic_drafter) pass pseudonymize=False."""
    assert messages, "messages must be non-empty"
    provider = getattr(client, "_ll_provider", None)
    assert provider is not None, (
        "client must come from make_client(); a bare OpenAI() carries no provider "
        "and would send this to whatever base_url it was built with"
    )
    if not getattr(client, "_ls_wrapped", False):
        kwargs.pop("langsmith_extra", None)
    extra_body = kwargs.pop("extra_body", {}) or {}
    extra_body.setdefault("thinking", provider.thinking)
    state = pseudonymizer.new_state(identity) if pseudonymize else None
    if state is not None:
        messages = _mask_messages(messages, state)
    resp = client.chat.completions.create(
        model=provider.model,
        messages=messages,
        max_tokens=max_tokens,
        reasoning_effort=provider.reasoning_effort,
        extra_body=extra_body,
        **kwargs,
    )
    if state is not None:
        _restore_response(resp, state)
    return resp


def complete_json(client, messages, max_tokens=JSON_MAX_TOKENS, **kwargs):
    """Single boundary for completions that must return parseable JSON.
    Reasoning tokens count against max_tokens, so a budget sized for the answer
    alone silently truncates: the API returns finish_reason='length' with empty
    content, which a bare json.loads turns into an opaque JSONDecodeError deep
    in the caller. Assert it where it happens instead."""
    resp = complete(
        client, messages, max_tokens=max_tokens,
        response_format={"type": "json_object"}, **kwargs,
    )
    choice = resp.choices[0]
    content = (choice.message.content or "").strip()
    assert choice.finish_reason != "length", (
        f"LLM output truncated at max_tokens={max_tokens}; raise JSON_MAX_TOKENS "
        f"or shrink the batch"
    )
    assert content, (
        f"LLM returned empty content (finish_reason={choice.finish_reason})"
    )
    return json.loads(content)
