"""Single source of truth for the inference client + completion calls.

All callers route through `make_client(account)` and `complete()`, so which
provider an account talks to, the model, the thinking toggle, the reasoning
effort, and the masking boundary all live in exactly one place.

Three providers ship. `deepseek` calls DeepSeek directly and is the default.
`nearai-glm` and `nearai-gpt-oss` reach NEAR AI's per-model direct completions
endpoints, each of which is a dstack CVM that publishes a TDX quote; the
gateway at cloud-api.near.ai is deliberately not used, because a per-model
endpoint is the only shape that lets a quote say which model it serves.

A confidential provider is verified before it is used, not described as
verified: `make_client()` will not return a client until
`inference_attestation.require()` has checked the quote against a committed
allowlist, and it raises rather than falling back. Users pick per account in
Settings; masking applies to every provider, because an attested enclave is
still a party we do not control.

Every call goes through `/v1/chat/completions` and none through `/v1/responses`.
That is a privacy choice, not a stylistic one: the responses API is stateful and
persists conversation content server-side, which is the opposite of what an
account picked a confidential provider for. `complete()` is the only place the
endpoint is named, and `test_llm_boundary` fails the build if anything reaches
for `client.responses`.
"""

import json
import os
import sys
import threading
import time

from openai import OpenAI

from backend.integrations import inference_attestation
from backend.integrations import telegram
from backend.masking import pseudonymizer


class Provider:
    """One inference endpoint. `key_env` names the .env variable holding its
    API key; a provider whose key is absent is not offered and not selectable,
    rather than silently standing in for another one."""

    def __init__(self, name, label, base_url, model, key_env, confidential,
                 blurb, attestation_url=None, reasoning_effort="max", thinking=None):
        assert name and base_url and model and key_env, "provider is underspecified"
        assert not (confidential and not attestation_url), (
            f"provider {name!r} claims to be confidential but names no attestation "
            f"endpoint; an unverifiable claim is the thing this catalog must not carry"
        )
        self.name = name
        self.label = label
        self.base_url = base_url
        self.model = model
        self.key_env = key_env
        self.confidential = confidential
        self.blurb = blurb
        self.attestation_url = attestation_url
        self.reasoning_effort = reasoning_effort
        self.thinking = thinking if thinking is not None else {"type": "enabled"}

    def api_key(self):
        return os.environ.get(self.key_env, "").strip()

    def configured(self):
        return bool(self.api_key())

    def attests(self):
        return bool(self.confidential and self.attestation_url)


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
            name="nearai-glm",
            label="GLM 5.2 in an enclave (confidential)",
            base_url="https://glm-5-2.completions.near.ai/v1",
            model="z-ai/glm-5.2",
            key_env="NEARAI_API_KEY",
            confidential=True,
            attestation_url="https://glm-5-2.completions.near.ai/v1/attestation/report",
            blurb=("Drafts are read by a model running in a hardware enclave whose "
                   "measurement this server checks before every session. NEAR AI "
                   "operates the machine and cannot read what runs inside it. "
                   "Served as FP8. Masking still applies."),
        ),
        Provider(
            name="nearai-gpt-oss",
            label="gpt-oss-120b in an enclave (confidential)",
            base_url="https://gpt-oss-120b.completions.near.ai/v1",
            model="openai/gpt-oss-120b",
            key_env="NEARAI_API_KEY",
            confidential=True,
            attestation_url="https://gpt-oss-120b.completions.near.ai/v1/attestation/report",
            blurb=("A smaller open-weight model in the same attested enclave setup, "
                   "cheaper and quicker than GLM 5.2. Served as FP4, with a 131k "
                   "context rather than 1M. Masking still applies."),
        ),
    )
}

DEFAULT_PROVIDER = "deepseek"

# Statuses that mean the provider will keep refusing until a human does
# something: an exhausted balance, a revoked key, a disabled account. Distinct
# from 429 and 5xx, which are worth retrying and are not this box's problem.
PROVISIONING_STATUSES = (401, 402, 403)

# One operator alert per provider per window, not one per email. A drained
# balance fails every draft in the queue, and a hundred identical Telegram
# messages is how an operator learns to mute the channel.
ALERT_COOLDOWN_SECONDS = 6 * 3600

_ALERT_LOCK = threading.Lock()
_ALERTED = {}


class ProviderUnavailable(RuntimeError):
    """The chosen provider cannot serve this account until the operator acts.

    Separate from a bug so the cause is legible in a log full of tracebacks,
    and separate from `AttestationError` because running out of credits is
    ordinary while a failed measurement is not. Neither one falls back to
    another provider: `resolve()` refuses to substitute, and an exhausted
    balance is not a reason to send someone's mail somewhere they did not
    choose."""

# Reasoning tokens count against max_tokens, so a budget sized for the answer
# alone truncates before any answer is emitted. Sized for the largest batch a
# caller sends (40 emails) rather than the typical one.
JSON_MAX_TOKENS = 16000

# Off unless deliberately switched on. Tracing ships every prompt and tool
# result to a third-party observability service, which is a claim the product
# pages do not make; an API key happening to be present in the environment is
# not consent to send other people's mail there. It also lands outside whatever
# enclave the chosen provider runs in, so it defeats attestation when enabled.
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
    is no account in hand (one-off tooling); everything on a mail path has one.

    A confidential provider is attested here, at the one place a client can be
    built, so no caller can reach an unverified enclave by taking a different
    route. A failed check raises: not drafting is the correct outcome, and
    quietly using a provider the user did not choose is not."""
    provider = resolve(account)
    if provider.attests():
        inference_attestation.require(provider)
    client = OpenAI(api_key=provider.api_key(), base_url=provider.base_url)
    client._ls_wrapped = False
    client = _traced(client)
    client._ll_provider = provider
    return client


def _create(client, provider, **kwargs):
    """The one call out, with provisioning failures named rather than left as a
    status code in a traceback. Anything else propagates untouched: a timeout is
    a timeout and this is not the layer that decides how to retry it."""
    try:
        return client.chat.completions.create(**kwargs)
    except Exception as err:
        status = getattr(err, "status_code", None)
        if status not in PROVISIONING_STATUSES:
            raise
        detail = {401: "the API key was rejected", 402: "the account is out of credits",
                  403: "the account is not permitted to use this model"}[status]
        _alert_once(provider, status, detail)
        raise ProviderUnavailable(
            f"{provider.label} cannot serve this account: {detail} "
            f"(HTTP {status} from {provider.base_url}). Fix {provider.key_env} or the "
            f"provider account; nothing will be sent to a different provider meanwhile."
        ) from err


def _alert_once(provider, status, detail):
    """Tell the operator, at most once per provider per window. Never raises:
    an undelivered alert must not replace the error the caller is about to
    see."""
    key = (provider.name, status)
    now = time.monotonic()
    with _ALERT_LOCK:
        last = _ALERTED.get(key)
        if last is not None and now - last < ALERT_COOLDOWN_SECONDS:
            return
        _ALERTED[key] = now
    sys.stderr.write(f"{provider.name}: {detail} (HTTP {status})\n")
    try:
        telegram.notify_error(
            f"Inference paused: {provider.label} — {detail}. "
            f"Drafts for accounts on this provider will keep failing until it is fixed."
        )
    except Exception as alert_err:
        sys.stderr.write(f"{provider.name}: operator alert not delivered ({alert_err})\n")


def reset_alerts_for_test():
    with _ALERT_LOCK:
        _ALERTED.clear()


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
    resp = _create(
        client, provider,
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
