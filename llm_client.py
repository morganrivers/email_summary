"""Single source of truth for DeepSeek client + completion calls.

All callers route through `complete()` so model, thinking toggle, and
reasoning effort live in exactly one place.
"""

import os
import sys

from openai import OpenAI

import pseudonymizer

MODEL = "deepseek-v4-pro"
BASE_URL = "https://api.deepseek.com"
REASONING_EFFORT = "max"
THINKING = {"type": "enabled"}

LANGSMITH_ENABLED = True


def make_client(api_key):
    assert api_key, "DEEPSEEK_API_KEY is empty"
    client = OpenAI(api_key=api_key, base_url=BASE_URL)
    client._ls_wrapped = False
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
    if not getattr(client, "_ls_wrapped", False):
        kwargs.pop("langsmith_extra", None)
    extra_body = kwargs.pop("extra_body", {}) or {}
    extra_body.setdefault("thinking", THINKING)
    state = pseudonymizer.new_state(identity) if pseudonymize else None
    if state is not None:
        messages = _mask_messages(messages, state)
    resp = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        max_tokens=max_tokens,
        reasoning_effort=REASONING_EFFORT,
        extra_body=extra_body,
        **kwargs,
    )
    if state is not None:
        _restore_response(resp, state)
    return resp
