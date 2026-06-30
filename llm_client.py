"""Single source of truth for DeepSeek client + completion calls.

All callers route through `complete()` so model, thinking toggle, and
reasoning effort live in exactly one place.
"""

import os
import sys

from openai import OpenAI

MODEL = "deepseek-v4-pro"
BASE_URL = "https://api.deepseek.com"
REASONING_EFFORT = "max"
THINKING = {"type": "enabled"}


def make_client(api_key):
    assert api_key, "DEEPSEEK_API_KEY is empty"
    client = OpenAI(api_key=api_key, base_url=BASE_URL)
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
    return wrap_openai(client)


def complete(client, messages, max_tokens, **kwargs):
    assert messages, "messages must be non-empty"
    extra_body = kwargs.pop("extra_body", {}) or {}
    extra_body.setdefault("thinking", THINKING)
    return client.chat.completions.create(
        model=MODEL,
        messages=messages,
        max_tokens=max_tokens,
        reasoning_effort=REASONING_EFFORT,
        extra_body=extra_body,
        **kwargs,
    )
