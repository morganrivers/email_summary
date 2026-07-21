"""Agentic email drafter.

Calls DeepSeek with tool schemas (calendar, email search, thread fetch). DeepSeek
decides which tools to invoke. Loop continues until the model returns a final draft
or MAX_ITERATIONS is hit. Returns the draft body as plain text.

Wraps the OpenAI client with langsmith.wrappers.wrap_openai when LANGSMITH_API_KEY
is set. No-op otherwise.
"""

import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone

import llm_client
import pseudonymizer
from llm_client import make_client, LANGSMITH_ENABLED

from tool_executors import TOOL_REGISTRY, TOOL_SCHEMAS

MAX_ITERATIONS = 5
MAX_TOKENS = 32000
MAX_EM_DASH_RETRIES = 4

GREETING_RE = re.compile(
    r'^(Hi|Hello|Hey|Dear|Good\s+(morning|afternoon|evening))\b',
    re.IGNORECASE,
)

EM_DASH_RE = re.compile(r'[—–]')

EM_DASH_CORRECTION_PROMPT = (
    "Your previous draft contained an em-dash (—) or en-dash (–). "
    "These characters cause the draft to be rejected. "
    "Rewrite the reply body, replacing every em-dash and en-dash with "
    "commas, periods, parentheses, or restructured sentences. "
    "Output only the corrected email body, beginning with the greeting. "
    "Do not call any tools."
)


def contains_em_dash(text):
    return bool(EM_DASH_RE.search(text or ''))


def _strip_preamble(body):
    """Strip any leading reasoning/commentary before the first greeting line.

    Some models emit reasoning text before the actual email when given tools.
    A draft must begin with a greeting; anything before it is preamble.
    """
    if not body:
        return body
    lines = body.split('\n')
    for i, line in enumerate(lines):
        if GREETING_RE.match(line.strip()):
            return '\n'.join(lines[i:]).strip()
    return body.strip()


_LS_CLIENT = None


def _get_ls_client():
    global _LS_CLIENT
    if not LANGSMITH_ENABLED:
        return None
    if _LS_CLIENT is not None:
        return _LS_CLIENT
    if not os.environ.get("LANGCHAIN_API_KEY"):
        return None
    try:
        from langsmith import Client
        _LS_CLIENT = Client()
        return _LS_CLIENT
    except Exception as err:
        sys.stderr.write(f"langsmith Client init failed: {err}\n")
        return None


def _tool_call_to_message(tc):
    return {
        "role": "tool",
        "tool_call_id": tc.id,
        "content": "",
    }


def draft(client, system_prompt, user_prompt, max_iterations=MAX_ITERATIONS,
          thread_id=None, on_iteration=None, identity=None, creds_dir=None):
    now = datetime.now(timezone.utc).isoformat()
    system_with_time = (
        f"{system_prompt}\n\n"
        f"Current UTC time: {now}\n\n"
        "You have access to tools to look up Morgan's email history and calendar. "
        "Use them when relevant context would materially improve the draft (e.g., "
        "checking availability before proposing a time, recalling prior commitments, "
        "verifying claims). If no lookup is needed, just write the draft. Aim for the "
        "fewest tool calls necessary.\n\n"
        "CRITICAL OUTPUT RULE: Your final response (after any tool calls) must contain "
        "ONLY the email body. Begin with the greeting (Hi/Hello/Dear/Hey). "
        "End with the sign-off and Morgan's name. No analysis, no reasoning, no preamble, "
        "no notes about why you wrote it that way. Just the email.\n\n"
        "PUNCTUATION RULE: Never use em-dashes (—) or en-dashes (–) in the body. "
        "Use commas, periods, parentheses, or restructured sentences instead. "
        "Em-dashes will cause the draft to be rejected.\n\n"
        "REASONING BUDGET: Keep your internal reasoning under 1000 words. "
        "Do not exhaustively explore alternatives. Decide quickly, then write. "
        "The final email content must fit in the response, so leave ample room for it."
    )
    state = pseudonymizer.new_state(identity)
    system_with_time = pseudonymizer.pseudonymize(system_with_time, state)
    user_prompt = pseudonymizer.pseudonymize(user_prompt, state)
    messages = [
        {"role": "system", "content": system_with_time},
        {"role": "user", "content": user_prompt},
    ]

    session_id = thread_id or str(uuid.uuid4())
    ls_extra = {"metadata": {"session_id": session_id, "thread_id": session_id}}
    project = os.environ.get("LANGCHAIN_PROJECT") or os.environ.get("LANGSMITH_PROJECT")
    ls_client = _get_ls_client()

    if ls_client:
        from langsmith.run_helpers import trace
        with trace(
            name="draft_email",
            run_type="chain",
            project_name=project,
            inputs={"system_prompt": system_with_time[:500], "user_prompt": user_prompt[:2000]},
            metadata={"session_id": session_id, "thread_id": session_id},
        ) as run:
            body = _draft_with_em_dash_retry(client, messages, max_iterations,
                                             ls_extra, state, on_iteration=on_iteration,
                                             creds_dir=creds_dir)
        body = pseudonymizer.restore(body, state)
        run_url = None
        try:
            run_url = ls_client.get_run_url(run=run, project_name=project)
        except Exception as err:
            sys.stderr.write(f"get_run_url failed: {err}\n")
        return body, run_url
    body = _draft_with_em_dash_retry(client, messages, max_iterations, ls_extra,
                                     state, on_iteration=on_iteration, creds_dir=creds_dir)
    body = pseudonymizer.restore(body, state)
    return body, None


def _summarize_tool_result(result):
    try:
        s = result if isinstance(result, str) else json.dumps(result)
    except Exception:
        s = str(result)
    return s[:120] + ("..." if len(s) > 120 else "")


def _log_iter(iteration, msg, resp):
    content_len = len(msg.content or "")
    reasoning_len = len(getattr(msg, "reasoning_content", None) or "")
    n_tools = len(msg.tool_calls or [])
    sys.stderr.write(
        f"drafter iter={iteration} content_len={content_len} "
        f"reasoning_len={reasoning_len} tool_calls={n_tools} "
        f"finish_reason={resp.choices[0].finish_reason}\n"
    )


def _safe_notify(on_iteration, *args):
    if not on_iteration:
        return
    try:
        on_iteration(*args)
    except Exception as err:
        sys.stderr.write(f"on_iteration failed: {err}\n")


def _draft_with_em_dash_retry(client, messages, max_iterations, ls_extra, state,
                              on_iteration=None, creds_dir=None):
    body = _run_loop(client, messages, max_iterations, ls_extra, state,
                     on_iteration=on_iteration, creds_dir=creds_dir)
    for attempt in range(MAX_EM_DASH_RETRIES):
        if not contains_em_dash(body):
            return body
        sys.stderr.write(
            f"em-dash detected in draft, retrying "
            f"({attempt + 1}/{MAX_EM_DASH_RETRIES})\n"
        )
        messages.append({"role": "assistant", "content": body})
        messages.append({"role": "user", "content": EM_DASH_CORRECTION_PROMPT})
        body = _run_loop(client, messages, max_iterations, ls_extra, state,
                         on_iteration=on_iteration, creds_dir=creds_dir)
    return body


def _run_loop(client, messages, max_iterations, ls_extra, state, on_iteration=None,
              creds_dir=None):
    tool_history = []
    for iteration in range(max_iterations):
        resp = llm_client.complete(
            client,
            messages=messages,
            max_tokens=MAX_TOKENS,
            pseudonymize=False,
            tools=TOOL_SCHEMAS,
            tool_choice="auto",
            langsmith_extra=ls_extra,
        )
        msg = resp.choices[0].message
        _log_iter(iteration + 1, msg, resp)

        if not msg.tool_calls:
            body = (msg.content or "").strip()
            _safe_notify(on_iteration, iteration + 1, msg, tool_history, True)
            assert body, "drafter returned empty body"
            return _strip_preamble(body)

        messages.append({
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                }
                for tc in msg.tool_calls
            ],
        })

        for tc in msg.tool_calls:
            fn_name = tc.function.name
            raw_args = pseudonymizer.restore(tc.function.arguments or "", state)
            try:
                fn_args = json.loads(raw_args) if raw_args else {}
            except json.JSONDecodeError:
                fn_args = {}
                result = {"error": f"invalid JSON arguments: {raw_args[:200]}"}
            else:
                executor = TOOL_REGISTRY.get(fn_name)
                if executor is None:
                    result = {"error": f"unknown tool {fn_name}"}
                else:
                    result = executor(fn_args, creds_dir)
            tool_history.append({
                "iteration": iteration + 1,
                "name": fn_name,
                "args": fn_args,
                "result_summary": _summarize_tool_result(result),
            })
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": pseudonymizer.pseudonymize(json.dumps(result), state),
            })

        _safe_notify(on_iteration, iteration + 1, msg, tool_history, False)

    sys.stderr.write(
        f"agentic_drafter hit MAX_ITERATIONS={max_iterations}; "
        "forcing final draft without further tool calls.\n"
    )
    final = llm_client.complete(
        client,
        messages=messages + [{
            "role": "user",
            "content": "Stop calling tools. Write the final reply body now, plain text only.",
        }],
        max_tokens=MAX_TOKENS,
        pseudonymize=False,
        langsmith_extra=ls_extra,
    )
    final_msg = final.choices[0].message
    _log_iter(max_iterations + 1, final_msg, final)
    body = (final_msg.content or "").strip()
    _safe_notify(on_iteration, max_iterations + 1, final_msg, tool_history, True)
    assert body, "drafter returned empty body after force-stop"
    return _strip_preamble(body)
