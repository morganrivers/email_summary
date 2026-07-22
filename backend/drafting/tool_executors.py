"""Executors for tools the agentic drafter can call.

Each function takes a single dict (the tool's arguments as parsed JSON),
shells out to the corresponding node helper, and returns a Python value.
Errors return error dicts rather than raising so the model can recover.
"""

import json
import subprocess

from backend import paths
from backend.integrations.gmail_gcal.node_runner import node_env

SEARCH_GMAIL = paths.node_script("search_gmail.mjs")
LIST_CALENDAR = paths.node_script("list_calendar.mjs")
GET_THREAD = paths.node_script("get_thread.mjs")

NODE_TIMEOUT = 60


def _run_node(script, args, creds_dir=None):
    cmd = ["node", str(script)] + args
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=NODE_TIMEOUT, env=node_env(creds_dir),
        )
    except subprocess.TimeoutExpired:
        return {"error": f"{script.name} timed out after {NODE_TIMEOUT}s"}
    if result.returncode != 0:
        return {"error": result.stderr.decode("utf-8", errors="replace").strip()}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        return {"error": f"{script.name} returned invalid JSON: {e}"}


def search_emails(args, creds_dir=None):
    query = args.get("query")
    if not query:
        return {"error": "query is required"}
    max_results = min(int(args.get("max_results", 5)), 10)
    out = _run_node(SEARCH_GMAIL, ["--query", query, "--max", str(max_results)], creds_dir)
    if isinstance(out, dict) and "error" in out:
        return out
    return {"results": out, "count": len(out)}


def get_calendar_events(args, creds_dir=None):
    start_iso = args.get("start_iso")
    end_iso = args.get("end_iso")
    if not start_iso or not end_iso:
        return {"error": "start_iso and end_iso are required (ISO 8601)"}
    out = _run_node(LIST_CALENDAR, ["--start", start_iso, "--end", end_iso], creds_dir)
    if isinstance(out, dict) and "error" in out:
        return out
    return {"events": out, "count": len(out)}


def get_email_thread(args, creds_dir=None):
    thread_id = args.get("thread_id")
    if not thread_id:
        return {"error": "thread_id is required"}
    out = _run_node(GET_THREAD, ["--thread-id", thread_id], creds_dir)
    if isinstance(out, dict) and "error" in out:
        return out
    return out


TOOL_REGISTRY = {
    "search_emails": search_emails,
    "get_calendar_events": get_calendar_events,
    "get_email_thread": get_email_thread,
}


TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "search_emails",
            "description": (
                "Full-text search across Morgan's Gmail. Returns matching messages with from, "
                "subject, date, snippet, and body (up to 2000 chars). Useful for finding past "
                "correspondence with a sender, prior discussion of a topic, or to verify what "
                "was previously promised. Use Gmail search syntax: from:alice@example.com, "
                "subject:budget, after:2026/06/01, label:starred."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Gmail search query, e.g. 'from:alice@example.com meeting'",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum messages to return (1-10, default 5)",
                        "default": 5,
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_calendar_events",
            "description": (
                "List calendar events between two ISO 8601 timestamps. Use to check Morgan's "
                "availability before proposing meeting times, or to see what is on his schedule. "
                "Returns event summary, start/end times, location, attendees, description."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "start_iso": {
                        "type": "string",
                        "description": "Start of range, ISO 8601 (e.g. '2026-07-01T00:00:00Z')",
                    },
                    "end_iso": {
                        "type": "string",
                        "description": "End of range, ISO 8601",
                    },
                },
                "required": ["start_iso", "end_iso"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_email_thread",
            "description": (
                "Fetch the full message list of a Gmail thread by threadId. Use when search_emails "
                "returns a result and you want to see the complete conversation history (all "
                "messages in the thread, oldest to newest)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "thread_id": {
                        "type": "string",
                        "description": "Gmail threadId (16-char hex string from search results)",
                    },
                },
                "required": ["thread_id"],
            },
        },
    },
]
