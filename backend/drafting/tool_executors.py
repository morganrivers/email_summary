"""Executors for tools the agentic drafter can call.

Each function takes the tool's arguments as a parsed dict plus the account whose
mailbox the call belongs to, and returns a Python value. Errors come back as
error dicts rather than raising, so a failed lookup is something the model can
read and recover from instead of losing the whole draft.

The account is the argument that used to be a credentials directory handed to a
Node subprocess. It is passed in rather than looked up: the drafter is already
holding it, and a tool that could resolve its own account would be a tool that
could reach a mailbox nobody asked it to.
"""

from backend.integrations.gmail_gcal import calendar_api, gmail_api


def _guard(call):
    """Run one Google call, turning a failure into the error dict the model
    sees. What surfaces is the exception's own text, which names the API and the
    request; a token never appears in one."""
    try:
        return call()
    except Exception as err:
        return {"error": f"{type(err).__name__}: {err}"}


def run_search(query, max_results, account):
    """Sole boundary to Gmail search: a list of messages, or an error dict. The
    tool-facing cap lives in search_emails rather than here, because it is a
    property of the tool (the drafter must not pull an unbounded number of
    messages into a prompt) and not of the search. Voice synthesis reads a wider
    sample of the user's own sent mail through this same seam."""
    assert query, "run_search needs a query"
    assert max_results > 0, f"max_results must be positive, got {max_results}"
    return _guard(lambda: gmail_api.search_messages(account, query, max_results))


def search_emails(args, account):
    query = args.get("query")
    if not query:
        return {"error": "query is required"}
    max_results = min(int(args.get("max_results", 5)), 10)
    out = run_search(query, max_results, account)
    if isinstance(out, dict) and "error" in out:
        return out
    return {"results": out, "count": len(out)}


def get_calendar_events(args, account):
    start_iso = args.get("start_iso")
    end_iso = args.get("end_iso")
    if not start_iso or not end_iso:
        return {"error": "start_iso and end_iso are required (ISO 8601)"}
    out = _guard(lambda: calendar_api.list_events(account, start_iso, end_iso, 50))
    if isinstance(out, dict) and "error" in out:
        return out
    return {"events": out, "count": len(out)}


def get_email_thread(args, account):
    thread_id = args.get("thread_id")
    if not thread_id:
        return {"error": "thread_id is required"}
    return _guard(lambda: gmail_api.get_thread(account, thread_id))


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
