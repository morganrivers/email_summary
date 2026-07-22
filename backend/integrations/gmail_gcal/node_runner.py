"""Single source of truth for the node subprocess environment.

Node helpers (gmail_lib.mjs) resolve OAuth creds from GMAIL_MCP_DIR. Passing a
per-account creds_dir here is the seam that lets one process serve many users'
mailboxes. creds_dir=None yields env=None (inherit the parent environment), the
historical single-tenant behavior.
"""

import os


def node_env(creds_dir):
    if not creds_dir:
        return None
    return {**os.environ, "GMAIL_MCP_DIR": str(creds_dir)}
