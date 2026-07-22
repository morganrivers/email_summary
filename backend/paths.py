"""Single source of truth for on-disk locations.

Every module resolves shared paths through here instead of its own
``Path(__file__).parent``, so relocating code between packages never breaks the
location of ``.env``, the Node bridge scripts, the account store, or runtime
scratch (the wake FIFO and lock files).
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"

ENV_FILE = REPO_ROOT / ".env"
GMAIL_GCAL_DIR = BACKEND_DIR / "integrations" / "gmail_gcal"
DATABASE_DIR = REPO_ROOT / "database"
RUN_DIR = REPO_ROOT


def node_script(name):
    """Absolute path to a Gmail/Calendar Node bridge script by filename."""
    path = GMAIL_GCAL_DIR / name
    assert path.suffix == ".mjs", f"node_script expects a .mjs file, got {name!r}"
    return path
