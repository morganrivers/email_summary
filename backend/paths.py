"""Single source of truth for on-disk locations.

Every module resolves shared paths through here instead of its own
``Path(__file__).parent``, so relocating code between packages never breaks the
location of ``.env``, the account store, or runtime scratch (the wake FIFO and
lock files).

Layout under the app root (``/opt/letterlock`` on the box):

    backend/ frontend/ deploy/   code, and the only thing deploy.sh writes
    .env  .gmail-mcp/            secrets, at the top
    state/                       mutable runtime scratch, one directory
    database/                    account store
    config/                      operator-supplied prompts, synced from
                                 ~/.system_files by deploy.sh

Runtime scratch is grouped under ``state/`` rather than dropped beside the
source: a deploy can then reason about "code" and "not code" by directory
instead of by filename.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"

ENV_FILE = REPO_ROOT / ".env"
STATIC_DIR = REPO_ROOT / "frontend" / "static"
DATABASE_DIR = REPO_ROOT / "database"
RUN_DIR = REPO_ROOT / "state"
CONFIG_DIR = REPO_ROOT / "config"

# Where these files lived before the app got its own config directory. A dev
# checkout still reads them from here, so only the box needs config/ populated.
LEGACY_CONFIG_DIR = Path.home() / ".system_files"


def config_file(name):
    """Operator-supplied config (the summary prompt, the voice profile). Prefers
    the deployed copy under config/ and falls back to ~/.system_files, so the
    same code path serves the box and a laptop checkout."""
    deployed = CONFIG_DIR / name
    return deployed if deployed.exists() else LEGACY_CONFIG_DIR / name


def relative_if_inside(path):
    """A manifest-ready form of `path`: relative to the app root when it lives
    under it, absolute otherwise. Storing the relative form means the manifest
    survives the directory being renamed (as /opt/email_summary ->
    /opt/letterlock was). account._resolve() reads both forms."""
    try:
        return str(Path(path).resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def ensure_run_dir():
    """Create the runtime scratch directory on first write. Called by the things
    that write into it rather than at import, so importing a module never has a
    filesystem side effect."""
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    return RUN_DIR
