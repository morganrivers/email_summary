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

It is also the single source of truth for the *modes* those locations carry,
because the answer stopped being "0600, owner only" when the web tier moved to
its own uid. Two uids now write ``database/`` and ``state/``, and the modes are
what say which of them may read a given file. See ``shared_dir`` below.
"""

import grp
import os
import pwd
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"

ENV_FILE = REPO_ROOT / ".env"

# The Polar webhook signing secret, and nothing else, kept out of .env so the
# unit that verifies those signatures does not also hold SESSION_SECRET (which
# mints login cookies) and the inference keys. It is the only secret the Polar
# receiver reads, which is what lets that unit run without SECRETS_GROUP. Every
# other Polar value, the API token included, stays in .env: the receiver no
# longer calls Polar's API, so nothing else needs to move.
BILLING_ENV_FILE = REPO_ROOT / ".env.billing"

# TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID, and nothing else. Read by no Python
# here: systemd hands it to cosigner.service as `EnvironmentFile=`, as root,
# before dropping to that unit's account, which is how the process holding the
# outer wrapping key gets an alert channel without getting .env. Named here so
# the deploy and the enclave's boot gate both know the file exists.
ALERTS_ENV_FILE = REPO_ROOT / ".env.alerts"
STATIC_DIR = REPO_ROOT / "frontend" / "static"
DATABASE_DIR = REPO_ROOT / "database"
RUN_DIR = REPO_ROOT / "state"
CONFIG_DIR = REPO_ROOT / "config"

# Where these files lived before the app got its own config directory. A dev
# checkout still reads them from here, so only the box needs config/ populated.
LEGACY_CONFIG_DIR = Path.home() / ".system_files"

# The group holding database/ and state/. Its members are the two uids that
# write account data: the mail units and the web UI. Deliberately not
# `letterlock`, which cosigner and egress carry as a supplementary group to
# reach the source and the venv -- widening those two into the account store is
# exactly what this group exists to avoid.
DATA_GROUP = "letterlock-data"

# The group holding .env. Same two members and the same reason for being its
# own group. Splitting the file itself, so the web tier never sees the
# inference keys, is a separate change: this one is about mailbox access.
SECRETS_GROUP = "letterlock-secrets"

# The account the web UI runs as, named here because two things need to agree
# about it: the deploy that creates it from `User=` in the drop-in, and
# `custody/handoff_server.py`, which is the one place a uid is checked rather
# than assumed. The socket's mode is still the grant; this name is what lets
# the listener refuse a peer the mode should never have admitted, so a widening
# from some future path change is a refusal in a log rather than an open door.
WEB_USER = "letterlock-web"

# The group holding the wake path: state/wake.fifo and the two wake_queue files.
# Its members are the mail uid and the Gmail push receiver, and nobody else.
#
# It is not DATA_GROUP, and the difference is the point. Poking the FIFO makes
# the daemon run, and a line in the spool names which account it runs for, so
# write access there is the ability to drive mail processing for an account of
# the writer's choosing. Each one costs that account a co-signer
# unwrap-and-sign. DATA_GROUP holds the web uid and the billing uid too, and
# neither has any business waking the daemon: at 0660 to that group the least
# trusted process on the box could walk the account list, spend the co-signer's
# hourly ceiling, and trip cosigner.policy._sweep_refusal, which refuses and
# alerts and stops mail for everyone until an operator clears it. No mail
# content reaches the writer either way, so this is an availability boundary
# rather than a confidentiality one, which is why it is a group and not a
# protocol change.
WAKE_GROUP = "letterlock-wake"

# The group holding the billing spool: the Polar receiver writes it, the mail
# daemon drains it. Separate from WAKE_GROUP because the two spools are two
# capabilities -- an entry on the wake path starts a drafting pass against a
# named account and spends that account's co-signer budget, and an entry here
# does not. Handing the billing receiver the wake group would give it the one
# thing it has no reason to do.
BILLING_QUEUE_GROUP = "letterlock-billing-queue"

# The group holding .env.billing. Its only member is the Polar receiver.
BILLING_SECRETS_GROUP = "letterlock-billing-secrets"

DIR_MODE_PRIVATE = 0o700
# setgid, so a directory created by either uid hands its files to the shared
# group rather than to whichever account happened to write first.
DIR_MODE_SHARED = 0o2770
# state/ only, and the extra bit is execute for others, never read. Four uids
# now open a file in there and they are deliberately not all in one group: the
# two webhooks reach their own spool and must not reach the account store, and
# DATA_GROUP grants both. Traversal is what lets a file's own mode be the
# grant. It confers nothing by itself -- every file in state/ is 0600 or 0660
# to a named group, so an account that can walk in still opens nothing -- and
# it does not extend to listing, which is why database/ does not get it: who
# has an account there is itself worth keeping.
DIR_MODE_TRAVERSABLE = 0o2771
FILE_MODE_PRIVATE = 0o600
FILE_MODE_SHARED = 0o660


def _gid(name):
    """A group's gid, or None where it does not exist.

    A checkout on a laptop has no such group, and neither does the box until
    the deploy that creates it has run. Both cases fall back to owner-only,
    which is what every one of these paths was before the split: the code can
    land ahead of the deploy without opening database/ to the co-signer's
    supplementary group in the window between them."""
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        return None


def data_gid():
    return _gid(DATA_GROUP)


def wake_gid():
    return _gid(WAKE_GROUP)


def billing_queue_gid():
    return _gid(BILLING_QUEUE_GROUP)


def web_uid():
    """The web tier's uid, or None where that account does not exist.

    None is a laptop, where the web UI and the daemon are the same person and
    the handoff peer check passes on the caller's own uid instead. It is not a
    reason to skip the check: an account that should exist and does not is a
    box where nothing runs as `WEB_USER` either, so refusing everything but our
    own uid is the correct answer in both cases."""
    try:
        return pwd.getpwnam(WEB_USER).pw_uid
    except KeyError:
        return None


def _adopt_group(path, gid):
    """Hand `path` to the shared group. Silent when this process does not own
    it: the other uid created it and has already set the group, and chown by a
    non-owner is refused rather than being a state worth reporting."""
    try:
        os.chown(path, -1, gid)
        return True
    except OSError:
        return False


def chmod_if_owned(path, mode):
    """Set `mode` when this process owns `path`, and do nothing when it does
    not. Same reason `_adopt_group` is silent: several uids in the shared group
    reach the same directories and the same spool files, and only one of them
    created any given one. chmod by a non-owner is EPERM, so without the guard
    the second uid to arrive raises on the first write of every request, and a
    permission decision surfaces as a crash.

    Doing nothing is correct rather than merely quiet: the owner sets the mode
    when it creates the path, so a non-owner reaching it is looking at a mode
    that is already right."""
    try:
        if os.stat(path).st_uid != os.getuid():
            return False
    except OSError:
        return False
    try:
        os.chmod(path, mode)
        return True
    except OSError:
        return False


def shared_dir(path, mode):
    """Create a directory the mail uid and the web uid share, and nobody else
    reaches.

    Owner-only where the shared group does not exist, so this is never a
    widening: it either grants the one group both uids are in, or it grants
    nobody.

    `mode` is required and has no default. It used to default to
    DIR_MODE_SHARED, and `backend/audit.py` took the default for `state/`, so
    the first audit row written after a boot re-set that directory from 2771 to
    2770 and the Gmail push receiver -- outside DATA_GROUP by design -- silently
    stopped being able to traverse to its own spool. The mode is the grant, so
    the caller has to say which one it means: a directory has one correct mode
    and the module that owns the directory is what knows it."""
    assert mode in (DIR_MODE_SHARED, DIR_MODE_TRAVERSABLE), f"unexpected {mode:o}"
    path.mkdir(parents=True, exist_ok=True)
    gid = data_gid()
    if gid is None:
        chmod_if_owned(path, DIR_MODE_PRIVATE)
        return path
    _adopt_group(path, gid)
    chmod_if_owned(path, mode)
    return path


def file_mode(shared=True):
    """The mode for a file under database/ or state/.

    `shared=False` is the mail uid's alone, and there is exactly one such file:
    the wrapped refresh token. The web tier holds the account's data key while
    it renders a document, so a token it could also read would open under that
    key -- the mode is what makes the two paths different capabilities rather
    than two names for one."""
    assert isinstance(shared, bool), "file_mode takes a flag, not a mode"
    if not shared or data_gid() is None:
        return FILE_MODE_PRIVATE
    return FILE_MODE_SHARED


def write_private(path, text):
    """Write `text` to `path`, which never exists at a mode anyone else can
    read.

    The alternative -- ``write_text`` then ``chmod`` -- leaves the file readable
    for the width of two syscalls, at whatever the directory and umask allow.
    That is not academic here: the enclave writes its RA-TLS private keys onto a
    tmpfs the compose file mounts at mode 0777, because the runtime creates it
    as root and the container's process is not root, so the widest the file can
    briefly be is world-readable.

    ``O_TRUNC`` and an explicit ``fchmod`` because the mode argument to
    ``os.open`` applies only when the file is created: a rewrite would otherwise
    keep whatever mode the previous one had."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE_PRIVATE)
    with os.fdopen(fd, "w") as handle:
        os.fchmod(fd, FILE_MODE_PRIVATE)
        handle.write(text)
    return path


def group_file(path, gid):
    """Hand one file to `gid` at the mode that group can use.

    Owner-only where the group does not exist, which is the laptop and the box
    before the deploy that creates it. That direction is a narrowing, so code
    landing ahead of its deploy stops the second uid writing rather than
    opening the file to anyone."""
    if gid is None:
        chmod_if_owned(path, FILE_MODE_PRIVATE)
        return path
    _adopt_group(path, gid)
    chmod_if_owned(path, FILE_MODE_SHARED)
    return path


def wake_file(path):
    """The FIFO and the wake spool, whose writers are the mail daemon and the
    Gmail push receiver. Sole answer for both, so `daemon_loop` and
    `wake_queue` cannot disagree about who may wake whom."""
    return group_file(path, wake_gid())


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
    filesystem side effect.

    Shared, because the web tier writes the audit log here and the daemon
    writes the wake spool and the custody socket beside it. Traversable rather
    than merely shared, because the two webhooks write their spools here too
    and are deliberately outside DATA_GROUP: see DIR_MODE_TRAVERSABLE."""
    return shared_dir(RUN_DIR, DIR_MODE_TRAVERSABLE)
