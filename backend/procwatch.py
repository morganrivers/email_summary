"""Watch this container for a process that should not be in it, and refuse to
keep running if one appears.

`execguard.py` is the prevention and it is the stronger half: a seccomp filter
cannot be raced, and nothing this module does would catch an `execve` that the
filter already killed. This is the backstop under it, and the rule it enforces
is one line -- every container runs one process, and that process is the one
reading this.

The rule used to have an exception. The mail role ran supercronic beside the
daemon and a shell per scheduled job, and those were processes the filter was
never installed in, so this module carried an allowlist of what the crontab was
permitted to be running. `backend/daemons/scheduler.py` moved the schedule onto
a thread and the exception went with it: there is no child process in any role
now, so there is nothing to allow.

That leaves this module covering the case the filter cannot: not being there.
`lock_down` is fatal under TEE_REQUIRED and a warning otherwise, so a kernel or
a runtime that refuses the filter is a process that can still `execve` -- and a
container nobody prevented anything in is exactly the one worth watching. It is
also the answer to "what if somebody got in anyway", which a measured image
still has to answer, and answering it with silence was the gap. A process that
appears here is a breach, and a breach that nobody hears about is the expensive
kind.

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
That is the price of an exact expected set, and the set is exact because a role
that legitimately starts processes cannot have one.
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
    own role, so the role a container watches itself as is the module that was
    actually started rather than a string a compose file supplied."""
    for role, name in SERVICE_MODULES.items():
        if name == module:
            return role
    raise AssertionError(
        f"{module!r} is not any role's service module; add it to "
        "SERVICE_MODULES or it will be watched as nothing")


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


def expected(pid):
    """Whether this process belongs in this container. Exactly one does.

    Identity by pid and never by name. The role's own service module is
    deliberately not an accepted argv: this watcher runs inside that process,
    so it is already answered by the pid, and accepting the name would accept a
    *second* daemon nobody started. Nothing else is accepted at all, which is
    what removes the argv-matching this function used to do -- every allowlist
    of command lines is one an attacker gets to write half of."""
    return pid == os.getpid()


def check(role):
    """Raise `IntrusionRefused` if this container holds a process it should
    not. Separated from the loop below so the rule is testable without a thread
    and without ending the test runner."""
    assert role in SERVICE_MODULES, f"unknown role {role!r}"
    unexpected = []
    for pid in sorted(live_pids()):
        if expected(pid):
            continue
        # No benefit of the doubt for a pid that vanished between the listing
        # and the read. That allowance existed for the mail role's scheduled
        # jobs, which really did start and end three times a day; nothing
        # starts a process here now, so a pid that existed at all is the
        # finding whether or not it is still there to be named.
        argv = cmdline(pid)
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
