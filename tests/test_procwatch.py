"""The watcher that finds a process the image does not start, and the channel
that tells somebody about it.

`execguard.py` is the prevention and it cannot be raced; this is the backstop
for the case it cannot cover, which is not being installed at all. The rule it
enforces is one line -- one process per container, and it is this one -- so the
subject here is that rule and the two things it does when the rule breaks:
report, then end the process.

The mail role used to be the exception, with supercronic and a shell per
scheduled job. `backend/daemons/scheduler.py` removed those processes, and the
tests that described what they were allowed to be went with them.
"""

import os

import pytest

from backend import intrusion, paths, procwatch
from deploy import render_image_manifest

MINE = os.getpid()

ROLES = sorted(procwatch.SERVICE_MODULES)


def _watching(monkeypatch, pids, cmdlines):
    """A container holding exactly `pids`, with `cmdlines` describing them."""
    monkeypatch.setattr(procwatch, "live_pids", lambda: set(pids))
    monkeypatch.setattr(procwatch, "cmdline", lambda pid: cmdlines.get(pid))


@pytest.mark.parametrize("role", ROLES)
def test_every_role_expects_exactly_itself(monkeypatch, role):
    """One rule, all five roles. Each container's entry point is its
    interpreter and nothing in it starts a second process."""
    _watching(monkeypatch, [MINE], {})
    assert procwatch.check(role) is None


@pytest.mark.parametrize("role", ROLES)
def test_any_second_process_is_refused(monkeypatch, role):
    _watching(monkeypatch, [MINE, 4242], {4242: ["/bin/sh"]})
    with pytest.raises(procwatch.IntrusionRefused) as refusal:
        procwatch.check(role)
    assert refusal.value.entries[0]["pid"] == 4242
    assert "/bin/sh" in refusal.value.entries[0]["cmdline"]


def test_a_process_this_uid_cannot_describe_is_still_reported(monkeypatch):
    """Unreadable is not absent, and it is the more interesting of the two: a
    process in this container that this account cannot name is a process
    running as somebody else."""
    _watching(monkeypatch, [MINE, 7], {})
    with pytest.raises(procwatch.IntrusionRefused) as refusal:
        procwatch.check("web")
    assert refusal.value.entries[0]["cmdline"] == "<unreadable>"


def test_a_pid_that_vanished_mid_scan_is_still_the_finding(monkeypatch):
    """The mail role used to be forgiven this, because its scheduled jobs
    really did start and end three times a day. Nothing starts a process in any
    role now, so a pid that was in the cgroup at all is reported whether or not
    it is still there to be named."""
    _watching(monkeypatch, [MINE, 99], {})
    for role in ROLES:
        with pytest.raises(procwatch.IntrusionRefused):
            procwatch.check(role)


def test_no_argv_buys_a_process_a_place_in_the_container(monkeypatch):
    """There is no allowlist of permitted command lines any more, and this is
    what that means: a second interpreter running the role's own service module
    is refused, and so is one running a formerly scheduled job. Both were
    accepted while the schedule was a set of processes."""
    for argv in (["python", "-m", "backend.daemons.daemon_loop"],
                 ["python", "-m", "backend.drafting.email_summary"],
                 ["/nix/store/def-supercronic/bin/supercronic", "/app/crontab"],
                 ["/bin/sh", "-c", "cd /app && python -m backend.billing.billing_poller"]):
        _watching(monkeypatch, [MINE, 40], {40: argv})
        with pytest.raises(procwatch.IntrusionRefused):
            procwatch.check("mail")


def test_every_watched_role_is_watched_for_the_module_that_starts_it():
    """`role_of(__spec__.name)` is only an identity if the module it is given is
    the one the image actually starts, so the two lists are asserted against
    each other rather than kept in step by hand."""
    roots = render_image_manifest.ROLE_ROOTS
    assert set(procwatch.SERVICE_MODULES) == set(roots)
    for role, module in procwatch.SERVICE_MODULES.items():
        assert module in roots[role], (
            f"{role} is watched for {module}, which is not one of its entry "
            f"points in render_image_manifest.ROLE_ROOTS")


def test_a_role_is_derived_from_the_module_that_was_started():
    """Entry points call `role_of(__spec__.name)` instead of naming their own
    role, so the role a container watches itself as is the module that was
    started rather than a string the compose file supplied."""
    assert procwatch.role_of("frontend.web_server") == "web"
    assert procwatch.role_of("backend.daemons.daemon_loop") == "mail"
    with pytest.raises(AssertionError):
        procwatch.role_of("backend.drafting.email_summary")


def test_only_the_roles_that_mount_state_can_report():
    """`egress` and `ingress` mount no volume, so their report is the container
    exiting and looping. The reporter says so by being None rather than by
    failing to write at the moment it matters."""
    for role in intrusion.REPORTING_ROLES:
        assert intrusion.reporter(role) is not None
    for role in ("egress", "ingress"):
        assert intrusion.reporter(role) is None


def test_a_report_survives_to_the_role_that_can_send_it(monkeypatch, tmp_path):
    """The web tier finds something, writes it, and the mail daemon is what
    drains it: only that role holds a Telegram token, and putting one in the
    process facing the internet to alert about the process facing the internet
    would be the trade this split exists to refuse."""
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path)
    intrusion.reporter("web")({"pid": 4242, "cmdline": "/bin/sh"})
    drained = intrusion.drain()
    assert len(drained) == 1
    assert drained[0]["role"] == "web"
    assert drained[0]["pid"] == 4242
    assert "4242" in intrusion.summarize(drained)
    assert intrusion.drain() == []


def test_a_report_that_cannot_be_written_does_not_stop_the_exit(monkeypatch, tmp_path):
    """The process writing one has already found something it cannot explain
    about itself, so the write may be into a filesystem an attacker controls.
    It must not be what the exit waits on.

    The unwritable path is a directory under a regular file, which fails in the
    mkdir rather than in the open: a path that merely does not exist yet is one
    `ensure_run_dir` creates, so it would have tested the opposite."""
    blocked = tmp_path / "not-a-directory"
    blocked.write_text("")
    monkeypatch.setattr(paths, "RUN_DIR", blocked / "state")
    intrusion.reporter("web")({"pid": 1, "cmdline": "x"})


def test_the_refusal_ends_the_process_rather_than_the_thread(monkeypatch):
    """`os._exit`, not `sys.exit`: this runs on a thread, where `SystemExit`
    ends the thread and leaves the compromised process serving."""
    ended = {}
    monkeypatch.setattr(os, "_exit", lambda code: ended.setdefault("code", code))
    sent = []
    err = procwatch.IntrusionRefused("found", [{"pid": 9, "cmdline": "sh"}])
    procwatch._refuse("web", err, sent.append)
    assert ended["code"] == procwatch.EXIT_INTRUSION
    assert sent == [{"pid": 9, "cmdline": "sh"}]
