"""The schedule, which is now one statement instead of three timer units and a
crontab that could not read each other.

Two things are being pinned. The arithmetic, because a cadence that fires twice
sends two daily summaries to the same person and one that never fires is a
watch that expires; and the wiring, because the point of moving the schedule
into the daemon is that nothing else starts these jobs.
"""

import datetime
import json

import pytest

from backend import paths
from backend.daemons import scheduler
from deploy import render_image_manifest
from tools import reachability

UTC = datetime.timezone.utc


def at(year, month, day, hour, minute=0):
    return datetime.datetime(year, month, day, hour, minute, tzinfo=UTC)


@pytest.fixture
def state(monkeypatch, tmp_path):
    """A `state/` of this test's own, so the marker file is this test's."""
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path)
    return tmp_path


@pytest.fixture
def ran(state, monkeypatch):
    """The names `tick` chose to run, with the work itself replaced: what is
    under test here is the decision, not what a daily summary does."""
    names = []
    monkeypatch.setattr(scheduler, "_run", lambda job: names.append(job.name))
    return names


def test_a_cadence_fires_after_the_moment_and_not_on_it():
    """`next_after` is strict. It is called with the last run, so a cadence
    that returned that same firing would run its job in a loop forever."""
    daily = scheduler.Cadence(hours=(5,))
    assert daily.next_after(at(2026, 8, 12, 5)) == at(2026, 8, 13, 5)
    assert daily.next_after(at(2026, 8, 12, 4, 59)) == at(2026, 8, 12, 5)
    assert daily.next_after(at(2026, 8, 12, 5, 1)) == at(2026, 8, 13, 5)


def test_a_weekly_cadence_lands_on_its_weekday():
    weekly = scheduler.Cadence(hours=(4,), weekday=scheduler.MONDAY)
    # 2026-08-12 is a Wednesday; 2026-08-17 is the Monday after it.
    assert weekly.next_after(at(2026, 8, 12, 9)) == at(2026, 8, 17, 4)
    assert weekly.next_after(at(2026, 8, 17, 3)) == at(2026, 8, 17, 4)
    assert weekly.next_after(at(2026, 8, 17, 4)) == at(2026, 8, 24, 4)


def test_a_multi_hour_cadence_takes_the_next_hour_in_the_set():
    every_three = scheduler.Cadence(hours=tuple(range(0, 24, 3)))
    assert every_three.next_after(at(2026, 8, 12, 4)) == at(2026, 8, 12, 6)
    assert every_three.next_after(at(2026, 8, 12, 21, 30)) == at(2026, 8, 13, 0)


def test_a_naive_moment_is_refused():
    """The schedule is UTC in both deployments. A naive datetime here would
    compare against an aware `now` and raise somewhere less obvious."""
    with pytest.raises(AssertionError):
        scheduler.Cadence(hours=(5,)).next_after(datetime.datetime(2026, 8, 12, 5))


def test_a_first_run_is_seeded_rather_than_fired(state, ran):
    """A fresh `state/` must not send every account a daily summary at whatever
    hour the container happened to start."""
    assert scheduler.tick(now=at(2026, 8, 12, 9)) == []
    assert ran == []
    marks = scheduler.load_marks()
    assert set(marks) == {job.name for job in scheduler.SCHEDULE}
    assert marks["email-summary"] == at(2026, 8, 12, 9)


def test_a_time_that_passed_while_the_process_was_down_runs_at_the_next_tick(state, ran):
    """What `Persistent=true` did on the timers and supercronic never did. The
    daemon was down over 05:00; the summary runs when it comes back."""
    scheduler.save_marks({"email-summary": at(2026, 8, 11, 5)})
    scheduler.tick(now=at(2026, 8, 12, 6))
    assert "email-summary" in ran


def test_a_job_whose_time_has_not_come_does_not_run(state, ran):
    scheduler.save_marks({"email-summary": at(2026, 8, 12, 5)})
    scheduler.tick(now=at(2026, 8, 12, 6))
    assert "email-summary" not in ran


def test_a_missed_run_is_not_replayed_once_per_missed_day(state, ran):
    """Catch-up runs the job, not the number of firings it slept through. Six
    days down is one summary, not six."""
    scheduler.save_marks({"email-summary": at(2026, 8, 6, 5)})
    scheduler.tick(now=at(2026, 8, 12, 6))
    assert ran.count("email-summary") == 1


def test_a_run_moves_the_marker_so_the_next_tick_leaves_it_alone(state, ran):
    scheduler.save_marks({"email-summary": at(2026, 8, 11, 5)})
    scheduler.tick(now=at(2026, 8, 12, 6))
    scheduler.tick(now=at(2026, 8, 12, 7))
    assert ran.count("email-summary") == 1


def test_a_failed_run_still_moves_the_marker(state, monkeypatch):
    """A oneshot that exits nonzero under a timer is not retried before its next
    scheduled time, and neither is this. All three jobs are sweeps whose next
    pass covers what this one missed."""
    monkeypatch.setattr(scheduler, "notify_error", lambda *a, **k: None)
    boom = _replace_job(monkeypatch, "email-summary", _raiser(RuntimeError("no")))
    scheduler.save_marks({"email-summary": at(2026, 8, 11, 5)})
    scheduler.tick(now=at(2026, 8, 12, 6))
    assert boom["calls"] == 1
    assert scheduler.load_marks()["email-summary"] > at(2026, 8, 12, 5)


def test_a_job_that_exits_nonzero_does_not_end_the_scheduler(state, monkeypatch):
    """Two of the three call `sys.exit(1)` to tell a oneshot unit they had
    failures. On a thread that is a `SystemExit` which would end the thread and
    silently stop every job scheduled after it."""
    _replace_job(monkeypatch, "email-summary", _raiser(SystemExit(1)))
    later = _replace_job(monkeypatch, "billing-poller", lambda: None)
    scheduler.save_marks({"email-summary": at(2026, 8, 11, 5),
                          "billing-poller": at(2026, 8, 12, 0)})
    scheduler.tick(now=at(2026, 8, 12, 6))
    assert later["calls"] == 1


def test_an_unreadable_marker_seeds_rather_than_runs(state, ran):
    """The file is a hint, not a record. Losing it costs one cycle of each job;
    treating it as "everything is due" would cost a message to every user."""
    (state / scheduler.MARKER_NAME).write_text("{ not json")
    assert scheduler.tick(now=at(2026, 8, 12, 9)) == []
    assert ran == []
    assert set(scheduler.load_marks()) == {job.name for job in scheduler.SCHEDULE}


def test_a_marker_entry_that_is_not_a_timestamp_is_treated_as_new(state, ran):
    (state / scheduler.MARKER_NAME).write_text(json.dumps({"email-summary": "soon"}))
    assert scheduler.tick(now=at(2026, 8, 12, 9)) == []
    assert ran == []


def test_the_marker_is_owner_only(state):
    """It says when each mailbox was last swept, and the only account that reads
    or writes it is the daemon's."""
    scheduler.tick(now=at(2026, 8, 12, 9))
    mode = (state / scheduler.MARKER_NAME).stat().st_mode & 0o777
    assert mode == paths.FILE_MODE_PRIVATE


def test_each_job_names_the_unit_that_runs_it_by_hand():
    """The three units are no longer a schedule -- they are the sandboxed way to
    run one of these jobs on the Hetzner server. That only works while the unit
    starts the same module the thread calls."""
    for job in scheduler.SCHEDULE:
        unit = reachability.UNIT_DIR / f"{job.name}.service"
        assert unit.is_file(), f"{job.name} has no unit to run it by hand"
        assert f"-m {job.module}" in unit.read_text(), (
            f"{unit.name} does not start {job.module}")


def test_nothing_but_the_daemon_starts_a_scheduled_job():
    """The timers are gone and so is the crontab. A second starter would be a
    second schedule, which is the thing this module replaced."""
    assert not list(reachability.UNIT_DIR.glob("*.timer")), (
        "a timer unit is back; the schedule is backend/daemons/scheduler.py")
    flake = reachability.FLAKE.read_text()
    assert "pkgs.supercronic" not in flake, "the image ships a scheduler again"
    assert "writeText \"email-bot-crontab\"" not in flake


def test_a_scheduled_job_is_not_an_entry_point_any_more():
    """They are reached through the scheduler now, not rooted. Leaving them in
    ROLE_ROOTS would mean the manifest still described a process that nothing
    starts."""
    mail = render_image_manifest.ROLE_ROOTS["mail"]
    for job in scheduler.SCHEDULE:
        assert job.module not in mail, (
            f"{job.module} is still listed as something the mail role starts")
    assert mail == {"backend.daemons.daemon_loop"}


def test_the_jobs_still_ship_in_the_mail_image():
    """Reached rather than rooted has to mean reached. The scheduler imports
    each one at module level, so the same walk that builds every other role's
    image finds them."""
    reached = reachability.Graph().reachable_modules({"backend.daemons.daemon_loop"})
    for job in scheduler.SCHEDULE:
        assert job.module in reached, (
            f"{job.module} is no longer reachable from the mail daemon, so it "
            "would not be in the mail image")


def _raiser(err):
    def run():
        raise err
    return run


def _replace_job(monkeypatch, name, run):
    """Swap one job's callable, keeping its cadence. Returns a call counter."""
    counter = {"calls": 0}

    def counted():
        counter["calls"] += 1
        return run()

    replaced = tuple(
        scheduler.Job(job.name, job.module,
                      counted if job.name == name else job.run, job.cadence)
        for job in scheduler.SCHEDULE)
    monkeypatch.setattr(scheduler, "SCHEDULE", replaced)
    return counter
