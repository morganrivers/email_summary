"""The schedule, and the thread in the mail daemon that runs it.

Three jobs run on a clock rather than on a wake: the daily summary, the weekly
`users.watch` renewal, and the Polar reconcile. They used to be started by two
different mechanisms that could not read each other -- three systemd timers on
the Hetzner server and a crontab beside the daemon in the enclave -- so the
cadence was written twice and held in step by a test comparing text. `SCHEDULE`
below is now the only statement of it, and both deployments run this thread.

This is also what makes every container single-process. supercronic started a
shell per job, and a shell is a process `execguard.py`'s seccomp filter was
never installed in; the filter kills `execve` in the process that installs it
and says nothing about a child that predates it. With the schedule inside the
daemon there is no child, so the filter covers the whole container and
`procwatch.expected()` is "one process, mine" for all five roles.

The jobs keep their `__main__` blocks. `python -m backend.drafting.email_summary`
is still how an operator runs one by hand, and `deploy/hetzner/*.service` still
names each one, so the unit is a sandboxed handle rather than a schedule.
`tests/test_scheduler.py` asserts each job's module against that unit's
`ExecStart`.

Catch-up, which the two old mechanisms disagreed about: the timers were
`Persistent=true` and re-ran a job whose time passed while the machine was
down; supercronic never did. A job here records when it last ran, so the answer
is the timers' answer in both deployments -- a scheduled time that passed
unobserved runs at the next tick.

The exception is a marker that is missing or unreadable, which is treated as
"not due" and seeded with the current time. A fresh `state/` would otherwise
fire all three jobs at whatever hour the container first started, and a daily
summary is a message to a person. The file is a hint and not a record: losing
it costs at most one cycle of each job, and the direction of that failure is
"runs later" rather than "runs twice".

A run that raises is still a run. The marker moves either way and the next
attempt is at the next scheduled time, which is what a failed oneshot under a
timer does. Failures alert; they do not retry, because every one of these three
is a sweep whose next pass covers what this one missed.
"""

from __future__ import annotations

import datetime
import json
import threading
import time

from backend import paths
from backend.billing import billing_poller
from backend.drafting import email_summary
from backend.integrations.telegram import notify_error
from backend.onboarding import watch_renew

MONDAY = 0

# How often the thread wakes to ask whether anything is due. The jobs are
# scheduled to the minute, so this bounds how late one can be. A poll rather
# than a sleep computed to the next due time because the wall clock can move
# and this way there is one code path that handles it.
POLL_SECONDS = 60

MARKER_NAME = "schedule.json"


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


class Cadence:
    """When a job runs, as the set of wall-clock times it fires at.

    Deliberately narrower than cron: an hour set, a minute, and an optional
    weekday is every cadence this product has, and a general parser would be
    more code than the three lines it reads."""

    # Longer than the longest gap any cadence here can have (a weekly job, so
    # seven days) plus a day of margin, so `next_after` searching past this is
    # a cadence that never fires rather than one that fires late.
    HORIZON_HOURS = 8 * 24

    def __init__(self, hours, minute=0, weekday=None):
        assert hours, "a cadence fires at at least one hour"
        assert all(0 <= hour <= 23 for hour in hours), f"bad hours {hours}"
        assert 0 <= minute <= 59, f"bad minute {minute}"
        assert weekday is None or 0 <= weekday <= 6, f"bad weekday {weekday}"
        self.hours = tuple(sorted(hours))
        self.minute = minute
        self.weekday = weekday

    def next_after(self, moment):
        """The first firing strictly after `moment`, in UTC.

        Strictly, because `moment` is the last run: a cadence that returned its
        own last firing would run a job forever in a loop."""
        assert moment.tzinfo is not None, "schedule arithmetic is in UTC"
        start = moment.replace(minute=self.minute, second=0, microsecond=0)
        for step in range(self.HORIZON_HOURS):
            candidate = start + datetime.timedelta(hours=step)
            if candidate <= moment:
                continue
            if candidate.hour not in self.hours:
                continue
            if self.weekday is not None and candidate.weekday() != self.weekday:
                continue
            return candidate
        raise AssertionError(f"no firing within {self.HORIZON_HOURS}h of {moment}")


class Job:
    """One scheduled unit of work: what to call, and what an operator calls to
    run the same thing by hand."""

    def __init__(self, name, module, run, cadence):
        assert callable(run), f"{name} has nothing to run"
        self.name = name
        self.module = module
        self.run = run
        self.cadence = cadence


# The cadences the three timer units and the enclave crontab used to carry.
# Times are UTC in both deployments.
SCHEDULE = (
    Job("email-summary", "backend.drafting.email_summary",
        email_summary.main, Cadence(hours=(5,))),
    Job("gmail-watch", "backend.onboarding.watch_renew",
        watch_renew.main, Cadence(hours=(4,), weekday=MONDAY)),
    Job("billing-poller", "backend.billing.billing_poller",
        billing_poller.main, Cadence(hours=tuple(range(0, 24, 3)))),
)


def log(msg):
    print(f"[scheduler] {msg}", flush=True)


def marker_path():
    """Resolved per call rather than at import, because `paths.RUN_DIR` is a
    constant a test redirects."""
    return paths.RUN_DIR / MARKER_NAME


def load_marks():
    """When each job last ran, by name. A file that cannot be read or parsed is
    the same answer as no file: nothing is known, which the caller turns into
    "not due" rather than into a run."""
    try:
        raw = json.loads(marker_path().read_text())
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as err:
        log(f"{marker_path()} unreadable ({err}); every job is treated as new")
        return {}
    if not isinstance(raw, dict):
        log(f"{marker_path()} is not an object; every job is treated as new")
        return {}
    marks = {}
    for name, stamp in raw.items():
        try:
            moment = datetime.datetime.fromisoformat(str(stamp))
        except ValueError:
            log(f"{name} has an unparseable last run {stamp!r}; treated as new")
            continue
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=datetime.timezone.utc)
        marks[name] = moment
    return marks


def save_marks(marks):
    """Owner-only, and never wider: the only writer and the only reader is this
    daemon's account, and the file says when a mailbox was last swept."""
    paths.ensure_run_dir()
    paths.write_private(
        marker_path(),
        json.dumps({name: moment.isoformat() for name, moment in marks.items()},
                   indent=2, sort_keys=True))


def due(now, marks):
    """The jobs whose next firing after their last run has already passed.

    A job with no mark is not due. That is the seeding case and it is handled
    by the caller, which records `now` for it; deciding it here would make a
    first boot send every account a summary at an arbitrary hour."""
    ready = []
    for job in SCHEDULE:
        last = marks.get(job.name)
        if last is None:
            continue
        if job.cadence.next_after(last) <= now:
            ready.append(job)
    return ready


def _run(job):
    """One job, with its failure kept off the daemon.

    `SystemExit` is caught by name: two of these call `sys.exit(1)` to tell a
    oneshot unit they had failures, and on a thread that would end the thread
    silently and stop the schedule for every job after it."""
    log(f"{job.name}: starting")
    started = time.monotonic()
    try:
        job.run()
    except SystemExit as err:
        if err.code:
            log(f"{job.name}: exited {err.code}")
    except Exception as err:
        log(f"{job.name}: failed: {type(err).__name__}: {err}")
        notify_error(f"scheduled job {job.name} failed", err)
        return
    log(f"{job.name}: done in {time.monotonic() - started:.1f}s")


def tick(now=None):
    """Run whatever is due, and record it. Separated from the loop so the rule
    is testable without a thread and without a clock.

    Returns the jobs it ran, which is what the tests assert on."""
    now = now or _utcnow()
    marks = load_marks()
    seeded = [job.name for job in SCHEDULE if job.name not in marks]
    for name in seeded:
        marks[name] = now
        log(f"{name}: first seen; next run is at its next scheduled time")
    ran = due(now, marks)
    for job in ran:
        _run(job)
        marks[job.name] = _utcnow()
    if seeded or ran:
        save_marks(marks)
    return ran


def _loop(poll):
    while True:
        try:
            tick()
        except Exception as err:
            # The schedule must outlive one bad pass: a marker file that cannot
            # be written is not a reason to stop running the jobs, and the
            # per-job failures are already handled above this.
            log(f"tick failed: {type(err).__name__}: {err}")
        time.sleep(poll)


def start(poll=POLL_SECONDS):
    """Begin running the schedule, on a daemon thread.

    A daemon thread, so a job in flight does not hold up the restart the daemon
    does on `restart.flag` -- the same as a timer-driven oneshot, which systemd
    also does not wait for."""
    thread = threading.Thread(target=_loop, args=(poll,), name="scheduler",
                              daemon=True)
    thread.start()
    return thread
