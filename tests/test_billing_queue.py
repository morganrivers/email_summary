"""The Polar receiver spools; the daemon applies.

What these pin is a permission boundary, not a feature: the process that parses
signatures from the open internet must not be the process that writes
database/accounts.json, which is every account's plan, its Polar link and the
store's integrity.
"""

import json

from backend import paths
from backend.accounts import account
from backend.billing import billing_queue, billing_webhook
from backend.daemons import daemon_loop


def _event(kind="order.paid", email="buyer@x.com"):
    return {"type": kind, "data": {"customer": {"email": email}}}


def test_spool_roundtrip_keeps_every_event_in_order(tmp_path, monkeypatch):
    """Not deduped, unlike the wake spool: two events for one customer are two
    facts about a timeline and the second is not a repeat of the first."""
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path)
    assert billing_queue.drain() == []
    billing_queue.enqueue(_event("order.paid"))
    billing_queue.enqueue(_event("subscription.canceled"))
    billing_queue.enqueue(_event("order.paid"))
    drained = billing_queue.drain()
    assert [e["type"] for e, _ in drained] == [
        "order.paid", "subscription.canceled", "order.paid"]
    assert [attempts for _, attempts in drained] == [0, 0, 0]
    assert billing_queue.drain() == []


def test_the_receiver_writes_the_spool_and_not_the_account_store(tmp_path, monkeypatch):
    """DeferredBilling is what the unit holds where it used to hold a
    PolarBilling. Pointing MANIFEST at a path that does not exist is the
    assertion: any write would raise rather than quietly pass."""
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path)
    monkeypatch.setattr(account, "MANIFEST", tmp_path / "absent" / "accounts.json")

    result = billing_queue.DeferredBilling().apply_event(_event())

    assert "spooled" in result
    assert [e["type"] for e, _ in billing_queue.drain()] == ["order.paid"]


def test_a_malformed_spool_line_does_not_stop_the_rest(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path)
    billing_queue.enqueue(_event())
    with open(tmp_path / "billing_queue.jsonl", "a") as fh:
        fh.write(json.dumps({"not_an_event": True}) + "\n")
    assert [e["type"] for e, _ in billing_queue.drain()] == ["order.paid"]


def test_the_daemon_applies_what_was_spooled(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path)
    applied = []

    class FakeBilling:
        def apply_event(self, event):
            applied.append(event["type"])
            return "ok"

    monkeypatch.setattr(daemon_loop, "PolarBilling", FakeBilling)
    billing_queue.enqueue(_event("order.paid"))
    billing_queue.enqueue(_event("subscription.active"))

    daemon_loop.process_billing()

    assert applied == ["order.paid", "subscription.active"]
    assert billing_queue.drain() == [], "applied events were left on the spool"


def test_one_failing_event_does_not_strand_the_others(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path)
    seen = []

    class FakeBilling:
        def apply_event(self, event):
            seen.append(event["type"])
            if event["type"] == "boom":
                raise RuntimeError("polar said no")
            return "ok"

    monkeypatch.setattr(daemon_loop, "PolarBilling", FakeBilling)
    monkeypatch.setattr(daemon_loop, "notify_error", lambda *a, **k: None)
    billing_queue.enqueue(_event("boom"))
    billing_queue.enqueue(_event("order.paid"))

    daemon_loop.process_billing()

    assert seen == ["boom", "order.paid"]


def test_a_failed_event_is_applied_on_a_later_pass(tmp_path, monkeypatch):
    """Polar was acked when the receiver spooled this, so nothing upstream will
    send it again. Without the retry, one timed-out call inside apply_event is
    an entitlement change that never happens."""
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path)
    attempts = []

    class FlakyBilling:
        def apply_event(self, event):
            attempts.append(event["type"])
            if len(attempts) == 1:
                raise RuntimeError("polar timed out")
            return "ok"

    monkeypatch.setattr(daemon_loop, "PolarBilling", FlakyBilling)
    billing_queue.enqueue(_event("subscription.active"))

    daemon_loop.process_billing()
    assert billing_queue.pending() is True, "a failed event was not put back"

    daemon_loop.process_billing()
    assert attempts == ["subscription.active", "subscription.active"]
    assert billing_queue.drain() == []


def test_an_event_that_never_applies_is_dropped_once_and_alerted(tmp_path, monkeypatch):
    """The other half: a retry that cannot end is a spool that grows forever and
    a daemon that spends every pass on the same failure. The alert fires on the
    drop and not on the attempts, so a failure the next pass settles wakes
    nobody and one that never settles is not a log line nobody reads."""
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path)
    alerts = []
    tries = []

    class BrokenBilling:
        def apply_event(self, event):
            tries.append(event["type"])
            raise RuntimeError("permanently broken")

    monkeypatch.setattr(daemon_loop, "PolarBilling", BrokenBilling)
    monkeypatch.setattr(daemon_loop, "notify_error",
                        lambda msg, err: alerts.append(msg))
    billing_queue.enqueue(_event("order.paid"))

    for _ in range(billing_queue.MAX_ATTEMPTS + 3):
        daemon_loop.process_billing()

    assert len(tries) == billing_queue.MAX_ATTEMPTS
    assert len(alerts) == 1 and "dropped" in alerts[0]
    assert billing_queue.pending() is False


def test_retry_carries_the_count_and_refuses_past_the_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path)
    event = _event("subscription.canceled")

    assert billing_queue.retry(event, 0) is True
    assert billing_queue.drain() == [(event, 1)]
    assert billing_queue.retry(event, billing_queue.MAX_ATTEMPTS - 1) is False
    assert billing_queue.pending() is False, "a dropped event was still spooled"


def test_an_entry_from_a_receiver_that_wrote_no_count_still_drains(tmp_path, monkeypatch):
    """The receiver and the daemon restart independently, so a spool written by
    the previous version of one is read by the next version of the other."""
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path)
    with open(tmp_path / "billing_queue.jsonl", "a") as fh:
        fh.write(json.dumps({"event": _event()}) + "\n")
        fh.write(json.dumps({"event": _event(), "attempts": "lots"}) + "\n")
    assert [a for _, a in billing_queue.drain()] == [0, 0]


def test_no_polar_client_is_built_when_nothing_is_spooled(tmp_path, monkeypatch):
    """A box with no Polar configured must not pay a constructor, and its
    asserts, on every pass of the daemon loop."""
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path)

    def explode():
        raise AssertionError("PolarBilling built with an empty spool")

    monkeypatch.setattr(daemon_loop, "PolarBilling", explode)
    daemon_loop.process_billing()


def test_an_unconfigured_polar_leaves_the_events_on_the_spool(tmp_path, monkeypatch):
    """The constructor is built before the drain, and this is why.

    `PolarBilling()` asserts its way out when POLAR_API_TOKEN is absent. Built
    after `drain()`, that assertion discards every event it was about to apply:
    the spool is already cleared, the exception lands in the daemon loop's outer
    handler, and on a box missing that token the 3-hourly poller cannot run
    either, so nothing recovers them. A paid subscription silently never
    activates."""
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path)

    def unconfigured():
        raise AssertionError("missing POLAR_API_TOKEN / POLAR_ORGANIZATION_ID")

    monkeypatch.setattr(daemon_loop, "PolarBilling", unconfigured)
    billing_queue.enqueue(_event("order.paid"))

    daemon_loop.process_billing()

    assert [e["type"] for e, _ in billing_queue.drain()] == ["order.paid"], (
        "events were consumed by a pass that could not apply them")


def test_pending_reports_work_without_consuming_it(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path)
    assert billing_queue.pending() is False
    billing_queue.enqueue(_event())
    assert billing_queue.pending() is True
    assert len(billing_queue.drain()) == 1
    assert billing_queue.pending() is False


def test_the_receiver_holds_no_api_token_and_no_account_store():
    """The imports whose absence is the isolation, read as an AST so the prose
    explaining the decision does not satisfy the test. PolarBilling reaches the
    manifest and the Polar API; either one back in this module puts the
    signature verifier in front of user data again."""
    import ast
    import inspect

    imported = set()
    for node in ast.walk(ast.parse(inspect.getsource(billing_webhook))):
        if isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)

    assert "PolarBilling" not in imported
    assert not any("accounts" in name for name in imported)
    assert not any(name.endswith("custody") or ".custody." in name for name in imported)
