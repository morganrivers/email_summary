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
    assert [e["type"] for e in drained] == [
        "order.paid", "subscription.canceled", "order.paid"]
    assert billing_queue.drain() == []


def test_the_receiver_writes_the_spool_and_not_the_account_store(tmp_path, monkeypatch):
    """DeferredBilling is what the unit holds where it used to hold a
    PolarBilling. Pointing MANIFEST at a path that does not exist is the
    assertion: any write would raise rather than quietly pass."""
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path)
    monkeypatch.setattr(account, "MANIFEST", tmp_path / "absent" / "accounts.json")

    result = billing_queue.DeferredBilling().apply_event(_event())

    assert "spooled" in result
    assert [e["type"] for e in billing_queue.drain()] == ["order.paid"]


def test_a_malformed_spool_line_does_not_stop_the_rest(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path)
    billing_queue.enqueue(_event())
    with open(tmp_path / "billing_queue.jsonl", "a") as fh:
        fh.write(json.dumps({"not_an_event": True}) + "\n")
    assert [e["type"] for e in billing_queue.drain()] == ["order.paid"]


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


def test_no_polar_client_is_built_when_nothing_is_spooled(tmp_path, monkeypatch):
    """A box with no Polar configured must not pay a constructor, and its
    asserts, on every pass of the daemon loop."""
    monkeypatch.setattr(paths, "RUN_DIR", tmp_path)

    def explode():
        raise AssertionError("PolarBilling built with an empty spool")

    monkeypatch.setattr(daemon_loop, "PolarBilling", explode)
    daemon_loop.process_billing()


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
