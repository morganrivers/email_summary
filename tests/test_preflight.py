"""What the deploy refuses to restart.

Only the custody dependency is pinned here. It is the one preflight rule that is
not about a value being present: a mail unit whose co-signer cannot start has
nothing to do but alert the operator on every wake, because there is no bypass
(docs/plan_token_custody.md §1, invariant 3), and that is a deploy-time fact
rather than a runtime one.
"""

from deploy import preflight


def test_a_mail_unit_waits_for_the_cosigner_on_the_same_box(monkeypatch):
    monkeypatch.setattr(preflight, "_manifest_present", lambda: None)
    monkeypatch.setattr(preflight.secrets_checks, "google_oauth_configured", lambda: None)
    monkeypatch.setattr(preflight, "unit_for_module", lambda module: "cosigner.service")
    monkeypatch.setattr(preflight, "_cosigner_configured",
                        lambda: "sealed credentials missing: /etc/credstore.encrypted/x")

    reason = preflight._mail_configured()
    assert reason and "custody unavailable" in reason
    assert "credstore" in reason, "the reason has to say what to provision"


def test_a_cosigner_on_another_box_is_not_judged_from_here(monkeypatch):
    """Once it moves under its own operator this deploy cannot see its
    credentials and cannot probe it either -- its site block demands a client
    certificate. Reporting nothing beats guessing."""
    monkeypatch.setattr(preflight, "_manifest_present", lambda: None)
    monkeypatch.setattr(preflight.secrets_checks, "google_oauth_configured", lambda: None)
    monkeypatch.setattr(preflight, "unit_for_module", lambda module: None)

    assert preflight._mail_configured() is None
