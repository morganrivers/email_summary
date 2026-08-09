"""Track C: the web-tier audit log.

What is pinned here is the two properties the log is worth having for. One row
per change a person made, written by the sole manifest writer so a second caller
cannot forget it; and nothing in a row that an attacker who reads the file
wanted -- no document body, no token, no chat id, which is enforced by the shape
of `detail` rather than by everyone remembering.

The co-signer's log (tests/test_cosigner.py) is the other half and shares no
code with this one on purpose; see backend/audit.py.
"""

import json
import re
import time

import harness
import pytest

from backend import audit, paths, site
from backend.accounts import account
from backend.drafting import personal_context


def _manifest(tmp_path, entries):
    p = tmp_path / "accounts.json"
    p.write_text(json.dumps({"accounts": entries}))
    return p


def _entry(email, **over):
    e = {
        "id": email,
        "handle": harness.handle_for(email),
        "identity": {"first": "A", "last": "B", "emails": [email]},
        "telegram": {},
        "timezone": "UTC",
        "plan_status": "active",
    }
    e.update(over)
    return e


@pytest.fixture
def store(tmp_path, monkeypatch):
    """An account store holding one user, with the audit log alongside it."""
    home = tmp_path / "database"
    home.mkdir()
    monkeypatch.setattr(account, "ACCOUNTS_DIR", home)
    monkeypatch.setattr(account, "MANIFEST", _manifest(home, [_entry("dana@x.com")]))
    return home


def rows(**kw):
    return audit.recent(limit=100, **kw)


def test_a_row_carries_who_what_and_when():
    audit.record("dana@x.com", audit.SIGN_IN, "ok")
    (row,) = rows()
    assert row["account_id"] == "dana@x.com"
    assert row["action"] == audit.SIGN_IN
    assert row["outcome"] == "ok"
    assert row["ts"] > 0


def test_an_unknown_action_is_refused():
    """The action set is closed, so a typo splits no query and a new call site
    is a deliberate addition to ACTIONS rather than a new string."""
    with pytest.raises(AssertionError):
        audit.record("dana@x.com", "whatever-i-felt-like", "ok")


def test_detail_takes_names_and_refuses_values():
    """The property the module exists to keep: there is no parameter a document
    body, an address or a token fits through."""
    audit.record("dana@x.com", audit.SETTINGS, "saved", ("timezone", "chars:2048"))
    assert rows()[0]["detail"] == "timezone,chars:2048"

    for smuggled in ("Dana lives at 12 Example Street and her number is 0170",
                     "dana@x.com",
                     "ya29.a0AfH6SMBx-the-access-token"):
        with pytest.raises(AssertionError):
            audit.record("dana@x.com", audit.SETTINGS, "saved", (smuggled,))
    assert len(rows()) == 1, "a refused row must not be written"


def test_the_request_origin_is_ambient_and_restored():
    """The mutators have no request in scope and must not grow a parameter for
    one. A stale origin left behind would attribute one user's change to
    another's address, which is why the context manager restores."""
    with audit.request_context("203.0.113.7", "Mozilla/5.0"):
        audit.record("dana@x.com", audit.SIGN_IN, "ok")
    audit.record("dana@x.com", audit.SIGN_OUT, "ok")

    signed_out, signed_in = rows()
    assert (signed_in["source_ip"], signed_in["user_agent"]) == ("203.0.113.7", "Mozilla/5.0")
    assert (signed_out["source_ip"], signed_out["user_agent"]) == (None, None)


def test_a_long_user_agent_is_truncated():
    with audit.request_context("203.0.113.7", "U" * 5000):
        audit.record("dana@x.com", audit.SIGN_IN, "ok")
    assert len(rows()[0]["user_agent"]) == audit.MAX_USER_AGENT


# --- the mutators, one row each -------------------------------------------


def test_settings_names_only_what_changed(store):
    """The settings form posts every field on every save, so logging what
    arrived would say a user changed five things every time they changed one."""
    account.set_settings("dana@x.com", timezone="Europe/Berlin", auto_schedule=False,
                         ban_dashes=True)
    (row,) = rows()
    assert (row["action"], row["outcome"]) == (audit.SETTINGS, "saved")
    assert row["detail"] == "timezone"

    account.set_settings("dana@x.com", timezone="Europe/Berlin", auto_schedule=False,
                         ban_dashes=True)
    assert rows()[0]["outcome"] == "unchanged"
    assert rows()[0]["detail"] is None


def test_telegram_link_and_unlink_are_one_row_each(store):
    account.set_telegram("dana@x.com", chat_id="12345")
    account.set_telegram("dana@x.com", clear=True)
    unlinked, linked = rows()
    assert (linked["action"], linked["outcome"], linked["detail"]) == (
        audit.TELEGRAM, "linked", "chat_id")
    assert (unlinked["action"], unlinked["outcome"]) == (audit.TELEGRAM, "unlinked")
    assert "12345" not in json.dumps(rows()), "a chat id is not a field name"


def test_the_voice_document_is_one_row_per_edit(store):
    """voice_dna.save() writes the document and points the manifest at it, so
    the row is written by set_voice: logging in both places would be two rows
    for one edit."""
    account.set_voice("dana@x.com", store / "dana@x.com" / "voice-dna.md")
    account.set_voice("dana@x.com", clear=True)
    cleared, saved = rows()
    assert (saved["action"], saved["outcome"]) == (audit.VOICE, "saved")
    assert (cleared["action"], cleared["outcome"]) == (audit.VOICE, "cleared")


def test_personal_context_records_its_length_and_never_its_text(store, tmp_path,
                                                                monkeypatch):
    # The document is encrypted under the account's data key now, so writing one
    # needs both halves of custody. What is under test is still the row.
    acct = account.get_account("dana@x.com")
    with harness.custody_available(tmp_path, monkeypatch):
        personal_context.save(acct, "I am in Berlin and I ride a bicycle.")
    (row,) = rows()
    assert (row["action"], row["outcome"]) == (audit.PERSONAL, "saved")
    assert row["detail"] == "chars:36"
    assert "Berlin" not in json.dumps(rows())

    personal_context.save(acct, "")
    assert rows()[0]["outcome"] == "cleared"

    personal_context.save(acct, "")
    assert len(rows()) == 2, "clearing nothing changed nothing and is not an edit"


def test_a_plan_change_records_both_ends(store):
    account.set_plan_status("dana@x.com", "inactive")
    (row,) = rows()
    assert (row["action"], row["outcome"], row["detail"]) == (
        audit.PLAN, "inactive", "from:active")


def test_registration_distinguishes_a_new_account_from_a_re_consent(store):
    account.register_account("eve@x.com", "Eve", "E")
    account.register_account("eve@x.com", "Eve", "E")
    second, first = rows(account_id="eve@x.com")
    assert (first["action"], first["outcome"]) == (audit.ACCOUNT, "created")
    assert (second["action"], second["outcome"]) == (audit.ACCOUNT, "updated")


def test_deletion_leaves_the_account_history_behind(store):
    """A log a user can empty by asking is not a log, and the row saying the
    account was deleted is the one most worth keeping. RETENTION_DAYS is what
    bounds how long their address stays here."""
    account.set_settings("dana@x.com", timezone="Europe/Berlin")
    assert account.delete_account("dana@x.com") is True
    deleted, settings = rows(account_id="dana@x.com")
    assert (deleted["action"], deleted["outcome"]) == (audit.ACCOUNT, "deleted")
    assert settings["action"] == audit.SETTINGS


# --- retention -------------------------------------------------------------


def test_prune_drops_the_old_and_leaves_no_readable_remains():
    """secure_delete is on, so a pruned row does not stay readable in the file's
    free list. A retention period that leaves the rows on disk is not one."""
    now = time.time()
    audit.record("old@x.com", audit.SIGN_IN, "ok", ts=now - 1000)
    audit.record("kept@x.com", audit.SIGN_IN, "ok", ts=now)

    assert audit.prune(before=now - 500) == 1
    assert [r["account_id"] for r in rows()] == ["kept@x.com"]

    blob = audit.db_path().read_bytes()
    assert b"old@x.com" not in blob
    assert b"kept@x.com" in blob


def test_record_prunes_at_most_once_an_interval(monkeypatch):
    """The prune rides on record() rather than a timer, so there is no unit to
    forget to deploy; the interval is what stops it running on every write."""
    calls = []
    monkeypatch.setattr(audit, "prune", lambda before=None: calls.append(before))
    audit.record("dana@x.com", audit.SIGN_IN, "ok")
    audit.record("dana@x.com", audit.SIGN_OUT, "ok")
    assert len(calls) == 1


# --- the web tier ---------------------------------------------------------


def _handler(headers, peer=site.LOOPBACK):
    """A Handler with no socket. _source_ip reads the headers and the peer and
    nothing else, so it can be exercised without standing a server up."""
    from frontend import web_server

    h = web_server.Handler.__new__(web_server.Handler)
    h.headers = headers
    h.client_address = (peer, 51234)
    return h


def test_the_source_ip_is_the_address_caddy_observed():
    """Caddy appends the peer it connected to, so the rightmost entry is the
    one it saw and everything left of it is a header the client wrote."""
    assert _handler({"X-Forwarded-For": "203.0.113.7"})._source_ip() == "203.0.113.7"
    assert _handler({"X-Forwarded-For": "10.0.0.1, 198.51.100.9"})._source_ip() == "198.51.100.9"
    assert _handler({})._source_ip() == site.LOOPBACK


def test_a_forwarded_header_from_an_untrusted_peer_is_ignored():
    """The one that matters: X-Forwarded-For is believed because of who sent
    it, not because of how this process happens to be bound. A client that
    reaches the port directly -- a WEB_HOST past loopback, an opened firewall,
    a sidecar -- writes the header itself, and believing it would let anyone
    choose what the audit log says about them, including somebody else's
    address."""
    direct = _handler({"X-Forwarded-For": "198.51.100.9"}, peer="203.0.113.200")
    assert direct._source_ip() == "203.0.113.200"


def test_an_empty_forwarded_header_falls_back_to_the_peer():
    assert _handler({"X-Forwarded-For": "  "})._source_ip() == site.LOOPBACK


def test_caddy_proxies_from_a_peer_the_app_trusts():
    """The two halves of the same claim, in two files: the address Caddy
    connects from, and the set whose X-Forwarded-For the app reads. Drift means
    every row silently records the proxy's own address instead of a browser's.
    Checked against the committed Caddyfile rather than only the renderer,
    because that file is installed by hand and can be edited in place."""
    assert site.upstream(site.WEB_PORT).rsplit(":", 1)[0] in site.TRUSTED_PROXIES

    rendered = (paths.REPO_ROOT / "deploy" / "hetzner" / "Caddyfile").read_text()
    upstreams = re.findall(r"reverse_proxy (\S+):\d+", rendered)
    assert upstreams, "no reverse_proxy lines found; did the Caddyfile move?"
    assert set(upstreams) <= site.TRUSTED_PROXIES, (
        f"Caddy proxies from {sorted(set(upstreams) - site.TRUSTED_PROXIES)}, "
        "whose X-Forwarded-For the app discards"
    )


def test_the_schema_has_nowhere_to_put_content():
    """The same discipline as cosigner/audit.py: a column added for debugging is
    what an attacker who reads this file is hoping for."""
    cols = {row[1] for row in audit.connect().execute("PRAGMA table_info(events)")}
    assert cols == {"id", "ts", "account_id", "action", "outcome", "detail",
                    "source_ip", "user_agent"}
