"""The contact form, which is the web tier's one unauthenticated relay.

Every submission both writes a journal line and sends a Telegram message on the
operator's bot token, so a script pointed at it floods two places at once. A
honeypot field stops a naive bot and nothing else, and `MAX_BODY` allows 128 KB
per submission.
"""

from frontend import web_server


def _drain(source, n):
    return [web_server._contact_allowed(source) for _ in range(n)]


def test_a_burst_is_allowed_and_a_flood_is_not(monkeypatch):
    """A bucket rather than a cooldown: someone who writes twice in a minute
    because they forgot something is the ordinary case, and a cooldown refuses
    that while a bucket refuses the hundredth."""
    monkeypatch.setattr(web_server, "_CONTACT_BUCKETS", {})
    allowed = _drain("198.51.100.7", web_server.CONTACT_BURST + 3)
    assert allowed[:web_server.CONTACT_BURST] == [True] * web_server.CONTACT_BURST
    assert allowed[web_server.CONTACT_BURST:] == [False, False, False]


def test_one_sender_does_not_spend_anothers_budget(monkeypatch):
    monkeypatch.setattr(web_server, "_CONTACT_BUCKETS", {})
    _drain("198.51.100.7", web_server.CONTACT_BURST)
    assert web_server._contact_allowed("198.51.100.8") is True


def test_the_bucket_refills_with_time(monkeypatch):
    monkeypatch.setattr(web_server, "_CONTACT_BUCKETS", {})
    now = [1000.0]
    monkeypatch.setattr(web_server.time, "monotonic", lambda: now[0])

    _drain("198.51.100.7", web_server.CONTACT_BURST)
    assert web_server._contact_allowed("198.51.100.7") is False
    now[0] += web_server.CONTACT_REFILL_SECONDS
    assert web_server._contact_allowed("198.51.100.7") is True


def test_a_refilled_bucket_leaves_no_row_behind(monkeypatch):
    """An entry means something only while it holds a deficit. Without the
    sweep the table is a per-address record of who has written to us, and it
    grows without bound besides."""
    monkeypatch.setattr(web_server, "_CONTACT_BUCKETS", {})
    now = [1000.0]
    monkeypatch.setattr(web_server.time, "monotonic", lambda: now[0])

    assert web_server._contact_allowed("198.51.100.7") is True
    now[0] += web_server.CONTACT_REFILL_SECONDS * web_server.CONTACT_BURST
    assert web_server._contact_allowed("198.51.100.8") is True
    assert set(web_server._CONTACT_BUCKETS) == {"198.51.100.8"}
