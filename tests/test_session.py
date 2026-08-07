"""The two signed cookies: the session, and the OAuth state.

The state moved in here from web_server because it answers the same question
the session does -- did this box mint this, and how long ago -- and because a
single-slot cookie made a second sign-in tab look like a CSRF attack.
"""

import time

import pytest

from frontend import session as sess


@pytest.fixture(autouse=True)
def signing_key(monkeypatch):
    monkeypatch.setenv(sess.secrets.SESSION_SECRET_ENV, "test-session-secret-0123456789")
    monkeypatch.setattr(sess, "_secret", None)
    yield
    monkeypatch.setattr(sess, "_secret", None)


def headers_for(*set_cookies):
    """The Cookie header a browser would send back, given Set-Cookie values."""
    jar = "; ".join(c.split(";")[0] for c in set_cookies)
    return {"Cookie": jar}


def test_a_session_round_trips():
    cookie = sess.make_cookie("dana@example.com")
    assert sess.get_email(headers_for(cookie)) == "dana@example.com"


def test_a_tampered_session_is_not_accepted():
    cookie = sess.make_cookie("dana@example.com")
    forged = cookie.replace("dana@example.com", "mallory@example.com", 1)
    assert sess.get_email(headers_for(forged)) is None


def test_a_state_round_trips():
    state = sess.new_state()
    cookie = sess.state_cookie(state)
    assert sess.state_is_ours(state, headers_for(cookie))


def test_a_state_we_did_not_mint_is_refused():
    cookie = sess.state_cookie(sess.new_state())
    assert not sess.state_is_ours("a-state-of-my-own-invention", headers_for(cookie))


def test_a_second_tab_does_not_invalidate_the_first():
    """The failure this replaced: two sign-in tabs, one cookie slot, so
    finishing the older consent came back as "state mismatch (possible CSRF)"
    -- an alarming way to say the user opened two tabs."""
    first = sess.new_state()
    first_cookie = sess.state_cookie(first)
    second = sess.new_state()
    second_cookie = sess.state_cookie(second, headers_for(first_cookie))

    browser = headers_for(second_cookie)
    assert sess.state_is_ours(second, browser)
    assert sess.state_is_ours(first, browser), "the first tab's consent was evicted"


def test_only_the_most_recent_states_are_kept():
    """Bounded, so the cookie cannot grow without limit and an abandoned state
    ages out rather than lingering behind newer ones."""
    cookie = None
    states = []
    for _ in range(sess.MAX_PENDING_STATES + 2):
        state = sess.new_state()
        states.append(state)
        cookie = sess.state_cookie(state, headers_for(cookie) if cookie else None)

    browser = headers_for(cookie)
    kept = [s for s in states if sess.state_is_ours(s, browser)]
    assert len(kept) == sess.MAX_PENDING_STATES
    assert kept == states[-sess.MAX_PENDING_STATES:]


def test_an_expired_state_is_refused(monkeypatch):
    state = sess.new_state()
    cookie = sess.state_cookie(state)
    later = time.time() + sess.STATE_TTL + 1
    monkeypatch.setattr(sess.time, "time", lambda: later)
    assert not sess.state_is_ours(state, headers_for(cookie))


def test_a_session_cookie_is_not_a_state_and_a_state_is_not_a_session():
    """One key signs both, so the purpose is inside the signed string. Without
    that, either value would verify as the other."""
    state = sess.new_state()
    assert sess.get_email(headers_for(f"{sess.SESSION_COOKIE}={state}")) is None

    session_value = sess.make_cookie("dana@example.com").split("=", 1)[1].split(";")[0]
    assert not sess.state_is_ours(
        session_value, headers_for(f"{sess.STATE_COOKIE}={session_value}"))
