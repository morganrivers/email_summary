"""The signed cookies: the session, the OAuth state and the Polar checkout.

The state moved in here from web_server because it answers the same question
the session does -- did this box mint this, and how long ago -- and because a
single-slot cookie made a second sign-in tab look like a CSRF attack. The
checkout binding is the third of the same shape: a round trip through a third
party that comes back naming what it started.
"""

import time

import pytest

from frontend import session as sess

CURRENT = "test-session-secret-0123456789"
ROTATED = "test-session-secret-9876543210"


@pytest.fixture(autouse=True)
def signing_key(monkeypatch):
    monkeypatch.delenv(sess.secrets.SESSION_SECRET_PREVIOUS_ENV, raising=False)
    monkeypatch.setenv(sess.secrets.SESSION_SECRET_ENV, CURRENT)
    monkeypatch.setattr(sess, "_keys", None)
    yield
    monkeypatch.setattr(sess, "_keys", None)


def rotate(monkeypatch, current, previous=None):
    """Restart the process with a new signing key, as a deploy would: the old
    value moved to SESSION_SECRET_PREVIOUS, or dropped entirely."""
    monkeypatch.setenv(sess.secrets.SESSION_SECRET_ENV, current)
    if previous is None:
        monkeypatch.delenv(sess.secrets.SESSION_SECRET_PREVIOUS_ENV, raising=False)
    else:
        monkeypatch.setenv(sess.secrets.SESSION_SECRET_PREVIOUS_ENV, previous)
    monkeypatch.setattr(sess, "_keys", None)


def headers_for(*set_cookies):
    """The Cookie header a browser would send back, given Set-Cookie values."""
    jar = "; ".join(c.split(";")[0] for c in set_cookies)
    return {"Cookie": jar}


def test_a_session_round_trips():
    cookie = sess.make_cookie("dana@example.com")
    assert sess.get_email(headers_for(cookie)) == "dana@example.com"


def test_both_cookies_carry_the_attributes_that_do_the_defending():
    """`SameSite=Lax` is the primary CSRF defence: a cross-site POST arrives
    without the session cookie. There is now a synchroniser token behind it
    (`csrf_token`/`csrf_ok`, checked by web_server._posted_form) so the defence
    does not rest on this one attribute alone, but these three still matter and
    each fails silently: dropping SameSite widens the window to shapes a Lax
    cookie follows, dropping Secure puts the cookie on the first plaintext
    request, and dropping HttpOnly hands it to any script that reaches the
    page."""
    for cookie in (sess.make_cookie("dana@example.com"),
                   sess.state_cookie(sess.new_state(), {})):
        attributes = {part.strip().lower() for part in cookie.split(";")[1:]}
        assert "httponly" in attributes, cookie
        assert "secure" in attributes, cookie
        assert "samesite=lax" in attributes, cookie
        assert "path=/" in attributes, cookie


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
    for _ in range(sess.MAX_PENDING + 2):
        state = sess.new_state()
        states.append(state)
        cookie = sess.state_cookie(state, headers_for(cookie) if cookie else None)

    browser = headers_for(cookie)
    kept = [s for s in states if sess.state_is_ours(s, browser)]
    assert len(kept) == sess.MAX_PENDING
    assert kept == states[-sess.MAX_PENDING:]


def test_an_expired_state_is_refused(monkeypatch):
    state = sess.new_state()
    cookie = sess.state_cookie(state)
    later = time.time() + sess.STATE_TTL + 1
    monkeypatch.setattr(sess.time, "time", lambda: later)
    assert not sess.state_is_ours(state, headers_for(cookie))


def test_a_state_is_one_shot_once_it_is_consumed():
    """Membership alone left a state usable for the rest of its half hour on
    every callback that did not clear the whole cookie -- so a refused sign-in
    left a reusable token behind, and `provisioning.pkce_verifier` derives the
    verifier from the state, which makes state reuse verifier reuse."""
    first, second = sess.new_state(), sess.new_state()
    cookie = sess.state_cookie(second, headers_for(sess.state_cookie(first)))
    browser = headers_for(cookie)
    assert sess.state_is_ours(first, browser) and sess.state_is_ours(second, browser)

    after = headers_for(sess.state_cookie_without(first, browser))
    assert not sess.state_is_ours(first, after), "the consumed state is still live"
    assert sess.state_is_ours(second, after), "the other tab's consent was evicted"


def test_a_session_cookie_is_not_a_state_and_a_state_is_not_a_session():
    """One key signs both, so the purpose is inside the signed string. Without
    that, either value would verify as the other."""
    state = sess.new_state()
    assert sess.get_email(headers_for(f"{sess.SESSION_COOKIE}={state}")) is None

    session_value = sess.make_cookie("dana@example.com").split("=", 1)[1].split(";")[0]
    assert not sess.state_is_ours(
        session_value, headers_for(f"{sess.STATE_COOKIE}={session_value}"))


# --- the anti-CSRF token --------------------------------------------------


def test_a_csrf_token_round_trips():
    token = sess.csrf_token("dana@example.com")
    assert sess.csrf_ok(token, "dana@example.com")


def test_a_csrf_token_is_bound_to_its_account():
    """Knowing the shape of a token is not enough to post as someone else: it
    verifies only against the email it was minted for."""
    token = sess.csrf_token("dana@example.com")
    assert not sess.csrf_ok(token, "mallory@example.com")


def test_a_missing_or_empty_csrf_token_is_refused():
    assert not sess.csrf_ok("", "dana@example.com")
    assert not sess.csrf_ok(None, "dana@example.com")
    assert not sess.csrf_ok(sess.csrf_token("dana@example.com"), "")


def test_a_session_cookie_is_not_a_csrf_token():
    """One key signs both; the purpose inside the signed string keeps a session
    value from being replayed as a CSRF token for that same account."""
    session_value = sess.make_cookie("dana@example.com").split("=", 1)[1].split(";")[0]
    assert not sess.csrf_ok(session_value, "dana@example.com")


def test_an_expired_csrf_token_is_refused(monkeypatch):
    token = sess.csrf_token("dana@example.com")
    later = time.time() + sess.SESSION_TTL + 1
    monkeypatch.setattr(sess.time, "time", lambda: later)
    assert not sess.csrf_ok(token, "dana@example.com")


def test_a_csrf_token_survives_a_rotation(monkeypatch):
    """It is minted from the session keyring, so a secret rotation must not
    reject the token on a form a user already has open."""
    token = sess.csrf_token("dana@example.com")
    rotate(monkeypatch, current=ROTATED, previous=CURRENT)
    assert sess.csrf_ok(token, "dana@example.com")


# --- rotation -------------------------------------------------------------


def test_a_session_survives_a_rotation(monkeypatch):
    """The point of the track: rotating the secret must not sign everyone out
    in the same second, or it never gets rotated at all."""
    cookie = sess.make_cookie("dana@example.com")
    rotate(monkeypatch, current=ROTATED, previous=CURRENT)
    assert sess.get_email(headers_for(cookie)) == "dana@example.com"


def test_dropping_the_previous_key_ends_the_sessions_it_signed(monkeypatch):
    """Retirement is a deploy that removes the variable, so a key stays live
    exactly as long as someone leaves it named."""
    cookie = sess.make_cookie("dana@example.com")
    rotate(monkeypatch, current=ROTATED, previous=CURRENT)
    rotate(monkeypatch, current=ROTATED)
    assert sess.get_email(headers_for(cookie)) is None


def test_a_consent_in_flight_survives_a_rotation(monkeypatch):
    """A restart lands mid round trip. Without this the callback comes back as
    "state mismatch (possible CSRF)", which reads as an attack and is not one."""
    state = sess.new_state()
    cookie = sess.state_cookie(state)
    rotate(monkeypatch, current=ROTATED, previous=CURRENT)
    assert sess.state_is_ours(state, headers_for(cookie))


def test_only_the_current_key_mints(monkeypatch):
    """A previous key verifies and never signs, so a rotation moves forward:
    every new cookie names the new key and the old one drains away."""
    rotate(monkeypatch, current=ROTATED, previous=CURRENT)
    kid = sess.make_cookie("dana@example.com").split("=", 1)[1].split(":")[0]
    assert kid == sess._kid(ROTATED.encode())
    assert kid != sess._kid(CURRENT.encode())


def test_the_previous_key_is_kept_apart_from_the_current_one(monkeypatch):
    """Both variables holding the same value is one key, not two, and must not
    look like a collision to the keyring."""
    rotate(monkeypatch, current=CURRENT, previous=CURRENT)
    assert len(sess._keyring()) == 1


def test_a_cookie_naming_an_unknown_key_is_refused(monkeypatch):
    cookie = sess.make_cookie("dana@example.com")
    rotate(monkeypatch, current=ROTATED, previous="test-session-secret-third-value")
    assert sess.get_email(headers_for(cookie)) is None


def test_an_unknown_key_id_is_refused_the_same_way_a_bad_signature_is(monkeypatch):
    """Not a timing measurement -- the structural property behind one. An early
    return on an unknown kid would skip the comparison a bad signature gets, and
    that difference is what a probe measures to learn which key ids are live."""
    rotate(monkeypatch, current=ROTATED, previous=CURRENT)
    compared = []
    real = sess.hmac.compare_digest
    monkeypatch.setattr(sess.hmac, "compare_digest",
                        lambda a, b: compared.append(1) or real(a, b))

    value = sess.make_cookie("dana@example.com").split("=", 1)[1].split(";")[0]
    _, rest = value.split(":", 1)
    forged = value[:-1] + ("1" if value[-1] == "0" else "0")

    compared.clear()
    assert sess.get_email(headers_for(f"{sess.SESSION_COOKIE}=deadbeef:{rest}")) is None
    unknown_kid = len(compared)

    compared.clear()
    assert sess.get_email(headers_for(f"{sess.SESSION_COOKIE}={forged}")) is None
    bad_mac = len(compared)

    assert unknown_kid == bad_mac == len(sess._keyring()) + 1


def test_the_startup_line_names_both_keys_without_printing_them(monkeypatch):
    rotate(monkeypatch, current=ROTATED, previous=CURRENT)
    line = sess.describe_keys()
    assert CURRENT not in line and ROTATED not in line
    assert sess._kid(ROTATED.encode()) in line
    assert sess._kid(CURRENT.encode()) in line

    rotate(monkeypatch, current=ROTATED)
    assert f"{sess.secrets.SESSION_SECRET_PREVIOUS_ENV}=(unset)" in sess.describe_keys()


# --- the Polar checkout ---------------------------------------------------


def test_a_checkout_is_bound_to_the_browser_that_started_it():
    """`/billing/return` is a GET taking an id from a query string, and
    SameSite=Lax follows a cross-site top-level navigation -- so an
    attacker-supplied link fires that handler with the victim's session. The
    metadata stamp answers whose checkout it is; this answers who started it."""
    cookie = sess.checkout_cookie("co_1")
    browser = headers_for(cookie)
    assert sess.checkout_is_ours("co_1", browser)
    assert not sess.checkout_is_ours("co_2", browser)
    assert not sess.checkout_is_ours("co_1", headers_for()), "no cookie, no binding"
    assert not sess.checkout_is_ours("", browser)


def test_a_checkout_id_cannot_be_forged_without_the_key():
    """The cookie is signed, so writing the id into it by hand proves nothing."""
    assert not sess.checkout_is_ours(
        "co_1", headers_for(f"{sess.CHECKOUT_COOKIE}=co_1"))


def test_two_checkouts_can_be_pending_and_one_is_consumed_at_a_time():
    """Same reason two consents can be: a second tab must not evict the first.
    Consumed on return, so a link is one-shot."""
    first = sess.checkout_cookie("co_1")
    browser = headers_for(sess.checkout_cookie("co_2", headers_for(first)))
    assert sess.checkout_is_ours("co_1", browser)
    assert sess.checkout_is_ours("co_2", browser)

    after = headers_for(sess.checkout_cookie_without("co_1", browser))
    assert not sess.checkout_is_ours("co_1", after)
    assert sess.checkout_is_ours("co_2", after)
    assert sess.checkout_cookie_without("co_1", after) is None, (
        "nothing to consume twice")


def test_an_expired_checkout_binding_is_refused(monkeypatch):
    cookie = sess.checkout_cookie("co_1")
    later = time.time() + sess.CHECKOUT_TTL + 1
    monkeypatch.setattr(sess.time, "time", lambda: later)
    assert not sess.checkout_is_ours("co_1", headers_for(cookie))


def test_a_state_is_not_a_checkout():
    """One key signs both cookies, so the purpose is inside the signed string."""
    state = sess.new_state()
    assert not sess.state_is_ours(
        state, headers_for(f"{sess.STATE_COOKIE}={sess.checkout_cookie(state)}"))
