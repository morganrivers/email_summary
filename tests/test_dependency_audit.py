"""Nothing we ship has a known advisory against it.

The live check reaches the advisory service, so it is gated: an offline laptop
and a sandboxed runner would both fail it, and a test that fails for a reason
that is not the code's fault gets deleted rather than debugged. The scheduled
daily job sets LETTERLOCK_AUDIT=1, which is the point of the whole track -- the
pins do not change daily but the advisory database does, so the same lock can
become vulnerable overnight with no commit involved.

The ungated tests below cover the part that is ours: the ignore file. They run
everywhere, because an ignore that has quietly outlived its expiry is a bug in
this repo rather than news from the outside world.
"""

import datetime
import os

import pytest

from deploy import audit
from deploy import requirements


TODAY = datetime.date(2026, 8, 7)


def _vuln(name="requests", version="2.34.2", id="GHSA-aaaa", aliases=(), fix=()):
    return audit.Vulnerability(name, version,
                               {"id": id, "aliases": list(aliases),
                                "fix_versions": list(fix)})


def _ignore(id="GHSA-aaaa", expires="2026-12-01", reason="no fixed version yet"):
    return audit.Ignore({"id": id, "expires": expires, "reason": reason})


@pytest.mark.skipif(
    not os.environ.get("LETTERLOCK_AUDIT"),
    reason="network-dependent; runs in the scheduled job",
)
def test_no_known_vulnerabilities_in_the_lock():
    report = audit.audit()
    assert report.ok(), "\n" + report.render()


def test_the_committed_ignore_file_parses_and_none_of_it_has_expired():
    """Ungated because it needs no network: every entry's shape and expiry date
    is in the repo. This is what stops the gated job from being the first thing
    to notice that an ignore went permanent."""
    today = datetime.date.today()
    for ignore in audit.ignores():
        assert ignore.expires >= today, (
            f"{ignore.id} expired on {ignore.expires}; re-decide it rather than "
            "extending the date, or the file becomes a permanent mute"
        )


def test_an_entry_without_an_expiry_is_refused():
    with pytest.raises(AssertionError, match="permanent one"):
        audit.ignores('[[ignore]]\nid = "GHSA-aaaa"\nreason = "later"\n')


def test_an_expired_ignore_blocks_the_same_way_the_advisory_does():
    vuln = _vuln()
    report = audit.Report([vuln], [_ignore(expires="2026-08-06")], TODAY)
    assert not report.ok()
    assert report.expired
    assert report.blocking == [vuln], "an expired ignore stops covering its vuln"


def test_a_live_ignore_covers_its_advisory_by_id_or_alias():
    by_id = audit.Report([_vuln()], [_ignore()], TODAY)
    assert by_id.ok() and by_id.ignored and not by_id.blocking

    by_alias = audit.Report([_vuln(aliases=["CVE-2026-1234"])],
                            [_ignore(id="CVE-2026-1234")], TODAY)
    assert by_alias.ok() and by_alias.ignored and not by_alias.blocking


def test_an_ignore_that_matches_nothing_is_a_failure():
    """Otherwise the file accumulates entries for advisories fixed years ago,
    and nobody can tell which of them are still doing anything."""
    report = audit.Report([], [_ignore()], TODAY)
    assert not report.ok()
    assert report.unused


def test_an_unignored_advisory_blocks():
    report = audit.Report([_vuln(id="GHSA-bbbb")], [_ignore(id="GHSA-aaaa")], TODAY)
    assert not report.ok()
    assert [v.id for v in report.blocking] == ["GHSA-bbbb"]
    assert "VULNERABLE" in report.render()


def test_the_closure_is_the_whole_lock_and_not_the_direct_pins():
    """The reason to audit the lock at all: requests is a direct pin, urllib3
    under it is not, and a CVE in urllib3 is exactly the one requirements.txt
    cannot show you."""
    pins = audit.closure()
    names = requirements.names(pins)
    direct = requirements.names(requirements.pins())
    assert direct <= names, "the lock must cover every direct pin"
    assert "urllib3" in names and "urllib3" not in direct
