"""The five checks that decide whether a TDX quote is one we authorized.

Two callers verify quotes and they must not drift apart:

  * ``cosigner/attest.py`` checks an inbound RA-TLS client certificate -- is the
    thing connecting to the co-signer the enclave we shipped?
  * ``backend/integrations/inference_attestation.py`` checks an outbound
    inference provider -- is the thing about to read a user's mail the enclave
    that provider published?

Opposite directions, same question, so the parsing, the allowlist rules, the
TCB policy and the caching live here and each caller supplies only what is
genuinely its own: where the quote came from and what its report_data is
supposed to bind.

The checks, in the order a failure should be reported:
  1. the quote parses and is TDX
  2. report_data carries the binding the caller demands
  3. measurements match an authorized entry
  4. signature chain to the Intel root      (dcap_qvl.verify, via collateral)
  5. TCB status and advisories are allowed

Check 3 is the one that needs a human: an image absent from the allowlist
cannot be used, and adding it is a reviewed edit to a committed file.

What this cannot detect: a correct image subverted at runtime. Attestation is
about which code booted.
"""

import asyncio
import hashlib
import json
import threading
import time
from pathlib import Path

REQUIRED = "required"
DEV_INSECURE = "dev-insecure"

MEASUREMENT_FIELDS = ("mr_td", "rt_mr0", "rt_mr1", "rt_mr2", "rt_mr3")

RECHECK_SECONDS = 24 * 3600

# A refusal is not held for a day. A pass is a statement about an image, which
# does not change until the thing reboots; a refusal can be a PCCS that timed
# out, and caching that for 24h turns one slow collateral fetch into a day of
# refused drafts for an enclave that is fine. Short enough that a transient
# failure costs one retry, long enough that a genuinely rejected image is not
# re-verified on every single email.
FAILURE_RECHECK_SECONDS = 60


class Verdict:
    """The answer for one quote, plus what to write in the log."""

    def __init__(self, ok, subject, reason=None, measurement=None, attested=False):
        self.ok = ok
        self.subject = subject
        self.reason = reason
        self.measurement = measurement
        self.attested = attested

    @property
    def fingerprint(self):
        return self.subject

    def __repr__(self):
        return (f"Verdict(ok={self.ok}, subject={self.subject!r}, "
                f"measurement={self.measurement!r}, reason={self.reason!r})")


class Policy:
    """One allowlist file, parsed. Holds what a verification is allowed to
    accept; the caller-specific keys in the same file are left alone."""

    def __init__(self, path):
        self.path = Path(path)
        assert self.path.exists(), f"no attestation allowlist at {self.path}"
        self.data = json.loads(self.path.read_text())
        assert isinstance(self.data, dict), f"{self.path} must hold an object"

    def get(self, key, default=None):
        return self.data.get(key, default)

    def mode(self, override=None):
        """``required`` or ``dev-insecure``.

        The escape hatch is deliberately hard to leave on by accident: an
        allowlist with entries in it means somebody provisioned this box for
        production, and then the assert fires at startup rather than after a
        month of unverified calls."""
        value = (override or self.get("mode") or REQUIRED).strip()
        assert value in (REQUIRED, DEV_INSECURE), f"unknown attestation mode {value!r}"
        if value == DEV_INSECURE:
            assert not self.entries(), (
                "attestation is dev-insecure but the allowlist names authorized "
                f"measurements ({self.path}); this box looks provisioned for production"
            )
        return value

    def rows(self, key, scope=None):
        """Authorized entries under one key, optionally only those naming a
        scope. A scope is how one file serves several verified things (one
        provider per scope) without an entry silently authorizing all of them."""
        rows = self.get(key, []) or []
        if scope is None:
            return rows
        return [e for e in rows if e.get("scope") == scope]

    def entries(self, scope=None):
        return self.rows("measurements", scope)

    def match(self, actual, scope=None):
        """The name of the authorized entry this image matches, or None.

        A null field is an explicit operator statement that the register is not
        pinned. ``mr_td`` may never be null: an entry that pins nothing
        authorizes everything."""
        for entry in self.entries(scope):
            name = entry.get("name") or "unnamed"
            assert entry.get("mr_td"), f"allowlist entry {name!r} does not pin mr_td"
            if all(entry.get(f) is None or entry.get(f) == actual.get(f)
                   for f in MEASUREMENT_FIELDS):
                return name
        return None


def load_dcap():
    """dcap-qvl, or None. Imported on use rather than at module scope so a box
    where the wheel was never installed still starts, and still fails closed."""
    try:
        import dcap_qvl
    except ImportError:
        return None
    return dcap_qvl


def measurements_of(report):
    """MRTD and the four RTMRs as hex, from a parsed TDX report."""
    out = {}
    for field in MEASUREMENT_FIELDS:
        value = getattr(report, field, None)
        out[field] = value.hex() if isinstance(value, (bytes, bytearray)) else None
    return out


def aggregate(actual):
    """A short stable id for an image, for the log when nothing matched."""
    joined = "|".join(f"{f}={actual.get(f)}" for f in MEASUREMENT_FIELDS)
    return hashlib.sha256(joined.encode()).hexdigest()[:32]


def fetch_collateral(dcap, pccs_url, quote):
    """The PCCS collateral for one quote, fetched inside a loop of our own.

    `dcap_qvl.get_collateral` is a pyo3 builtin that asks for the running event
    loop when it is *called*, not when it is awaited. Passing the call straight
    to `asyncio.run` therefore evaluates it before any loop exists and raises
    "no running event loop" every time, which `verify()` reports as a failed
    quote verification -- an attestation that can never pass, wearing the
    costume of one that was checked and refused. The call has to happen inside
    the coroutine."""
    assert pccs_url, "no pccs_url in the allowlist; cannot fetch collateral"
    assert quote, "fetch_collateral needs quote bytes"

    async def fetch():
        return await dcap.get_collateral(pccs_url, quote)

    return asyncio.run(fetch())


def verify(quote, policy, subject, expected_report_data, scope=None):
    """The verdict for one quote. ``expected_report_data`` is the prefix
    report_data must carry, with every remaining byte required to be zero, so a
    quote minted for some other purpose cannot be replayed here."""
    assert quote, "verify() needs quote bytes"
    dcap = load_dcap()
    if dcap is None:
        return Verdict(False, subject, reason="dcap-qvl is not installed")

    try:
        parsed = dcap.parse_quote(quote)
    except Exception as err:
        return Verdict(False, subject, reason=f"quote does not parse: {err}")
    if not parsed.is_tdx():
        return Verdict(False, subject, reason="quote is not a TDX quote")

    got = bytes(getattr(parsed.report, "report_data", b""))
    if not _binds(got, expected_report_data):
        return Verdict(False, subject, reason="report_data does not carry the expected binding")

    actual = measurements_of(parsed.report)
    name = policy.match(actual, scope)
    measurement = name or aggregate(actual)
    if name is None:
        return Verdict(False, subject, measurement=measurement,
                       reason="measurement is not on the allowlist")

    try:
        collateral = fetch_collateral(dcap, policy.get("pccs_url"), quote)
        report = dcap.verify(quote, collateral, int(time.time()))
    except Exception as err:
        return Verdict(False, subject, measurement=measurement,
                       reason=f"quote verification failed: {err}")

    if report.status not in (policy.get("allowed_tcb_status") or []):
        return Verdict(False, subject, measurement=measurement,
                       reason=f"TCB status {report.status}")
    rejected = set(policy.get("rejected_advisories") or []) & set(report.advisory_ids or [])
    if rejected:
        return Verdict(False, subject, measurement=measurement,
                       reason=f"rejected advisories {sorted(rejected)}")

    return Verdict(True, subject, measurement=measurement, attested=True)


def _binds(got, expected):
    assert expected, "an empty binding would accept a quote bound to nothing"
    return got[:len(expected)] == expected and not any(got[len(expected):])


class VerdictCache:
    """Verdicts by subject, re-checked daily -- and refusals re-checked in a
    minute.

    A quote is a boot-time measurement, so asking a thousand times an hour
    returns identical bytes. TCB status is the one input that moves without a
    reboot: Intel raises the required level after a vulnerability and an
    ``UpToDate`` verdict becomes ``OutOfDate`` with no restart anywhere.

    The two lifetimes are not symmetric because the two answers are not. A pass
    describes an image; a refusal often describes the network between here and
    a PCCS. Holding the second one as long as the first is how a five-second
    outage becomes a day with no drafts."""

    def __init__(self, recheck_seconds=RECHECK_SECONDS,
                 failure_seconds=FAILURE_RECHECK_SECONDS):
        self.recheck_seconds = recheck_seconds
        self.failure_seconds = failure_seconds
        self._lock = threading.Lock()
        self._entries = {}

    def _ttl(self, verdict):
        return self.recheck_seconds if verdict.ok else self.failure_seconds

    def get(self, subject):
        assert subject is not None, "a cached verdict needs a subject to key on"
        with self._lock:
            cached = self._entries.get(subject)
        if cached is None or time.time() - cached[1] >= self._ttl(cached[0]):
            return None
        return cached[0]

    def put(self, subject, verdict):
        with self._lock:
            self._entries[subject] = (verdict, time.time())

    def clear(self):
        with self._lock:
            self._entries.clear()
