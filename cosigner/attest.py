"""Is the thing on the other end of this connection the enclave we authorized?

RA-TLS puts the TDX quote inside the enclave's own certificate, so the check
costs no extra round trip: the certificate arrives with the handshake and the
quote arrives with it.

**Cadence: per TLS connection, not per request.** A quote is a boot-time
measurement -- MRTD and RTMR0-3 are fixed when the TD launches -- so asking a
thousand times an hour returns identical bytes. The enclave mints a fresh
RA-TLS keypair at each boot, and a boot is exactly when the measurement can
change, so an unseen certificate fingerprint is the correct trigger for the
full check. Verdicts are cached by fingerprint and re-checked daily, because
TCB status is the one input that moves without a reboot: Intel raises the
required level after a vulnerability, and an `UpToDate` verdict becomes
`OutOfDate` with no restart anywhere.

Five checks, per docs/tee_enclaves_and_upgrades.md §4.3:
  1. signature chain to the Intel root       (dcap_qvl.verify)
  2. TCB status                              (allowed_tcb_status)
  3. QE identity                             (dcap_qvl.verify, from collateral)
  4. measurements against the allowlist      (this file's own copy)
  5. report_data == the digest of the leaf certificate

Check 4 is why this service exists at all given the KMS already gates
`app_secret`: the allowlist sits under a different operator, and the enclave
cannot edit it.

What this does not detect: a correct image subverted at runtime -- a side
channel, an injection, a ROP chain. Attestation is about which code booted.
The rate limit and the audit log are what bound that case.
"""

import hashlib
import json
import os
import threading
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "allowlist.json"

REQUIRED = "required"
DEV_INSECURE = "dev-insecure"

RECHECK_SECONDS = 24 * 3600

MEASUREMENT_FIELDS = ("mr_td", "rt_mr0", "rt_mr1", "rt_mr2", "rt_mr3")

_LOCK = threading.Lock()
_VERDICTS = {}
_CONFIG = None


class Verdict:
    """The answer for one client certificate, plus what to write in the log."""

    def __init__(self, ok, fingerprint, reason=None, measurement=None, attested=False):
        self.ok = ok
        self.fingerprint = fingerprint
        self.reason = reason
        self.measurement = measurement
        self.attested = attested

    def __repr__(self):
        return (f"Verdict(ok={self.ok}, fp={self.fingerprint!r}, "
                f"measurement={self.measurement!r}, reason={self.reason!r})")


def config_path():
    return Path(os.environ.get("COSIGNER_ALLOWLIST") or DEFAULT_CONFIG_PATH)


def config():
    global _CONFIG
    with _LOCK:
        if _CONFIG is None:
            path = config_path()
            assert path.exists(), f"no attestation allowlist at {path}"
            _CONFIG = json.loads(path.read_text())
            assert isinstance(_CONFIG, dict), f"{path} must hold an object"
        return _CONFIG


def reset_for_test(path=None):
    """Forget the parsed config and every cached verdict. With no path, go back
    to the packaged allowlist rather than whatever a previous call pointed at."""
    global _CONFIG
    with _LOCK:
        _CONFIG = None
        _VERDICTS.clear()
    if path is None:
        os.environ.pop("COSIGNER_ALLOWLIST", None)
    else:
        os.environ["COSIGNER_ALLOWLIST"] = str(path)


def mode():
    """`required` or `dev-insecure`.

    The escape hatch exists so tracks I and J can be built and tested before
    the Phala instance is rented (plan §7, phase 1). It is deliberately hard to
    leave on by accident: an allowlist with entries in it, or TEE_REQUIRED set
    anywhere in this unit's environment, means somebody has provisioned this
    box for production and the assert fires at startup rather than after a
    month of unverified unwraps."""
    value = (os.environ.get("COSIGNER_ATTESTATION") or config().get("mode") or REQUIRED).strip()
    assert value in (REQUIRED, DEV_INSECURE), f"unknown attestation mode {value!r}"
    if value == DEV_INSECURE:
        assert not config().get("measurements"), (
            "attestation is dev-insecure but the allowlist names authorized "
            f"measurements ({config_path()}); this box looks provisioned for production"
        )
        assert os.environ.get("TEE_REQUIRED", "").strip() not in ("1", "true", "yes"), (
            "attestation is dev-insecure but TEE_REQUIRED is set; refusing to "
            "run unverified against an enclave that believes it is attested"
        )
    return value


def configured():
    """None when this module can decide, else why it cannot. Used by
    `deploy/preflight.py` so a missing allowlist is reported at deploy time
    rather than discovered by every unwrap failing."""
    try:
        current = mode()
    except AssertionError as err:
        return str(err)
    if current == REQUIRED:
        if not config().get("measurements"):
            return f"attestation required but no measurements authorized in {config_path()}"
        if not config().get("quote_oid"):
            return f"attestation required but quote_oid is unset in {config_path()}"
        if _dcap() is None:
            return "attestation required but dcap-qvl is not installed"
    return None


def _dcap():
    """dcap-qvl, or None. Imported on use rather than at module scope so the
    service still starts (and still fails closed, loudly) on a box where the
    wheel was never installed."""
    try:
        import dcap_qvl
    except ImportError:
        return None
    return dcap_qvl


def fingerprint(cert_der):
    return hashlib.sha256(cert_der).hexdigest()


def report_data_for_cert(cert):
    """The digest the quote's report_data must carry.

    `pem-sha256` is the convention `backend/tee/tee_boot._report_data_for_cert`
    already uses: SHA-256 over the leaf certificate's PEM text. `spki-sha256`
    hashes the SubjectPublicKeyInfo DER instead, which is immune to PEM
    line-wrapping differences. Which one is right is decided by what dstack's
    guest agent actually binds, so it is named in the config and confirmed
    against a live RA-TLS certificate at the cutover -- not guessed here, and
    never "whichever one matches", which would accept a quote bound to nothing
    in particular."""
    binding = config().get("binding")
    if binding == "pem-sha256":
        return hashlib.sha256(cert.public_bytes(serialization.Encoding.PEM)).digest()
    if binding == "spki-sha256":
        return hashlib.sha256(cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )).digest()
    raise AssertionError(f"unknown report_data binding {binding!r} in {config_path()}")


def extract_quote(cert):
    """The TDX quote out of the RA-TLS certificate extension named in the
    config. None when the certificate carries no such extension, which for a
    connection claiming to be the enclave is a denial, not a fallback."""
    oid = config().get("quote_oid")
    assert oid, f"quote_oid is not set in {config_path()}"
    try:
        ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid))
    except x509.ExtensionNotFound:
        return None
    return ext.value.public_bytes() if hasattr(ext.value, "public_bytes") else bytes(ext.value.value)


def measurements_of(report):
    """MRTD and the four RTMRs as hex, from a parsed TDX report."""
    out = {}
    for field in MEASUREMENT_FIELDS:
        value = getattr(report, field, None)
        out[field] = value.hex() if isinstance(value, (bytes, bytearray)) else None
    return out


def match_allowlist(actual):
    """The name of the authorized entry this image matches, or None.

    A null in an entry means the operator explicitly chose not to pin that
    register. `mr_td` may never be null: an entry that pins nothing authorizes
    everything."""
    for entry in config().get("measurements", []):
        name = entry.get("name") or "unnamed"
        assert entry.get("mr_td"), f"allowlist entry {name!r} does not pin mr_td"
        if all(entry.get(f) is None or entry.get(f) == actual.get(f)
               for f in MEASUREMENT_FIELDS):
            return name
    return None


def aggregate(actual):
    """A short stable id for an image, for the audit log when nothing matched."""
    joined = "|".join(f"{f}={actual.get(f)}" for f in MEASUREMENT_FIELDS)
    return hashlib.sha256(joined.encode()).hexdigest()[:32]


def _verify_quote(cert, fp):
    dcap = _dcap()
    if dcap is None:
        return Verdict(False, fp, reason="dcap-qvl is not installed")

    quote = extract_quote(cert)
    if not quote:
        return Verdict(False, fp, reason="client certificate carries no RA-TLS quote")

    try:
        parsed = dcap.parse_quote(quote)
    except Exception as err:
        return Verdict(False, fp, reason=f"quote does not parse: {err}")
    if not parsed.is_tdx():
        return Verdict(False, fp, reason="quote is not a TDX quote")

    actual = measurements_of(parsed.report)
    name = match_allowlist(actual)
    measurement = name or aggregate(actual)
    if name is None:
        return Verdict(False, fp, measurement=measurement,
                       reason="measurement is not on the allowlist")

    expected = report_data_for_cert(cert)
    got = bytes(getattr(parsed.report, "report_data", b""))
    if got[:len(expected)] != expected or any(got[len(expected):]):
        return Verdict(False, fp, measurement=measurement,
                       reason="report_data does not bind this certificate")

    try:
        import asyncio

        collateral = asyncio.run(dcap.get_collateral(config()["pccs_url"], quote))
        report = dcap.verify(quote, collateral, int(time.time()))
    except Exception as err:
        return Verdict(False, fp, measurement=measurement,
                       reason=f"quote verification failed: {err}")

    if report.status not in config().get("allowed_tcb_status", []):
        return Verdict(False, fp, measurement=measurement,
                       reason=f"TCB status {report.status}")
    rejected = set(config().get("rejected_advisories", [])) & set(report.advisory_ids or [])
    if rejected:
        return Verdict(False, fp, measurement=measurement,
                       reason=f"rejected advisories {sorted(rejected)}")

    return Verdict(True, fp, measurement=measurement, attested=True)


def verify_client(cert_der):
    """The verdict for one client certificate, cached by fingerprint.

    A missing certificate is a denial under `required`: Caddy is configured to
    demand one, so its absence means either a misconfigured proxy or something
    reaching this port directly."""
    current = mode()
    if not cert_der:
        if current == DEV_INSECURE:
            return Verdict(True, None, reason="attestation disabled (dev)", attested=False)
        return Verdict(False, None, reason="no client certificate presented")

    fp = fingerprint(cert_der)
    if current == DEV_INSECURE:
        return Verdict(True, fp, reason="attestation disabled (dev)", attested=False)

    now = time.time()
    with _LOCK:
        cached = _VERDICTS.get(fp)
    if cached is not None and now - cached[1] < RECHECK_SECONDS:
        return cached[0]

    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception as err:
        return Verdict(False, fp, reason=f"client certificate does not parse: {err}")

    verdict = _verify_quote(cert, fp)
    with _LOCK:
        _VERDICTS[fp] = (verdict, now)
    return verdict
