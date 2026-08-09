"""Is the thing on the other end of this connection the enclave we authorized?

RA-TLS puts the TDX quote inside the enclave's own certificate, so the check
costs no extra round trip: the certificate arrives with the handshake and the
quote arrives with it.

**Cadence: per TLS connection, not per request.** A quote is a boot-time
measurement -- MRTD and RTMR0-3 are fixed when the TD launches -- so asking a
thousand times an hour returns identical bytes. The enclave mints a fresh
RA-TLS keypair at each boot, and a boot is exactly when the measurement can
change, so an unseen certificate fingerprint is the correct trigger for the
full check.

The five checks themselves live in ``backend/tee/quote_policy.py``, shared with
the outbound inference path so the two directions cannot drift. What stays here
is what is genuinely RA-TLS: pulling the quote out of a certificate extension,
and what report_data has to bind to.

Check 3 (measurements against the allowlist) is why this service exists at all
given the KMS already gates `app_secret`: the allowlist sits under a different
operator, and the enclave cannot edit it.

What this does not detect: a correct image subverted at runtime -- a side
channel, an injection, a ROP chain. Attestation is about which code booted.
The rate limit and the audit log are what bound that case.
"""

import hashlib
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from backend.tee import quote_policy
from backend.tee.quote_policy import DEV_INSECURE  # noqa: F401  (re-exported for callers)
from backend.tee.quote_policy import REQUIRED, Verdict

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "allowlist.json"

_CACHE = quote_policy.VerdictCache()
_POLICY = None


def config_path():
    return Path(os.environ.get("COSIGNER_ALLOWLIST") or DEFAULT_CONFIG_PATH)


def policy():
    global _POLICY
    path = config_path()
    if _POLICY is None or _POLICY.path != path:
        _POLICY = quote_policy.Policy(path)
    return _POLICY


def config():
    return policy().data


def reset_for_test(path=None):
    """Forget the parsed config and every cached verdict. With no path, go back
    to the packaged allowlist rather than whatever a previous call pointed at."""
    global _POLICY
    _POLICY = None
    _CACHE.clear()
    if path is None:
        os.environ.pop("COSIGNER_ALLOWLIST", None)
    else:
        os.environ["COSIGNER_ALLOWLIST"] = str(path)


def mode():
    """`required` or `dev-insecure`.

    The escape hatch exists so tracks I and J can be built and tested before
    the Phala instance is rented (plan §7, phase 1). TEE_REQUIRED set anywhere
    in this unit's environment is the other tell that somebody has provisioned
    this box for production."""
    value = policy().mode(os.environ.get("COSIGNER_ATTESTATION"))
    if value == DEV_INSECURE:
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
        if not policy().entries():
            return f"attestation required but no measurements authorized in {config_path()}"
        if not config().get("quote_oid"):
            return f"attestation required but quote_oid is unset in {config_path()}"
        if quote_policy.load_dcap() is None:
            return "attestation required but dcap-qvl is not installed"
    return None


def fingerprint(cert_der):
    return hashlib.sha256(cert_der).hexdigest()


def match_allowlist(actual):
    return policy().match(actual)


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
    if hasattr(ext.value, "public_bytes"):
        return ext.value.public_bytes()
    return bytes(ext.value.value)


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

    cached = _CACHE.get(fp)
    if cached is not None:
        return cached

    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception as err:
        return Verdict(False, fp, reason=f"client certificate does not parse: {err}")

    quote = extract_quote(cert)
    if not quote:
        return Verdict(False, fp, reason="client certificate carries no RA-TLS quote")

    verdict = quote_policy.verify(quote, policy(), fp, report_data_for_cert(cert))
    _CACHE.put(fp, verdict)
    return verdict
