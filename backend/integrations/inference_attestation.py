"""Is the enclave about to read this user's mail the one we authorized?

`llm_client` names a base URL and an API key. Neither proves anything: a
provider that advertises confidential inference and a provider that says so on
a marketing page are the same two strings. This module is what turns "runs in
an attested enclave" from a claim about the vendor into a property this box
enforces, by refusing to build a client for a confidential provider whose
enclave does not verify.

The evidence comes from the provider's own attestation endpoint, and the check
is the shared one in ``backend/tee/quote_policy`` -- the same five checks the
co-signer applies to inbound RA-TLS, pointed the other way.

Two bindings make the report about *our* call rather than about some enclave
somewhere:

  * report_data carries the response signing address, so the key that signs
    completions is the key the quote vouches for
  * report_data carries a nonce we generated seconds ago, so a captured report
    from a previously-good image cannot be replayed

The enclave also states which model it serves, and that is checked against the
model the provider is configured to ask for. A gateway that quietly routed to a
different model would otherwise pass every cryptographic check.

What this does not do: verify the response itself. Per-completion receipts are
signed by the attested key and checking them is the next layer, not this one.
This module answers whether the endpoint is the authorized enclave, at the
cadence a boot-time measurement can change.
"""

import json
import os
import secrets
from pathlib import Path

import certifi
import requests

from backend.tee import quote_policy
from backend.tee.quote_policy import DEV_INSECURE, REQUIRED

DEFAULT_ALLOWLIST = Path(__file__).resolve().parent / "inference_allowlist.json"

NONCE_BYTES = 32
ADDRESS_BYTES = 20
_PAD_BYTES = 12

TIMEOUT_SECONDS = 30

_CACHE = quote_policy.VerdictCache()
_POLICY = None


class AttestationError(RuntimeError):
    """Raised instead of returning a client. Refusing to draft is the failure
    this is for; the alternative is mail going somewhere unverified."""


def allowlist_path():
    return Path(os.environ.get("LETTERLOCK_INFERENCE_ALLOWLIST") or DEFAULT_ALLOWLIST)


def policy():
    global _POLICY
    path = allowlist_path()
    if _POLICY is None or _POLICY.path != path:
        _POLICY = quote_policy.Policy(path)
    return _POLICY


def reset_for_test(path=None):
    global _POLICY
    _POLICY = None
    _CACHE.clear()
    if path is None:
        os.environ.pop("LETTERLOCK_INFERENCE_ALLOWLIST", None)
    else:
        os.environ["LETTERLOCK_INFERENCE_ALLOWLIST"] = str(path)


def mode():
    return policy().mode(os.environ.get("LETTERLOCK_INFERENCE_ATTESTATION"))


def configured(providers):
    """None when every confidential provider can be decided about, else why one
    cannot. `deploy/preflight.py` calls this so an unpinned image is reported at
    deploy time rather than by every draft failing."""
    try:
        current = mode()
    except AssertionError as err:
        return str(err)
    if current == DEV_INSECURE:
        return None
    if quote_policy.load_dcap() is None:
        return "attestation required but dcap-qvl is not installed"
    for provider in providers:
        if not provider.attests():
            continue
        if not policy().entries(provider.name):
            return (f"provider {provider.name!r} is confidential but no measurements "
                    f"are authorized for it in {allowlist_path()}; run "
                    f"`python -m backend.integrations.inference_attestation {provider.name}`")
    return None


class Report:
    """One dstack attestation report, as the NEAR AI direct completions
    endpoints serve it. Parsing lives in one place so a field rename is one
    edit, not a hunt through the verification path."""

    def __init__(self, payload, nonce):
        assert isinstance(payload, dict), "attestation report must be a JSON object"
        self.payload = payload
        self.nonce = nonce

    @property
    def model(self):
        return self.payload.get("model_name")

    @property
    def signing_address(self):
        return (self.payload.get("signing_address") or "").strip()

    @property
    def request_nonce(self):
        return (self.payload.get("request_nonce") or "").strip()

    @property
    def quote(self):
        raw = self.payload.get("intel_quote")
        assert raw, "attestation report carries no intel_quote"
        return bytes.fromhex(raw)

    @property
    def info(self):
        return self.payload.get("info") or {}

    def address_bytes(self):
        value = self.signing_address.removeprefix("0x")
        assert len(value) == ADDRESS_BYTES * 2, (
            f"signing_address is {len(value) // 2} bytes, expected {ADDRESS_BYTES}"
        )
        return bytes.fromhex(value)

    def expected_report_data(self):
        """What the quote must carry: the signing address, then the padding the
        20-byte address leaves in a 32-byte word, then the nonce we sent."""
        return self.address_bytes() + bytes(_PAD_BYTES) + bytes.fromhex(self.nonce)

    def echoed_our_nonce(self):
        return self.request_nonce == self.nonce

    def measurements(self):
        dcap = quote_policy.load_dcap()
        assert dcap is not None, "dcap-qvl is not installed"
        return quote_policy.measurements_of(dcap.parse_quote(self.quote).report)


def fetch(provider, nonce=None):
    """The provider's current report, bound to a nonce we just generated."""
    assert provider.attestation_url, f"provider {provider.name!r} names no attestation url"
    nonce = nonce or secrets.token_hex(NONCE_BYTES)
    response = requests.get(
        provider.attestation_url, params={"nonce": nonce},
        timeout=TIMEOUT_SECONDS, verify=certifi.where(),
    )
    response.raise_for_status()
    return Report(response.json(), nonce)


def verify(provider):
    """The verdict for one provider, cached by the enclave's signing address.

    Keying on the signing address rather than the URL is what makes the cache
    safe: the address changes when the enclave reboots, and a reboot is exactly
    when the measurement can change."""
    current = mode()
    if current == DEV_INSECURE:
        return quote_policy.Verdict(True, provider.name,
                                    reason="attestation disabled (dev)", attested=False)

    try:
        report = fetch(provider)
    except Exception as err:
        return quote_policy.Verdict(False, provider.name,
                                    reason=f"attestation report unavailable: {err}")

    subject = f"{provider.name}:{report.signing_address}"
    cached = _CACHE.get(subject)
    if cached is not None:
        return cached

    if not report.echoed_our_nonce():
        return quote_policy.Verdict(
            False, subject,
            reason=f"endpoint echoed nonce {report.request_nonce!r}, not the one we sent",
        )
    if report.model != provider.model:
        return quote_policy.Verdict(
            False, subject,
            reason=f"enclave serves model {report.model!r}, not {provider.model!r}",
        )

    verdict = quote_policy.verify(
        report.quote, policy(), subject,
        report.expected_report_data(), scope=provider.name,
    )
    _CACHE.put(subject, verdict)
    return verdict


def require(provider):
    """Verify or raise. The only entry point the mail path should use."""
    verdict = verify(provider)
    if not verdict.ok:
        raise AttestationError(
            f"refusing to send mail to {provider.name!r}: {verdict.reason} "
            f"(measurement {verdict.measurement}); authorize it in "
            f"{allowlist_path()} after reviewing it, or pick another provider"
        )
    return verdict


def pin(provider):
    """The allowlist entry this provider's enclave would need, printed for a
    human to review and commit. Deliberately not written to the file: a pin
    that a script can add is a pin nobody read."""
    report = fetch(provider)
    entry = {"name": f"{provider.name} {report.info.get('app_name') or 'unknown'}",
             "scope": provider.name,
             "compose_hash": report.info.get("compose_hash"),
             "os_image_hash": report.info.get("os_image_hash")}
    entry.update(report.measurements())
    return entry


def main(argv):
    from backend.integrations import llm_client

    names = argv or [p.name for p in llm_client.PROVIDERS.values() if p.attests()]
    for name in names:
        provider = llm_client.PROVIDERS.get(name)
        assert provider is not None, f"unknown provider {name!r}"
        print(json.dumps(pin(provider), indent=2))
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main(sys.argv[1:]))
