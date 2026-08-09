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

Both of those, and the model check, run *before* the verdict cache is consulted.
The cache is keyed on what the endpoint says about itself, so consulting it
first would hand a replayed identity the pass belonging to the instance it
copied, without that endpoint ever answering the nonce. What a cache hit means
after that ordering is only "the quote itself is not re-verified for a day",
which is the trade it was introduced for.

**The model server is not in RTMR3.** NEAR's TD boots a bootstrap compose --
a compose-manager, certbot, an otel collector -- and that is what RTMR3
measures. The model containers are brought up and down afterwards by the
manager, from separate files, without RTMR3 moving. Pinning the measurement
alone therefore pins the launcher and says nothing about what is serving
tokens.

What covers the gap is a second attestation the endpoint publishes beside the
first: the manager's action log, hashed into `actions_hash` and bound into its
own quote's report_data alongside our nonce. Each action names the compose file
and its SHA-256, so replaying the log says which composes were started and
never torn down, by content rather than by filename. `ComposeLog` recomputes
the hash from the actions rather than trusting the field, so an edited log
fails even though the quote over the claimed hash is valid.

What this still does not do: verify the response itself, or tie a container
image digest back to reviewed source (that needs the build's Sigstore
provenance). This module answers whether the endpoint is the authorized enclave
running authorized composes, at the cadence those can change.
"""

import hashlib
import json
import os
import secrets
from pathlib import Path

import certifi
import requests

from backend.tee import quote_policy
from backend.tee.quote_policy import DEV_INSECURE

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


class MalformedReport(AttestationError):
    """A field of the report is missing, or is not the shape it must be.

    Everything in a report is written by the party being checked, so a hex
    string that does not decode is an ordinary answer from an endpoint, not a
    broken invariant here. Asserting it raised AssertionError, and
    `bytes.fromhex` raised ValueError, straight out of `make_client()` past
    every reason string and every cached verdict -- fail-closed by accident
    rather than a refusal anyone could read. `verify()` turns this into a
    Verdict like any other denial."""


def _hex(raw, field, length=None):
    """Bytes from a hex field of the report, or `MalformedReport`."""
    if not isinstance(raw, str) or not raw:
        raise MalformedReport(f"{field} is missing")
    value = raw.removeprefix("0x").strip()
    if length is not None and len(value) != length * 2:
        raise MalformedReport(
            f"{field} is {len(value) // 2} bytes, expected {length}"
        )
    try:
        return bytes.fromhex(value)
    except ValueError as err:
        raise MalformedReport(f"{field} is not hex: {err}") from err


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
    except quote_policy.AllowlistInvalid as err:
        return str(err)
    if current == DEV_INSECURE:
        return None
    if quote_policy.load_dcap() is None:
        return "attestation required but dcap-qvl is not installed"
    for provider in providers:
        if not provider.attests():
            continue
        for key in ("measurements", "composes"):
            if not policy().rows(key, provider.name):
                return (f"provider {provider.name!r} is confidential but no {key} "
                        f"are authorized for it in {allowlist_path()}; run "
                        f"`python -m backend.integrations.inference_attestation {provider.name}`")
    return None


class Report:
    """One dstack attestation report, as the NEAR AI direct completions
    endpoints serve it. Parsing lives in one place so a field rename is one
    edit, not a hunt through the verification path."""

    def __init__(self, payload, nonce):
        if not isinstance(payload, dict):
            raise MalformedReport(f"attestation report is {type(payload).__name__}, not an object")
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
        return _hex(self.payload.get("intel_quote"), "intel_quote")

    @property
    def info(self):
        return self.payload.get("info") or {}

    def identity(self):
        """Everything that decides the verdict, as one cache key.

        The signing address alone is not enough: NEAR runs several CVMs behind
        one hostname and they can share a signing key, so keying on it would let
        a pinned instance's pass be served from cache for an unpinned one. The
        instance and the compose log are what actually differ between them, and
        the log changes whenever the manager starts anything, which is precisely
        when a cached verdict must not be reused."""
        log = self.payload.get("compose_manager_attestation") or {}
        return ":".join((
            self.signing_address,
            self.info.get("instance_id") or "no-instance",
            log.get("actions_hash") or "no-log",
        ))

    def address_bytes(self):
        return _hex(self.signing_address, "signing_address", ADDRESS_BYTES)

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

    def compose_log(self):
        payload = self.payload.get("compose_manager_attestation")
        return ComposeLog(payload, self.nonce) if payload else None


class ComposeLog:
    """The compose-manager's attested record of what it started and stopped.

    This is the only evidence of which model container is serving, because the
    manager launches them after boot and RTMR3 does not move when it does."""

    def __init__(self, payload, nonce):
        if not isinstance(payload, dict):
            raise MalformedReport(
                f"compose_manager_attestation is {type(payload).__name__}, not an object")
        self.payload = payload
        self.nonce = nonce

    @property
    def actions(self):
        actions = self.payload.get("actions") or []
        if not isinstance(actions, list):
            raise MalformedReport(
                f"compose_manager_attestation actions is {type(actions).__name__}, not a list")
        return actions

    @property
    def claimed_hash(self):
        return (self.payload.get("actions_hash") or "").strip()

    @property
    def quote(self):
        return _hex(self.payload.get("quote"), "compose_manager_attestation quote")

    def computed_hash(self):
        """SHA-256 over the actions as compact JSON with sorted keys, which is
        the canonicalization the manager signs. Recomputed rather than read, so
        appending a line to the log invalidates the quote over it."""
        canonical = json.dumps(self.actions, separators=(",", ":"), sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def hash_is_honest(self):
        return self.computed_hash() == self.claimed_hash

    def expected_report_data(self):
        return _hex(self.claimed_hash, "actions_hash") + bytes.fromhex(self.nonce)

    def started(self):
        """Compose file -> its SHA-256, for every compose brought up and not
        since brought down. Deliberately not "currently running": a container
        that exited on its own leaves no action, so this is the set that was
        started and never explicitly stopped, which is the larger and safer
        set to demand authorization for."""
        up = {}
        for action in self.actions:
            verb, name = action.get("action"), action.get("file")
            if not name:
                continue
            if verb == "compose_up":
                up[name] = action.get("file_sha256")
            elif verb == "compose_down":
                up.pop(name, None)
        return up


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
    """The verdict for one provider, cached by the enclave's identity.

    Keying on the identity rather than the URL is what makes the cache safe:
    one hostname is a pool of CVMs, and each fetch may reach a different one."""
    current = mode()
    if current == DEV_INSECURE:
        return quote_policy.Verdict(True, provider.name,
                                    reason="attestation disabled (dev)", attested=False)

    try:
        report = fetch(provider)
    except Exception as err:
        return quote_policy.Verdict(False, provider.name,
                                    reason=f"attestation report unavailable: {err}")

    try:
        subject = f"{provider.name}:{report.identity()}"
    except MalformedReport as err:
        return quote_policy.Verdict(False, provider.name, reason=f"malformed report: {err}")

    # Before the cache, not after. `identity()` is what the endpoint says about
    # itself, so an endpoint replaying a previously verified instance's fields
    # would otherwise be handed that instance's pass without echoing anything.
    # These two cost nothing here -- the fetch has already happened -- and they
    # narrow what a cache hit means to "the quote is not re-verified for a day",
    # which is the trade the cache was for.
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

    cached = _CACHE.get(subject)
    if cached is not None:
        return cached

    try:
        verdict = quote_policy.verify(
            report.quote, policy(), subject,
            report.expected_report_data(), scope=provider.name,
        )
        if verdict.ok:
            verdict = _verify_composes(report, provider, subject) or verdict
    except MalformedReport as err:
        # A field the provider wrote, in a shape it must not be. That is a
        # denial with a reason, not a traceback out of the middle of drafting.
        verdict = quote_policy.Verdict(False, subject, reason=f"malformed report: {err}")
    _CACHE.put(subject, verdict)
    return verdict


def _verify_composes(report, provider, subject):
    """The reason the compose log is unacceptable, as a failing Verdict, or None
    when it is fine. Separate from the boot measurement because it answers a
    different question: not which image booted, but what it has run since."""
    log = report.compose_log()
    if log is None:
        return quote_policy.Verdict(
            False, subject,
            reason="endpoint published no compose-manager attestation, so nothing "
                   "says which model container is serving",
        )
    if not log.hash_is_honest():
        return quote_policy.Verdict(
            False, subject,
            reason=f"actions_hash {log.claimed_hash} does not match the actions "
                   f"it is supposed to cover ({log.computed_hash()})",
        )

    manager = quote_policy.verify(
        log.quote, policy(), subject, log.expected_report_data(), scope=provider.name,
    )
    if not manager.ok:
        return quote_policy.Verdict(
            False, subject, measurement=manager.measurement,
            reason=f"compose-manager quote: {manager.reason}",
        )

    authorized = {row.get("file"): row.get("file_sha256")
                  for row in policy().rows("composes", provider.name)}
    unauthorized = sorted(
        f"{name}@{digest}" for name, digest in log.started().items()
        if authorized.get(name) != digest
    )
    if unauthorized:
        return quote_policy.Verdict(
            False, subject, measurement=manager.measurement,
            reason=f"unauthorized composes started in the enclave: {unauthorized}",
        )
    return None


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
    """The allowlist rows this provider's enclave would need, printed for a
    human to review and commit. Deliberately not written to the file: a pin
    that a script can add is a pin nobody read."""
    report = fetch(provider)
    measurement = {"name": f"{provider.name} {report.info.get('app_name') or 'unknown'}",
                   "scope": provider.name,
                   "compose_hash": report.info.get("compose_hash"),
                   "os_image_hash": report.info.get("os_image_hash")}
    measurement.update(report.measurements())

    log = report.compose_log()
    composes = [] if log is None else [
        {"scope": provider.name, "file": name, "file_sha256": digest}
        for name, digest in sorted(log.started().items())
    ]
    return {"measurements": [measurement], "composes": composes}


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
