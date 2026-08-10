"""TEE boot gate (Track F3) and hello-world spike (Track F1).

Two entrypoints, one module (single source of the attestation boot sequence):

  python tee_boot.py <role>     attest-before-run gate. Run by the container
                                entrypoint before daemon/webhook start. When
                                TEE_REQUIRED=1 it fails closed unless the CVM is
                                genuinely attested and secrets were released.
                                The role is the compose `command:` -- what a
                                container must be provisioned with is a function
                                of which container it is, since the compose file
                                hands each one a different subset and that
                                partition is what RTMR3 measures.

  python tee_boot.py --selftest F1 hello-world: exercise KMS unseal + RA-TLS +
                                quote against the live guest agent and print the
                                results. Deployed via f1-selftest-compose.yml.

Fail-closed rule: the load-bearing secret is the Gmail OAuth token. If we cannot
prove we run attested, we must not touch mailboxes. So under TEE_REQUIRED the
gate aborts (exit 1) rather than starting the daemon. Outside a CVM (dev box,
Hetzner) the socket is absent and, with TEE_REQUIRED unset, the gate no-ops so
the same app code still runs.

The KMS is the enforcer: GetKey / GetTlsKey release only to a CVM whose
measurement matches the authorized policy. A tampered image gets a refusal here,
which is exactly the F2 wrong-measurement signal.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

from backend import paths, secrets, secrets_checks
from backend.tee.dstack_client import DstackClient, DstackError, DstackUnavailable

APP_KEY_PATH = "tee-email-bot/app"
RA_TLS_SUBJECT = "tee-email-bot"

ATTEST_DIR = Path(os.environ.get("TEE_ATTEST_DIR", "/app/attestation"))


def _report_data_for_cert(cert_pem: str) -> bytes:
    return hashlib.sha256(cert_pem.encode()).digest()


def _write_attestation_record(info: dict, tls: dict, quote: dict) -> None:
    ATTEST_DIR.mkdir(parents=True, exist_ok=True)
    chain = tls.get("certificate_chain") or []
    # Created 0600 rather than written and then chmodded. The compose file
    # mounts this directory as a tmpfs at mode 0777 -- the runtime creates it as
    # root and the container's process is not root -- so a default-mode create
    # is a world-readable private key for as long as it takes to reach the
    # chmod. paths.write_private is the same call in backend/custody/client.py,
    # which writes the co-signer client key into this same directory.
    paths.write_private(ATTEST_DIR / "ra_tls.key", tls.get("key", ""))
    (ATTEST_DIR / "ra_tls.crt").write_text("\n".join(chain))
    record = {
        "app_id": info.get("app_id"),
        "instance_id": info.get("instance_id"),
        "compose_hash": info.get("compose_hash"),
        "mr_aggregated": info.get("mr_aggregated"),
        "os_image_hash": info.get("os_image_hash"),
        "key_provider_info": info.get("key_provider_info"),
        "quote": quote.get("quote"),
        "event_log": quote.get("event_log"),
        "report_data": quote.get("report_data"),
    }
    (ATTEST_DIR / "boot_info.json").write_text(json.dumps(record, indent=2))


def _measurement_gap(info: dict) -> str | None:
    """Why this boot is not the published one, or None when it is.

    An unset EXPECTED_COMPOSE_HASH used to return here silently, so the check
    was on only for whoever remembered to set the variable -- and the compose
    file ships it as `${EXPECTED_COMPOSE_HASH:-}`, which is unset by default.
    A comparison that passes when one side is missing is not a comparison.

    What it is worth, exactly, since it is easy to over-read: the value comes
    from the enclave's own environment, so it is the enclave checking a claim it
    was handed rather than one anybody else made. It catches the deploy that
    published one compose and booted another. The statement no operator can
    forge is `cosigner/attest.py`'s allowlist, on the other box.

    A reason string rather than an assert because it is operator input, and
    because `run_gate` has one way of reporting a refusal and every other
    fail-closed branch already uses it."""
    expected = os.environ.get("EXPECTED_COMPOSE_HASH", "").strip()
    if not expected:
        return ("EXPECTED_COMPOSE_HASH is unset. Under TEE_REQUIRED the enclave "
                "has to be told which compose it is supposed to be, or it will "
                "run whichever one it was given.")
    actual = (info.get("compose_hash") or "").strip()
    if actual != expected:
        return (f"compose_hash mismatch: running {actual!r} != published "
                f"{expected!r}. Image does not match the published measurement.")
    return None


def _inference_attestable() -> str | None:
    """Can every confidential provider be decided about? A capability and not a
    secret, which is why it is here and not in ``backend/secrets_checks.py``: it
    asks whether the dcap-qvl wheel made it into the image and whether the
    provider's enclave is pinned. Both are properties of the build.

    The same call `deploy/preflight.py` makes, so the box and the image report
    an unpinned image the same way. Without it a build that dropped the wheel
    starts cleanly and refuses every confidential draft at the first email, with
    the reason buried in a per-draft log line."""
    from backend.integrations import inference_attestation, llm_client

    return inference_attestation.configured(llm_client.PROVIDERS.values())


def _host_overridden() -> str | None:
    """Every externally visible URL this role mints must name this deployment.

    ``backend/site.py`` compiles in the Hetzner hostnames as defaults. A CVM
    that does not override them redirects Google's consent to the box's
    ``/auth/callback``, which holds a different SESSION_SECRET and a different
    state cookie -- so either sign-in is refused as "did not start in this
    browser" or, if the two share a session secret, the box exchanges the
    authorization code and takes custody of the refresh token. Same for the
    checkout return URL and every link in a Telegram message."""
    from backend import site

    stale = [name for name, value, default in (
        ("LETTERLOCK_HOST", site.APP_HOST, site.DEFAULT_APP_HOST),
        ("LETTERLOCK_API_HOST", site.API_HOST, site.DEFAULT_API_HOST),
    ) if value == default]
    if stale:
        return (f"{', '.join(stale)} still names the Hetzner deployment; every "
                "URL this role mints would send the user to the other box")
    return None


# What each role needs beyond its secrets, asked at boot in the container that
# needs it. Kept apart from ``secrets_checks.REQUIRED_BY_ROLE`` because these
# are properties of the image and of this deployment's configuration rather
# than values the KMS releases, and because the compose file cannot satisfy
# them by naming a variable.
CAPABILITIES_BY_ROLE = {
    "mail": (_inference_attestable, _host_overridden),
    "web": (_host_overridden,),
    "hook": (),
    "egress": (),
}

assert set(CAPABILITIES_BY_ROLE) == set(secrets_checks.REQUIRED_BY_ROLE), (
    "the two role tables name different roles; a role admitted by one and "
    "missing from the other is a KeyError inside the gate"
)


def _role_from(argv: list[str]) -> str:
    """Which container this is. The compose `command:` is the statement of
    record, so the entrypoint passes it straight through; LETTERLOCK_ROLE is the
    fallback for a hand-run gate."""
    positional = [a for a in argv if not a.startswith("-")]
    role = (positional[0] if positional else os.environ.get("LETTERLOCK_ROLE", "")).strip()
    return role


def run_gate(role: str = "") -> int:
    client = DstackClient()

    if not secrets.tee_required():
        if client.available():
            print("[tee_boot] dstack socket present; TEE_REQUIRED unset, skipping gate.")
        else:
            print("[tee_boot] no dstack socket and TEE_REQUIRED unset (dev/non-TEE host).")
        return 0

    if role not in secrets_checks.REQUIRED_BY_ROLE:
        print(f"[tee_boot] FAIL-CLOSED: TEE_REQUIRED but role {role!r} is not one of "
              f"{sorted(secrets_checks.REQUIRED_BY_ROLE)}; the gate cannot know what "
              "to require of a container it cannot name.", file=sys.stderr)
        return 1

    on_volume = secrets_checks.volume_secrets()
    if on_volume:
        for path in on_volume:
            print(
                f"[tee_boot] FAIL-CLOSED: {path} exists inside the CVM. "
                "Secrets are injected post-attestation as encrypted environment; "
                "a file on the volume is a copy the KMS does not gate.",
                file=sys.stderr,
            )
        return 1

    try:
        info = client.info()
    except DstackUnavailable as e:
        print(f"[tee_boot] FAIL-CLOSED: TEE_REQUIRED but no guest agent: {e}", file=sys.stderr)
        return 1

    gap = _measurement_gap(info)
    if gap:
        print(f"[tee_boot] FAIL-CLOSED: {gap}", file=sys.stderr)
        return 1

    try:
        # GetTlsKey is KMS-gated: success proves attestation passed and gives us
        # the RA-TLS keypair whose cert the guest agent binds to the quote.
        tls = client.get_tls_key(subject=RA_TLS_SUBJECT)
        # GetKey exercises the same release path used to unseal per-app material.
        client.get_key(APP_KEY_PATH, purpose="seal")
        leaf = (tls.get("certificate_chain") or [""])[0]
        quote = client.get_quote(_report_data_for_cert(leaf))
    except DstackError as e:
        print(f"[tee_boot] FAIL-CLOSED: KMS/attestation refused: {e}", file=sys.stderr)
        return 1

    # Which secrets must be present, and what "present" means, live in
    # backend/secrets_checks.py -- the same checks the deploy preflight runs.
    # This was a list of four variable names here, so the gate passed without
    # SESSION_SECRET, the Polar credentials or the Google OAuth client secret:
    # a gate that names its own subset drifts from the services it gates. It is
    # asked per role because the compose file answers per role.
    gaps = secrets_checks.missing(role) + [
        reason for reason in (check() for check in CAPABILITIES_BY_ROLE[role]) if reason
    ]
    if gaps:
        for reason in gaps:
            print(f"[tee_boot] FAIL-CLOSED: attested but not provisioned: {reason}",
                  file=sys.stderr)
        return 1

    _write_attestation_record(info, tls, quote)
    print(
        f"[tee_boot] attested role={role}. "
        f"app_id={info.get('app_id')} compose_hash={info.get('compose_hash')} "
        f"mr_aggregated={info.get('mr_aggregated')}"
    )
    return 0


def run_selftest() -> int:
    client = DstackClient()
    if not client.available():
        print(f"[f1] no dstack socket at {client.socket_path}; deploy inside a CVM.",
              file=sys.stderr)
        return 1

    print("[f1] === dstack hello-world: KMS unseal + RA-TLS + quote ===")
    info = client.info()
    for k in ("app_id", "instance_id", "compose_hash", "mr_aggregated", "os_image_hash"):
        print(f"[f1] info.{k} = {info.get(k)}")

    key = client.get_key(APP_KEY_PATH, purpose="selftest")
    kb = key.get("key", "")
    print(f"[f1] GetKey ok: key_len={len(kb)} sig_chain={len(key.get('signature_chain') or [])}")

    tls = client.get_tls_key(subject=RA_TLS_SUBJECT)
    chain = tls.get("certificate_chain") or []
    print(f"[f1] GetTlsKey ok: has_key={bool(tls.get('key'))} cert_chain_len={len(chain)}")

    leaf = chain[0] if chain else ""
    quote = client.get_quote(_report_data_for_cert(leaf))
    q = quote.get("quote", "")
    print(f"[f1] GetQuote ok: quote_len={len(q)} report_data={quote.get('report_data')}")

    print("[f1] SUCCESS: KMS released keys and a TDX quote to this measurement.")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return run_selftest()
    return run_gate(_role_from(argv))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
