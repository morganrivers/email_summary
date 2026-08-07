"""Can each systemd unit actually start on this box?

deploy.sh runs this on the server after the rsync and before it restarts
anything, so a unit whose secrets or Python deps are not provisioned yet is
skipped with a reason instead of being restarted into a crash loop.

Two checks per unit:
  * its entry module imports (catches a missing dependency, e.g. a
    requirements.txt line that was never installed into venv/)
  * its configuration is present, decided by backend/secrets.py, which answers
    by calling the same code the service itself calls -- PolarBilling() for the
    Polar credentials. No copies of those rules live here or in the TEE boot
    gate.

The unit -> module mapping is read out of the unit files' ExecStart, so the
.service file stays the only place a unit's entry point is named. A timer is
checked through the service it triggers (systemd's same-basename default).

Usage: python -m deploy.preflight [unit ...]   (default: every installed unit)
Prints one line per unit, "OK <unit>" or "SKIP <unit>: <reason>", and exits 0
even when units are skipped -- deploy.sh decides what to do about them.
"""

import re
import subprocess
import sys
from pathlib import Path

from backend import paths
from backend import secrets

UNIT_DIR = Path(__file__).resolve().parent / "hetzner"
_EXEC_MODULE = re.compile(r"^ExecStart=.*?\s-m\s+(\S+)", re.MULTILINE)
_LOAD_CREDENTIAL = re.compile(r"^LoadCredentialEncrypted=[^:]+:(\S+)", re.MULTILINE)

secrets.load()


def _manifest_present():
    """Units that enumerate accounts at startup need the store to exist. There
    is no implicit owner account any more, so an unseeded box is a configuration
    gap the deploy should report rather than a service that asserts on wake."""
    from backend.accounts import account

    if not account.MANIFEST.exists():
        return (f"no account manifest at {account.MANIFEST}; run "
                "`venv/bin/python -m backend.accounts.seed_owner`")
    return None


def _mail_configured():
    """What a unit that touches a mailbox needs before it is worth starting: the
    account store, the shared Google OAuth app every token refresh is signed
    with, and custody. The enclave gates on the same OAuth pair through
    ``secrets.REQUIRED``; this is the Hetzner half of it, so the box does not
    check a strict subset of what the CVM fails closed on."""
    return (_manifest_present() or secrets.google_oauth_configured()
            or _custody_available() or _inference_attestable())


def _inference_attestable():
    """Can every confidential provider be decided about? A provider whose
    enclave image rotated out of the allowlist takes drafting down the moment a
    user who chose it gets mail, so it belongs in the deploy's report rather
    than in a daemon traceback at 3am."""
    from backend.integrations import inference_attestation, llm_client

    return inference_attestation.configured(llm_client.PROVIDERS.values())


def _custody_available():
    """Every access token now costs a co-signer round trip and there is no
    bypass, so a mail unit on a box whose co-signer cannot start has nothing to
    do but alert the operator on every wake.

    Only answerable while the co-signer runs here. Once it moves to its own
    operator this deploy has no standing to judge it -- reachability is not
    checkable either, since its site block demands a client certificate this
    script does not hold -- so the check reports nothing rather than guessing."""
    if unit_for_module("cosigner.server") is None:
        return None
    reason = _cosigner_configured()
    return f"custody unavailable: {reason}" if reason else None


def _web_configured():
    """The web UI signs users in with Google, so a missing OAuth app takes it
    down as surely as a missing cookie key does. It also generates voice
    profiles, which builds an inference client like any mail path does."""
    return (secrets.session_configured() or secrets.google_oauth_configured()
            or _inference_attestable())


def _definitely_absent(path):
    """Is this file certainly not there? A credential store is 0700 root-only,
    so an unprivileged run of this script cannot see inside it. Reporting
    "missing" from a PermissionError would skip a correctly provisioned unit;
    only a readable directory with nothing in it is evidence."""
    try:
        return not Path(path).exists()
    except PermissionError:
        return False


def _egress_allowlist_derivable():
    """The proxy computes its allowlist at startup from the modules that name
    the hosts, so an import that broke one of them is an empty or short list and
    an empty list is every unit offline. Checked here rather than left to the
    assert in main() because the sandbox this deploy installs points every other
    unit at this proxy: it starting is the precondition for the rest of the box
    having a network at all."""
    from backend import egress

    allowed = egress.hosts()
    if not allowed:
        return "the egress allowlist came back empty; no unit could reach anything"
    return None


def _cosigner_configured():
    """The co-signer needs its two sealed credentials on disk and an
    attestation allowlist it can decide with.

    The credentials are checked as the *encrypted* files the unit loads, not as
    decrypted material: systemd only unseals them into $CREDENTIALS_DIRECTORY
    for the running unit, so this process could never see them and a check that
    tried would skip a correctly provisioned box forever."""
    from cosigner import attest

    unit = unit_for_module("cosigner.server")
    if unit is None:
        return "no unit runs cosigner.server"
    missing = [p for p in _LOAD_CREDENTIAL.findall((UNIT_DIR / unit).read_text())
               if _definitely_absent(p)]
    if missing:
        return (f"sealed credentials missing: {', '.join(missing)}; see the header of "
                f"deploy/hetzner/{unit}")
    return attest.configured()


# module -> extra configuration check, run only after the module imports. The
# secret checks come from backend/secrets.py, which the TEE boot gate also
# applies: a unit skipped here for a missing value is the same unit that would
# fail closed in the enclave, for the same stated reason.
CONFIG_CHECKS = {
    "cosigner.server": _cosigner_configured,
    "backend.daemons.egress_proxy": _egress_allowlist_derivable,
    "backend.billing.billing_webhook": secrets.polar_configured,
    "backend.billing.billing_poller": secrets.polar_api_configured,
    "frontend.web_server": _web_configured,
    "backend.daemons.daemon_loop": _mail_configured,
    "backend.daemons.gmail_hook_server": _mail_configured,
    "backend.onboarding.watch_renew": _mail_configured,
    # The summary sweeps every account, so it needs the store like the rest.
    "backend.drafting.email_summary": _mail_configured,
}


def unit_module(unit):
    """The Python module a unit runs, read from its ExecStart. Timers resolve
    through the same-basename service. None when the unit runs something that is
    not a Python module (or the unit file is missing)."""
    name = unit if unit.endswith((".service", ".timer")) else f"{unit}.service"
    if name.endswith(".timer"):
        name = f"{name[:-6]}.service"
    path = UNIT_DIR / name
    if not path.exists():
        return None
    m = _EXEC_MODULE.search(path.read_text())
    return m.group(1) if m else None


def unit_for_module(module):
    """The unit file that runs a module, so a check can read the unit's own
    settings without hardcoding its filename."""
    for name in installed_units():
        if unit_module(name) == module:
            return name
    return None


def imports_cleanly(module):
    """Import the module in a throwaway process: a failure here is a missing
    dependency or a config value read at import time, both of which would take
    the service down on start. Every entry module is inert at import (main() is
    guarded), so nothing blocks."""
    result = subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        cwd=paths.REPO_ROOT, capture_output=True, timeout=120,
    )
    if result.returncode == 0:
        return None
    tail = (result.stderr.decode(errors="replace").strip().splitlines() or ["import failed"])[-1]
    return tail


def check_unit(unit):
    """None when the unit is safe to (re)start, else the reason it is not."""
    module = unit_module(unit)
    if module is None:
        return None  # not a Python unit; nothing here can vouch for it
    failure = imports_cleanly(module)
    if failure is not None:
        return failure
    check = CONFIG_CHECKS.get(module)
    return check() if check else None


def installed_units():
    return sorted(p.name for p in UNIT_DIR.iterdir()
                  if p.suffix in (".service", ".timer"))


def main(argv):
    units = argv or installed_units()
    for unit in units:
        reason = check_unit(unit)
        if reason is None:
            print(f"OK {unit}")
        else:
            print(f"SKIP {unit}: {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
