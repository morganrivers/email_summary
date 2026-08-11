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

from backend import paths, secrets, secrets_checks
from tools import reachability

UNIT_DIR = Path(__file__).resolve().parent / "hetzner"
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
    ``secrets_checks.REQUIRED``; this is the Hetzner half of it, so the box does
    not check a strict subset of what the CVM fails closed on.

    Looser than ``secrets_checks.REQUIRED_BY_ROLE["mail"]``, and the difference
    is not drift. The enclave's mail role additionally fails closed without an
    inference key, the Telegram token and the Polar API token, because in there
    no container receives Polar webhooks and the reconcile it runs is the only
    path a renewal or a cancellation travels. On this box those are separate
    units with their own entries in the table below, a Polar receiver exists,
    and a box with no Polar configured at all drafts mail perfectly well -- so
    requiring them here would skip the daemon over units it does not run."""
    return (_manifest_present() or secrets_checks.google_oauth_configured()
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
    """What the web UI needs by itself: the secrets of the enclave's `web` role,
    and the co-signer it asks for a data key when it renders a user's two
    documents.

    The secret half is `secrets_checks.REQUIRED_BY_ROLE["web"]` rather than a
    list here, because this unit and that container are the same program with the
    same needs, and two lists is how one of them ends up checking something the
    other does not. Today that is the cookie key alone: the consent URL, the
    code exchange, voice generation and the three Polar calls all run in the
    daemon over backend/custody/handoff.py, because this process is allowed
    neither a mailbox token, nor the client secret that would obtain one, nor
    an organization-wide Polar token. A box missing any of those takes the
    daemon out of this report, which is where the remedy is; the site itself
    stays up with everything except sign-in."""
    gaps = secrets_checks.missing("web")
    return (gaps[0] if gaps else None) or _custody_available()


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
    """The proxy reads its allowlist from a committed file, so a deploy that
    rsynced a tree without it -- or with one this code cannot parse -- is a proxy
    that refuses to start, and the sandbox this deploy installs points every
    other unit at that proxy. It starting is the precondition for the rest of the
    box having a network at all, which is why this is checked before the restart
    rather than found afterwards.

    Staleness is not checked here and deliberately so: re-deriving the list needs
    the modules that name the hosts, which is the fan-out the proxy stopped
    carrying. `tests/test_egress.py` compares the committed file against those
    constants, so a stale list fails in CI, where the fix is a re-render and a
    commit rather than an edit on a box."""
    from backend import egress

    try:
        allowed = egress.hosts()
    except egress.AllowlistInvalid as e:
        return str(e)
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
# secret checks come from backend/secrets_checks.py, which the TEE boot gate
# also applies: a unit skipped here for a missing value is the same unit that
# would fail closed in the enclave, for the same stated reason.
CONFIG_CHECKS = {
    "cosigner.server": _cosigner_configured,
    "backend.daemons.egress_proxy": _egress_allowlist_derivable,
    # The receiver verifies signatures and spools; it holds no API token and
    # reads .env.billing alone, so the webhook secret is the whole of what it
    # needs. Checking polar_configured() here would skip the unit for a missing
    # value it never reads, or pass it on one it cannot see.
    "backend.billing.billing_webhook": secrets_checks.polar_webhook_configured,
    "backend.billing.billing_poller": secrets_checks.polar_api_configured,
    "frontend.web_server": _web_configured,
    # The daemon applies the spooled billing events, so the API token is its
    # concern now. Not a hard requirement: a box with no Polar configured
    # drafts mail perfectly well, which is why this stays _mail_configured.
    "backend.daemons.daemon_loop": _mail_configured,
    "backend.daemons.gmail_hook_server": _mail_configured,
    "backend.onboarding.watch_renew": _mail_configured,
    # The summary sweeps every account, so it needs the store like the rest.
    "backend.drafting.email_summary": _mail_configured,
}


def unit_module(unit):
    """The Python module a unit runs, read from its ExecStart. Timers resolve
    through the same-basename service. None when the unit runs something that is
    not a Python module (or the unit file is missing).

    The name is checked into the shape of a dotted module before it leaves here,
    because `imports_cleanly()` puts it inside a string an interpreter then
    executes. The argument list means there is no shell and the source is a file
    in this repository rather than a request, so this is not a live hole; it is
    the shape worth removing on sight, and the check is one regex. A unit file
    naming something else is a broken repository and stops the run rather than
    skipping one unit.

    Both the expression that finds the name and the one that judges it come from
    `tools.reachability`, which reads the same `ExecStart=` lines out of the same
    files to decide what ships. Two copies would be two answers to one
    question."""
    name = unit if unit.endswith((".service", ".timer")) else f"{unit}.service"
    if name.endswith(".timer"):
        name = f"{name[:-6]}.service"
    path = UNIT_DIR / name
    if not path.exists():
        return None
    m = reachability.EXEC_MODULE_RE.search(path.read_text())
    if not m:
        return None
    return reachability.check_module_name(m.group(1), path.name)


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
