"""Can each systemd unit actually start on this box?

deploy.sh runs this on the server after the rsync and before it restarts
anything, so a unit whose secrets or Python deps are not provisioned yet is
skipped with a reason instead of being restarted into a crash loop.

Two checks per unit:
  * its entry module imports (catches a missing dependency, e.g. a
    requirements.txt line that was never installed into venv/)
  * its configuration is present, decided by calling the same code the service
    itself calls -- PolarBilling() for the Polar credentials,
    session.secret_configured() for the cookie secret. No copies of those rules
    live here.

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

from dotenv import load_dotenv

from backend import paths

UNIT_DIR = Path(__file__).resolve().parent / "hetzner"
_EXEC_MODULE = re.compile(r"^ExecStart=.*?\s-m\s+(\S+)", re.MULTILINE)

load_dotenv(paths.ENV_FILE)


def _polar_configured():
    """Polar API token + organization for the active environment, plus the
    webhook signing secret. PolarBilling's own asserts are the check."""
    from backend.billing import billing

    try:
        billing.PolarBilling()
    except AssertionError as err:
        return str(err)
    if not billing.webhook_secret():
        return "POLAR_WEBHOOK_SECRET not set"
    return None


def _polar_read_configured():
    """The poller never verifies a webhook, so it needs the token and org only."""
    from backend.billing import billing

    try:
        billing.PolarBilling()
    except AssertionError as err:
        return str(err)
    return None


def _session_configured():
    from frontend import session

    if not session.secret_configured():
        return "SESSION_SECRET not set"
    return None


def _manifest_present():
    """Units that enumerate accounts at startup need the store to exist. There
    is no implicit owner account any more, so an unseeded box is a configuration
    gap the deploy should report rather than a service that asserts on wake."""
    from backend.accounts import account

    if not account.MANIFEST.exists():
        return (f"no account manifest at {account.MANIFEST}; run "
                "`venv/bin/python -m backend.accounts.seed_owner`")
    return None


# module -> extra configuration check, run only after the module imports.
CONFIG_CHECKS = {
    "backend.billing.billing_webhook": _polar_configured,
    "backend.billing.billing_poller": _polar_read_configured,
    "frontend.web_server": _session_configured,
    "backend.daemons.daemon_loop": _manifest_present,
    "backend.daemons.gmail_hook_server": _manifest_present,
    "backend.onboarding.watch_renew": _manifest_present,
    # The summary sweeps every account, so it needs the store like the rest.
    "backend.drafting.email_summary": _manifest_present,
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
