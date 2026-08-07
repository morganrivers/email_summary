"""Whether anything we ship has a known advisory against it.

    python -m deploy.audit          # print the report, exit 1 if it blocks

What is audited is `deploy/phala/uv.lock`, not `requirements.txt`. The lock is
the full transitive closure; requirements.txt holds direct pins only, so a CVE
in something pulled in indirectly -- urllib3 under requests, cffi under
cryptography -- is invisible there. The lock is also the artifact uv2nix builds
the measured image from, so it is the list that describes what actually runs.

The closure is read through `uv export --frozen`, which reads the committed lock
and resolves nothing, so this says what is pinned today rather than what would
resolve today. Environment markers are stripped before auditing: pip-audit
evaluates them against the interpreter running it, and a Windows-only or
PyPy-only line is still a line in the image. Stripping them means a package is
audited once regardless of which machine runs the job, which is why the closure
is asserted to name each distribution once.

Hashes are exported off. The lock is already the integrity record, and pip-audit
under `--no-deps` installs nothing that a hash could protect.

The daily job blocks. An advisory with no fixed version therefore needs a
deliberate decision rather than a red job everyone learns to scroll past, and
that decision goes in `deploy/audit_ignores.toml` with an expiry date. Expiry is
the whole point: an entry past its date fails the audit exactly as the advisory
did, so an ignore cannot quietly become permanent. An entry that no longer
matches anything fails too, so the file cannot accumulate ignores for
advisories that were fixed years ago.
"""

import datetime
import json
import re
import subprocess
import sys
import tempfile
import tomllib

from backend import paths
from deploy import requirements

LOCK_DIR = requirements.PYPROJECT_FILE.parent
LOCK_FILE = LOCK_DIR / "uv.lock"
IGNORE_FILE = paths.REPO_ROOT / "deploy" / "audit_ignores.toml"

_MARKER = re.compile(r"\s*;.*$")
_IGNORE_KEYS = {"id", "expires", "reason"}


def closure():
    """Every distribution the lock pins, as `name==version` lines."""
    assert LOCK_FILE.exists(), f"no lock to audit at {LOCK_FILE}"
    exported = subprocess.run(
        ["uv", "export", "--directory", str(LOCK_DIR),
         "--frozen", "--no-hashes", "--no-emit-project"],
        capture_output=True, text=True, check=True,
    ).stdout
    pins = []
    for raw in exported.splitlines():
        line = _MARKER.sub("", raw).strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        pins.append(line)
    parsed = requirements.parse("\n".join(pins) + "\n", LOCK_FILE)
    named = requirements.names(parsed)
    assert len(named) == len(parsed), (
        f"{LOCK_FILE} exports the same distribution at two versions; the "
        "marker-stripping in this module assumes one version per name"
    )
    return parsed


def vulnerabilities(pins):
    """What pip-audit says about those exact pins, resolving nothing."""
    with tempfile.NamedTemporaryFile("w", suffix=".txt") as fh:
        fh.write("\n".join(pins) + "\n")
        fh.flush()
        proc = subprocess.run(
            [sys.executable, "-m", "pip_audit", "--requirement", fh.name,
             "--no-deps", "--format", "json", "--progress-spinner", "off"],
            capture_output=True, text=True,
        )
    assert proc.stdout.strip(), (
        f"pip-audit produced no report (exit {proc.returncode}): {proc.stderr.strip()}"
    )
    found = []
    for dep in json.loads(proc.stdout)["dependencies"]:
        for vuln in dep.get("vulns", []):
            found.append(Vulnerability(dep["name"], dep["version"], vuln))
    return found


class Vulnerability:
    """One advisory against one pinned distribution."""

    def __init__(self, name, version, vuln):
        self.name = name
        self.version = version
        self.id = vuln["id"]
        self.aliases = set(vuln.get("aliases") or ())
        self.fix_versions = list(vuln.get("fix_versions") or ())

    def known_as(self, identifier):
        return identifier == self.id or identifier in self.aliases

    def __str__(self):
        fix = ", ".join(self.fix_versions) if self.fix_versions else "no fix available"
        return f"{self.name}=={self.version}  {self.id}  ({fix})"


class Ignore:
    """A deliberate, dated decision not to block on one advisory."""

    def __init__(self, entry, source=IGNORE_FILE):
        assert set(entry) == _IGNORE_KEYS, (
            f"{source.name} entry needs exactly {sorted(_IGNORE_KEYS)}, got "
            f"{sorted(entry)}. An ignore without an expiry date is a permanent one."
        )
        self.id = entry["id"]
        self.expires = datetime.date.fromisoformat(entry["expires"])
        self.reason = entry["reason"].strip()
        assert self.reason, f"{source.name} entry {self.id} has an empty reason"

    def covers(self, vuln):
        return vuln.known_as(self.id)

    def __str__(self):
        return f"{self.id}  expires {self.expires}  {self.reason}"


def ignores(text=None):
    entries = tomllib.loads(IGNORE_FILE.read_text() if text is None else text)
    return [Ignore(entry) for entry in entries.get("ignore", [])]


class Report:
    """The audit's verdict: what blocks, and what about the ignore file itself
    blocks. Both are failures, because a stale ignore file is how a blocking
    audit turns into an advisory one nobody notices."""

    def __init__(self, vulns, ignores_, today):
        self.today = today
        self.expired = [i for i in ignores_ if i.expires < today]
        live = [i for i in ignores_ if i.expires >= today]
        self.unused = [i for i in live if not any(i.covers(v) for v in vulns)]
        self.blocking = [v for v in vulns
                         if not any(i.covers(v) for i in live)]
        self.ignored = [v for v in vulns if v not in self.blocking]

    def ok(self):
        return not (self.blocking or self.expired or self.unused)

    def render(self):
        lines = []
        for vuln in self.blocking:
            lines.append(f"VULNERABLE  {vuln}")
        for vuln in self.ignored:
            lines.append(f"ignored     {vuln}")
        for ignore in self.expired:
            lines.append(
                f"EXPIRED     {ignore} -- re-decide it or drop the pin; "
                "an expired ignore blocks the same way the advisory does"
            )
        for ignore in self.unused:
            lines.append(
                f"STALE       {ignore} -- matches nothing in the lock any more; "
                f"delete it from {IGNORE_FILE.name}"
            )
        if not lines:
            lines.append("no known vulnerabilities in the lock")
        return "\n".join(lines)


def audit(today=None):
    return Report(vulnerabilities(closure()), ignores(),
                  today or datetime.date.today())


def main():
    report = audit()
    print(report.render())
    return 0 if report.ok() else 1


if __name__ == "__main__":
    sys.exit(main())
