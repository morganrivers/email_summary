"""flake8, isort and bandit, run by the suite rather than by memory.

A linter in a contributing guide is a linter nobody runs. All three are pinned
in requirements-dev.txt and fail here, so a warning lands in the same red the
rest of the suite lands in. flake8 and isort read setup.cfg; bandit does not
read setup.cfg at all, so its one piece of configuration is SKIPS below.

flake8 carries pyflakes, which is the half that finds defects rather than
formatting: an unused import is usually a refactor that did not finish, and a
redefinition (F811) is one of two functions that will never be called. The
pycodestyle half is style, and the configuration in setup.cfg says which style.

bandit asks the third question, which neither of the others does: is this call
one of the known-dangerous ones. What it is here for is B506 (yaml.load), the
TLS checks (B501/B502/B503), B324 (an insecure hash), B602/B605 (a shell), B113
(a request with no timeout) and B701 -- a class of mistake that reviews miss
because each is one plausible-looking line.

The trees checked are the first-party packages named in tools/reachability.py,
so a new top-level package is linted because it is a package rather than because
someone remembered to add it here. flake8 and isort also read tests/; bandit
does not, because a test constructs fake credentials and swallows exceptions on
purpose, and neither is a defect in something that runs.

bandit runs twice, because two bodies of code here have different rules.
`SHIPPED` is what a service starts and what the measured image carries, and it
is scanned with nothing skipped but B101. `OPERATOR` is `deploy/` and `tools/`,
run by hand on somebody's machine, never inside a unit and never in the image
(`deploy/phala/image_files.nix` lists no file from either), and there the three
subprocess checks are skipped. Skipping them tree-wide, which is what this
module did first, means the day something under `backend/` grows a
`subprocess.run` there is no warning at all.
"""

import subprocess
import sys

import pytest

from backend import paths
from tools import reachability

TREES = sorted(reachability.PACKAGES + ("tests",))

# Run by hand by an operator; everything else is started by a unit or shipped in
# the image. The split is what lets the subprocess checks stay on where it
# matters, so it is spelled as the exception rather than as two hand-written
# lists that can drift from reachability.PACKAGES.
OPERATOR = ("deploy", "tools")
SHIPPED = sorted(set(reachability.PACKAGES) - set(OPERATOR)) + ["runtime_guard.py"]

# The one check that is wrong about this codebase on every line it fires on, so
# it is here rather than as a marker on each of 216 asserts. Everything else is
# a `# nosec <id>  # reason` on the line it belongs to.
SKIPS = {
    "B101": "an assert here states an invariant about our own caller, never a "
            "control: every check whose subject crossed a trust boundary raises "
            "a named type, and tests/test_optimized_controls.py runs the refusal "
            "suites under -O to keep it that way",
}

# Skipped for OPERATOR only.
SUBPROCESS_SKIPS = {
    "B404": "importing subprocess is not a finding; B602/B605 judge the call, "
            "and both stay on here",
    "B603": "fires on every subprocess.run taking a list argv, which is the safe "
            "form. B602 (shell=True) stays on and is the one that matters",
    "B607": "`uv` and `systemd-run` come from PATH, and pinning absolute paths "
            "would break the developer machines these run on for no gain: "
            "anyone who can edit that PATH can edit the script",
}


def _run(module, *args, trees=TREES):
    return subprocess.run(
        [sys.executable, "-m", module, *args, *trees],
        cwd=paths.REPO_ROOT, capture_output=True, text=True, timeout=600,
    )


def _require(module):
    if subprocess.run([sys.executable, "-c", f"import {module}"],
                      capture_output=True).returncode != 0:
        pytest.fail(
            f"{module} is not installed; it is pinned in requirements-dev.txt "
            f"and this check is not optional"
        )


def test_flake8_is_clean():
    _require("flake8")
    result = _run("flake8")
    assert result.returncode == 0, (
        f"flake8 found {len(result.stdout.strip().splitlines())} problems:\n"
        f"{result.stdout}{result.stderr}"
    )


def test_imports_are_sorted():
    _require("isort")
    result = _run("isort", "--check-only", "--diff")
    assert result.returncode == 0, (
        f"isort would reorder imports; run `python -m isort {' '.join(TREES)}`"
        f"\n{result.stdout}{result.stderr}"
    )


def _bandit(trees, skips):
    _require("bandit")
    return _run("bandit", "--quiet", "--recursive",
                "--skip", ",".join(sorted(skips)), trees=trees)


def test_bandit_finds_nothing_in_shipped_code():
    """What a unit starts and what the image carries, with the subprocess checks
    on. There is no `subprocess`, `os.system`, `eval` or `exec` anywhere under
    these packages today; this is what keeps it that way.

    A genuine false positive gets `# nosec <id>  # reason` on its line, the way
    `# noqa` is already used here. Seven exist, all B105."""
    result = _bandit(SHIPPED, SKIPS)
    assert result.returncode == 0, (
        f"bandit found problems in shipped code:\n{result.stdout}{result.stderr}"
    )


def test_bandit_finds_nothing_in_operator_code():
    result = _bandit(list(OPERATOR), {**SKIPS, **SUBPROCESS_SKIPS})
    assert result.returncode == 0, (
        f"bandit found problems in operator code:\n{result.stdout}{result.stderr}"
    )
