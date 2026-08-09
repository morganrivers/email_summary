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
"""

import subprocess
import sys

import pytest

from backend import paths
from tools import reachability

TREES = sorted(reachability.PACKAGES + ("tests",))
SHIPPED = sorted(reachability.PACKAGES)

# Whole-class false positives, listed here with the reason rather than as a
# nosec marker on each of the twelve hundred lines. A check that is wrong about
# this codebase every single time teaches everyone to ignore the output.
SKIPS = {
    "B101": "asserts are a control here, not a note about one; runtime_guard "
            "refuses to start under -O and tests/test_runtime_guard.py pins it",
    "B105": "fires on a variable *name* holding token/secret/password, which is "
            "what SESSION_SECRET_ENV and TOKEN_ENDPOINT are: names of names",
    "B106": "same rule, reached through a keyword argument (token_file=...)",
    "B107": "same rule, reached through a default argument",
    "B404": "importing subprocess is not a finding; B602/B605 judge the call",
    "B603": "fires on every subprocess.run taking a list argv, which is the safe "
            "form. B602 (shell=True) stays on and is the one that matters",
    "B607": "`uv` and `systemd-run` are resolved from PATH by deploy tooling run "
            "by hand on a developer's box, never by a service",
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


def test_bandit_finds_nothing():
    """A finding that is genuinely a false positive gets `# nosec <id>` and a
    reason on the line, the way `# noqa` is already used here. A whole class of
    them belongs in SKIPS instead."""
    _require("bandit")
    result = _run("bandit", "--quiet", "--recursive",
                  "--skip", ",".join(sorted(SKIPS)), trees=SHIPPED)
    assert result.returncode == 0, (
        f"bandit found problems:\n{result.stdout}{result.stderr}"
    )
