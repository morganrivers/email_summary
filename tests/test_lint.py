"""flake8 and isort, run by the suite rather than by memory.

A linter in a contributing guide is a linter nobody runs. These two are pinned
in requirements-dev.txt, configured in setup.cfg, and fail here, so a warning
lands in the same red the rest of the suite lands in.

flake8 carries pyflakes, which is the half that finds defects rather than
formatting: an unused import is usually a refactor that did not finish, and a
redefinition (F811) is one of two functions that will never be called. The
pycodestyle half is style, and the configuration in setup.cfg says which style.

The trees checked are the first-party packages named in tools/reachability.py,
so a new top-level package is linted because it is a package rather than because
someone remembered to add it here.
"""

import subprocess
import sys

import pytest

from backend import paths
from tools import reachability

TREES = sorted(reachability.PACKAGES + ("tests",))


def _run(module, *args):
    return subprocess.run(
        [sys.executable, "-m", module, *args, *TREES],
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
