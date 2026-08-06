"""Neither package starts with assertions compiled out.

Several controls in this tree are spelled as asserts and are the control rather
than a note about one: the path-traversal check on a token path, the "the JWK
we publish carries no private key" check, the refusal to accept a quote bound to
nothing. `python -O` deletes all of them and changes nothing else, which is the
one way this codebase can be running and unprotected at the same time.
"""

import subprocess
import sys
from pathlib import Path

import pytest

import runtime_guard

REPO_ROOT = Path(__file__).resolve().parent.parent


def _import_under_O(package):
    return subprocess.run(
        [sys.executable, "-O", "-c", f"import {package}"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )


def test_asserts_are_enabled_in_this_run():
    assert runtime_guard.asserts_enabled()


@pytest.mark.parametrize("package", ["backend", "cosigner"])
def test_importing_with_assertions_disabled_refuses_to_start(package):
    """Both, separately. `cosigner` imports nothing from `backend`, so it cannot
    inherit the application's guard and needs its own."""
    result = _import_under_O(package)
    assert result.returncode != 0, f"{package} imported happily under -O"
    assert "assertions disabled" in result.stderr
