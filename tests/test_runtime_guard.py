"""Neither package starts with assertions compiled out.

`python -O` deletes every assert in the tree and changes nothing else, so a boot
under it is one nobody chose and nobody would notice. This is that refusal, plus
the two places the flag could arrive without a code review seeing it: a unit
file and the flake.

It is deliberately not the argument that the code behind it is safe. This guard
covers only the boots that go through the two package `__init__` files, so what
answers for the rest is `tests/test_optimized_controls.py`, which runs the
refusal suites under `-O` and requires them to pass unchanged.
"""

import re
import subprocess
import sys
from pathlib import Path

import pytest

import runtime_guard
from tools import reachability

REPO_ROOT = Path(__file__).resolve().parent.parent

OPTIMIZE_FLAG = re.compile(r"(?:^|\s)-{1,2}(?:O{1,2}|-optimize)\b")
OPTIMIZE_ENV = re.compile(r"PYTHONOPTIMIZE\s*=\s*\"?(\S*?)\"?\s*$", re.M)


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


@pytest.mark.parametrize("unit", sorted(reachability.UNIT_DIR.glob("*.service")),
                         ids=lambda p: p.name)
def test_no_unit_asks_for_a_stripped_interpreter(unit):
    """The guard above turns `-O` into a unit that will not start, which is the
    right failure and a bad way to find out. A unit file is the one place the
    flag could be added without a code review seeing it, so it is read here:
    ExecStart is the command line, Environment= is the rest of the answer."""
    text = unit.read_text()
    for line in text.splitlines():
        if line.startswith("ExecStart"):
            assert not OPTIMIZE_FLAG.search(line), (
                f"{unit.name} starts python with assertions stripped: {line.strip()}"
            )
    found = OPTIMIZE_ENV.search(text)
    assert found is None or found.group(1) in ("", "0"), (
        f"{unit.name} sets {found.group(0).strip()!r}, which strips assertions"
    )


def test_the_enclave_image_does_not_ask_for_one_either():
    """The image starts its processes from the flake with no operator at the
    console, so a flag reaching it is one nobody is positioned to notice."""
    code = "\n".join(line.split("#", 1)[0]
                     for line in reachability.FLAKE.read_text().splitlines())
    for line in code.splitlines():
        if "python" in line and " -m " in line:
            assert not OPTIMIZE_FLAG.search(line), (
                f"flake.nix starts python with assertions stripped: {line.strip()}"
            )
    assert OPTIMIZE_ENV.search(code) is None, "flake.nix sets PYTHONOPTIMIZE"
