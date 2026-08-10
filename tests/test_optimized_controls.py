"""Running with assertions compiled out costs invariant checking, not controls.

`runtime_guard` refuses to start under `-O`, and that refusal is correct, but it
is not an argument that the code behind it is safe: it only covers boots that go
through `backend/__init__.py` or `cosigner/__init__.py`. A tool importing a
submodule directly, a REPL, or an entry point somebody adds next year gets the
optimized-out build with no refusal at all. Depending on the guard alone makes
`PYTHONOPTIMIZE` a security setting, which is the one thing it must not be.

So the property is stated the only way that can fail honestly: run the suites
that pin refusals with `PYTHONOPTIMIZE=1`, with the guard neutralised for the
duration, and require them to pass unchanged. Every check standing between an
input and something it must not reach raises a named type, so those tests still
pass; an assert states an invariant about our own callers, and a test whose
subject is one of those carries `harness.needs_asserts` and skips here.

The moment somebody spells a new control as an assert, one of these suites goes
red under `-O` while staying green everywhere else, which is exactly the
signal wanted. pytest rewrites the assertions inside test modules into code the
interpreter does not strip, so the suites keep their own teeth in this run --
what disappears is the asserts in the code under test, which is the point.

The guard is neutralised through `sitecustomize`, imported by `site` before any
first-party package, rather than through an environment variable this codebase
honours: a switch that turns the refusal off in production would be a worse
thing than the one this test exists to prevent.
"""

import subprocess
import sys

import pytest

from backend import paths

# The suites whose subject is a refusal: split custody, the co-signer's request
# policy, the handle boundary, and the prompt fence. Between them they cover
# every module Track A of docs/plan_bandit_findings.md converted.
SUITES = (
    "tests/test_custody.py",
    "tests/test_cosigner.py",
    "tests/test_handle_boundary.py",
    "tests/test_prompt_fence.py",
)

SITECUSTOMIZE = """\
import runtime_guard

# The guard is what this run is deliberately stepping around; every other
# refusal in the tree has to hold on its own.
runtime_guard.require_asserts = lambda: None
"""

TIMEOUT = 900


@pytest.fixture(scope="module")
def optimized_env(tmp_path_factory):
    """`-O` for the child, with the boot guard patched out and nothing else."""
    stage = tmp_path_factory.mktemp("optimized")
    (stage / "sitecustomize.py").write_text(SITECUSTOMIZE)
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(stage),
        "PYTHONOPTIMIZE": "1",
        "PYTHONPATH": f"{stage}{':'}{paths.REPO_ROOT}",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _run(env, *args):
    return subprocess.run(
        [sys.executable, *args], cwd=paths.REPO_ROOT, env=env,
        capture_output=True, text=True, timeout=TIMEOUT,
    )


def test_the_child_really_runs_with_assertions_disabled(optimized_env):
    """Without this the suite below could pass by never having been optimized.

    It also proves the second half: `backend` imported at all, so the guard was
    neutralised rather than the package quietly failing to load."""
    result = _run(optimized_env, "-c",
                  "import sys, backend, cosigner; print(sys.flags.optimize)")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "1", result.stdout


def test_the_refusal_suites_pass_with_assertions_compiled_out(optimized_env):
    result = _run(optimized_env, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                  *SUITES)
    assert result.returncode == 0, (
        "a refusal stopped refusing once assertions were compiled out, so it "
        "was written as an assert and is a control with an interpreter flag "
        "for an off switch. Convert it to a named raise (see "
        "docs/plan_assert_conversion.md); mark the test with "
        f"harness.needs_asserts only if what it pins is an internal invariant."
        f"\n{result.stdout}{result.stderr}"
    )
