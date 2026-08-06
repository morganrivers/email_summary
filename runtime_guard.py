"""Refuse to run with assertions compiled out.

This codebase states its security controls as asserts, and several of them are
the control rather than a note about one: the path-traversal check in
`custody.tokens.token_path`, the `"d" not in jwk` check that stands between a
library change and the co-signer publishing its signing key, the empty-binding
check in `tee.quote_policy._binds` that would otherwise accept a quote bound to
nothing, the length and version checks in `cosigner.keys.unwrap`. Under `-O` or
`PYTHONOPTIMIZE=1` every one of them disappears and the process keeps running,
which is the failure mode this exists to make impossible.

Converting those four to explicit raises would protect those four. This
protects all of them, including the ones written after today, and it is why an
assert is an acceptable way to spell a control here. Both packages call it at
import, so no entry point can miss it: `backend/__init__.py` for the
application, `cosigner/__init__.py` for the co-signer, which imports nothing
from `backend` and therefore cannot rely on its guard.
"""

import sys


class OptimizedOut(RuntimeError):
    """Assertions are disabled, so the controls written as asserts are gone."""


def asserts_enabled():
    """True when `assert` still evaluates. Written so the answer comes from the
    interpreter's own behaviour rather than from reading a flag that a future
    Python could stop honouring."""
    enabled = False
    assert (enabled := True), "unreachable"
    return enabled


def require_asserts():
    """Raise unless assertions are live. Called at package import."""
    if asserts_enabled():
        return
    raise OptimizedOut(
        "Letterlock refuses to start with assertions disabled: python was run "
        f"with -O or PYTHONOPTIMIZE={sys.flags.optimize}, which compiles out "
        "the checks this codebase states as asserts, several of which are "
        "security controls rather than notes (see runtime_guard.__doc__)."
    )
