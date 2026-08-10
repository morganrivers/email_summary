"""Refuse to run with assertions compiled out.

Under `-O` or `PYTHONOPTIMIZE=1` every `assert` in this tree disappears and the
process keeps running. That is a boot nobody asked for and nobody would notice,
so it is refused: both packages call this at import, `backend/__init__.py` for
the application and `cosigner/__init__.py` for the co-signer, which imports
nothing from `backend` and therefore cannot rely on its guard.

What this is **not** is the reason a control may be spelled as an assert. It
only covers boots that go through those two `__init__` files; a tool importing a
submodule directly, a REPL, or an entry point added next year gets the
optimized-out build with no refusal at all, and leaning on this would make
`PYTHONOPTIMIZE` a security setting. So the controls that used to be asserts
have been converted and the property is now stated the other way round:

    running under `-O` costs some internal invariant checking, and no control.

Every check whose subject crossed a trust boundary raises a named type -- the
account-id path guard (`account.check_id`), the duplicate-handle refusal in
`account.all_accounts`, the `"d" not in jwk` check standing between a library
change and the co-signer publishing its signing key, the empty binding in
`tee.quote_policy._binds`, the length and version checks in
`cosigner.keys.unwrap`. `tests/test_optimized_controls.py` runs the refusal
suites under `-O` and is what keeps that true for the ones written after today.
An assert here now means an invariant about our own callers, which `-O` is
welcome to remove.
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
