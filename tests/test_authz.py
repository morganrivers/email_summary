"""Who may reach whose data, on the application side.

Two properties, neither of which any single review of a route handler proves.

The first is the lesson the checkout IDOR taught: that bug was not a missing
`if`. It was an externally supplied identifier used before it had been resolved
to an owner. So the invariant worth pinning is not "every handler calls
_require_auth" -- it is that no account-scoped call ever names its account from
something the request carried. `frontend/web_server.py` is read as an AST for
that, the way `tests/test_llm_boundary.py` reads the tree for a forbidden
endpoint, because a grep over ~25 handlers is exactly the check a reviewer
skips on the twenty-sixth.

The second is that the store is unreadable to any account but the one the units
run as. Tenant separation here is filesystem convention (all six units share the
`letterlock` uid), so the modes are the whole of it and a default 0755 from one
forgotten `mkdir` removes it silently.
"""

import ast
import stat

import pytest

from backend import paths
from backend.accounts import account


WEB_SERVER = paths.REPO_ROOT / "frontend" / "web_server.py"

# Modules whose functions take an account identifier first. `provisioning` is
# deliberately absent: `handle_callback(query, ...)` consumes the OAuth query by
# design and derives the identity from Google's answer rather than from the
# browser. `billing` is absent for the same kind of reason -- `confirm_checkout`
# takes a browser-supplied checkout id on purpose and resolves it back to the
# signed-in account itself (tests/test_billing.py).
ACCOUNT_SCOPED = {"account", "voice_dna", "personal_context"}

# Where request-controlled data enters a handler. Anything assigned from an
# expression mentioning one of these is tainted, and so is anything assigned
# from that.
REQUEST_DATA = {"form", "query"}


def _tree():
    return ast.parse(WEB_SERVER.read_text())


def _names(node):
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _root(node):
    """The name an expression is built out of: `form.get(x).strip()` -> `form`.

    Taint follows the root rather than every name mentioned, because
    `account.set_settings(acct.id, timezone=tz)` mentions a tainted `tz` and
    returns an Account. Reading that as tainted would mark every later `acct`
    in the handler and make the rule useless."""
    while True:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, ast.Subscript):
            node = node.value
        else:
            return None


def _tainted_names(scope):
    """Names inside one function that carry something the request supplied.

    Per function, not per module: `_handle_post` binds `email` from the contact
    form and `_get_account` binds it from the signed cookie, and a module-wide
    answer would have to call both the same thing.

    Fixed-point rather than one pass, so `tz = form.get(...)` followed by
    `chosen = tz` is caught."""
    tainted = set(REQUEST_DATA)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(scope):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            if node.value is None or _root(node.value) not in tainted:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for name in ast.walk(target):
                    if isinstance(name, ast.Name) and name.id not in tainted:
                        tainted.add(name.id)
                        changed = True
    return tainted


def _account_scoped_calls(scope):
    for node in ast.walk(scope):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = node.func
        if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                and func.value.id in ACCOUNT_SCOPED):
            yield f"{func.value.id}.{func.attr}", node.args[0]


def _offenders(scope):
    tainted = _tainted_names(scope)
    return [
        f"{name}({ast.unparse(first)}) at line {first.lineno}"
        for name, first in _account_scoped_calls(scope)
        if _root(first) in tainted or (_names(first) & tainted)
    ]


def _scopes(tree):
    return [n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def test_no_route_names_an_account_from_the_request():
    found = [o for scope in _scopes(_tree()) for o in _offenders(scope)]
    assert not found, (
        "an account-scoped call took its account from request data: "
        + "; ".join(found)
        + ". The account must come from the signed cookie (_require_auth), or "
        "be resolved to an owner first the way confirm_checkout does."
    )


def test_the_taint_rule_would_catch_the_bug_it_exists_for():
    """The check above passing means nothing unless it can fail. This is the
    shape of the checkout IDOR, rewritten as an account lookup."""
    tree = ast.parse(
        "def handler(self):\n"
        "    form = self._read_body()\n"
        "    who = form.get('account_id')\n"
        "    acct = account.account_for_email(who)\n"
        "    return voice_dna.load(acct)\n"
    )
    (scope,) = _scopes(tree)
    assert "who" in _tainted_names(scope)
    assert _offenders(scope), "the rule cannot fail, so its passing says nothing"


def test_the_rule_does_not_fire_on_a_request_value_that_is_not_an_identifier():
    """A handler passing a form field as a *setting* is the normal case; only
    the account position is the question."""
    tree = ast.parse(
        "def handler(self, acct):\n"
        "    form = self._read_body()\n"
        "    tz = form.get('timezone')\n"
        "    account.set_settings(acct.id, timezone=tz)\n"
    )
    (scope,) = _scopes(tree)
    assert not _offenders(scope)


def test_every_authenticated_handler_derives_its_account_from_the_cookie():
    """`_get_account` is the only place an Account is built in the web tier, and
    it reads the session. A second construction path is how one route ends up
    with an ownership rule of its own."""
    tree = _tree()
    builders = [
        node for name, node in
        ((f"{n.func.value.id}.{n.func.attr}", n) for n in ast.walk(tree)
         if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
         and isinstance(n.func.value, ast.Name))
        if name == "account.account_for_email"
    ]
    assert builders, "web_server no longer builds an account at all; update this test"
    for node in builders:
        source = ast.unparse(node.args[0])
        assert source in ("email", "acct.id"), (
            f"account_for_email({source}) at line {node.lineno}: an account is "
            "built from something other than the session email or an account "
            "already authenticated"
        )


@pytest.fixture
def store(tmp_path, monkeypatch):
    home = tmp_path / "database"
    monkeypatch.setattr(account, "ACCOUNTS_DIR", home)
    monkeypatch.setattr(account, "MANIFEST", home / "accounts.json")
    return home


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_the_store_is_unreadable_to_every_other_local_account(store):
    account.register_account("dana@x.com", "Dana", "R")
    assert _mode(store) == 0o700, "the store directory is readable off-uid"
    assert _mode(account.MANIFEST) == 0o600, (
        "accounts.json carries per-user identity, chat ids and billing links"
    )


def test_a_rewritten_manifest_does_not_widen_its_own_mode(store):
    account.register_account("dana@x.com", "Dana", "R")
    account.MANIFEST.chmod(0o644)
    account.register_account("eve@x.com", "Eve", "R")
    assert _mode(account.MANIFEST) == 0o600, (
        "the atomic replace must carry the mode; a widened file stays widened "
        "until someone notices"
    )
