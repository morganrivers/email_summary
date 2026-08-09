"""What the co-signer is allowed to learn an account by.

The co-signer needs a stable per-account value to enforce its per-account
ceiling and its wrap-once rule. While that value was the user's email address,
a copy of the co-signer's database was the customer list plus a timestamped
record of when each of those people's mail was processed -- on the box whose
stated premise is that compromising it yields a wrapping key with nothing to
unwrap.

The fix is one substitution, and the danger is that the substitution is
invisible. Nothing on the co-signer parses the value, so passing an address
where a handle belongs works: the request succeeds, the log fills with
addresses, and the only symptom is that the derived key differs from the one
the record was written under, which surfaces later as a record that will not
open. So the property is pinned three ways -- the guard refuses a value that is
not a handle, the tree is read for a call that names the wrong variable, and
`tests/test_custody_integration.py` greps the co-signer's real database for an
address after a real refresh.
"""

import ast

import pytest
from harness import python_sources, relative

from backend.accounts import account

# Every client function whose first argument crosses the wire as `F_UID`.
WIRE_CALLS = ("wrap", "unwrap", "unwrap_and_sign", "rewrap")

# What that argument is allowed to be spelled. Not a taint analysis: the point
# is that one name is used everywhere for the value that leaves this box, so a
# call passing `uid`, `email` or `acct.id` reads as wrong on sight and fails
# here rather than at the next rotation.
ALLOWED = {"handle"}


def wire_calls(path):
    """`(function, first argument source, line)` for each co-signer call."""
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr not in WIRE_CALLS:
            continue
        if not isinstance(func.value, ast.Name) or func.value.id != "cosigner":
            continue
        yield func.attr, ast.unparse(node.args[0]), node.lineno


def test_every_cosigner_call_names_a_handle():
    offenders = [
        f"{relative(path)}:{line} cosigner.{name}({arg})"
        for path in python_sources(("backend",))
        for name, arg, line in wire_calls(path)
        if arg not in ALLOWED
    ]
    assert not offenders, (
        "a co-signer call passed something other than `handle`: "
        + "; ".join(offenders)
        + ". If that value is an account id, this box has just put an address "
        "in the co-signer's audit log and derived the wrong key with it."
    )


def test_the_rule_can_fail():
    """The check above is worth nothing if no call could ever offend it."""
    found = [name for path in python_sources(("backend",))
             for name, _, _ in wire_calls(path)]
    assert set(found) == set(WIRE_CALLS), (
        f"expected a call to each of {WIRE_CALLS}, found {sorted(set(found))}"
    )


@pytest.mark.parametrize("value", [
    "alice@example.com",
    "default",
    "",
    None,
    "0123456789abcdef0123456789abcde",       # 31 hex digits
    "0123456789ABCDEF0123456789ABCDEF",      # one value, one spelling
])
def test_the_guard_refuses_anything_that_is_not_a_handle(value):
    with pytest.raises(AssertionError):
        account.check_handle(value)


def test_a_minted_handle_is_random_and_of_the_shape_the_guard_wants():
    minted = {account.new_handle() for _ in range(50)}
    assert len(minted) == 50, "handles repeat, so two accounts can collide"
    for handle in minted:
        assert account.check_handle(handle) == handle


def test_a_handle_resolves_back_to_a_person_only_here(tmp_path, monkeypatch):
    """The mapping the co-signer does not have. `whois` is the operator command
    that reads it, and it is why making the log opaque does not make an incident
    unactionable."""
    from backend.accounts import whois

    monkeypatch.setattr(account, "ACCOUNTS_DIR", tmp_path)
    monkeypatch.setattr(account, "MANIFEST", tmp_path / "accounts.json")
    acct = account.register_account("dana@x.com", "Dana", "R")

    assert whois.resolve(acct.handle) == ("account", "dana@x.com")
    assert whois.resolve("dana@x.com") == ("handle", acct.handle)
    assert whois.resolve("f" * 32) is None
    assert whois.resolve("nobody@x.com") is None


def test_a_re_consent_keeps_the_handle_it_already_had(tmp_path, monkeypatch):
    """Every record the account owns is encrypted with the handle as the salt
    and the AAD, so a new one on a second sign-in would leave the user unable to
    read their own data."""
    monkeypatch.setattr(account, "ACCOUNTS_DIR", tmp_path)
    monkeypatch.setattr(account, "MANIFEST", tmp_path / "accounts.json")
    first = account.register_account("dana@x.com", "Dana", "R")
    again = account.register_account("dana@x.com", "Dana", "R")
    assert again.handle == first.handle


def test_two_accounts_never_share_a_handle(tmp_path, monkeypatch):
    """Asserted when the manifest is read, not only when it is written: a
    hand-edited entry that duplicated one would let one account open another's
    records and spend its co-signer budget."""
    monkeypatch.setattr(account, "ACCOUNTS_DIR", tmp_path)
    monkeypatch.setattr(account, "MANIFEST", tmp_path / "accounts.json")
    account.register_account("dana@x.com", "Dana", "R")
    account.register_account("eve@x.com", "Eve", "R")

    data = account._read_manifest()
    data["accounts"][1]["handle"] = data["accounts"][0]["handle"]
    account._write_manifest(data)
    with pytest.raises(AssertionError, match="share an opaque handle"):
        account.all_accounts()
