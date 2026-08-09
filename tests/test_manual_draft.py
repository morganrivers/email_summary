"""The manual (`+bot`) draft path treats the text above the forward marker as
the owner's trusted, un-fenced drafting instructions. Gmail plus-addressing is
public, so the alias in `To:` proves only intent, not authorship: an outsider
can address `owner+bot@` and have it land in the owner's inbox. `is_bot_request`
must therefore also require Gmail's SENT label, which only the owner's own send
produces, or that trust plus the mailbox-search tool is handed to whoever knows
the address.
"""

from backend.accounts import account
from backend.drafting import manual_draft


def _acct(emails=("owner@example.com",)):
    entry = {
        "id": "owner@example.com",
        "identity": {"first": "Olwen", "last": "Reed",
                     "first_aliases": [], "emails": list(emails)},
        "telegram": {},
        "plan_status": "active",
        "handle": "0" * 32,
    }
    return account._account_from_entry(entry)


ALIAS = "owner+bot@example.com"


def test_a_forward_the_owner_sent_is_a_bot_request():
    acct = _acct()
    email = {"to": ALIAS, "from": "Olwen Reed <owner@example.com>",
             "labelIds": ["SENT", "INBOX"]}
    assert manual_draft.is_bot_request(email, acct)


def test_an_outsider_to_the_public_alias_is_not_a_bot_request():
    """The bug: a stranger emailing owner+bot@ used to be trusted as the owner's
    own instructions. Without the SENT label it must fall through to the fenced
    auto-reply path."""
    acct = _acct()
    email = {"to": ALIAS, "from": "attacker@evil.com", "labelIds": ["INBOX"]}
    assert not manual_draft.is_bot_request(email, acct)


def test_a_forged_from_header_does_not_pass_without_the_sent_label():
    """A From header is attacker-settable; authorship is Gmail's SENT label,
    which an outsider's delivered mail never carries."""
    acct = _acct()
    email = {"to": ALIAS, "from": "Olwen Reed <owner@example.com>",
             "labelIds": ["INBOX"]}
    assert not manual_draft.is_bot_request(email, acct)


def test_a_send_as_alias_the_owner_uses_still_passes():
    """SENT is stamped whatever address the owner sent from, so a send-as alias
    that is not in the account's identity works without an address allow-list."""
    acct = _acct()
    email = {"to": ALIAS, "from": "owner-work@company.example",
             "labelIds": ["SENT", "INBOX"]}
    assert manual_draft.is_bot_request(email, acct)


def test_a_normal_inbound_email_is_not_a_bot_request():
    acct = _acct()
    email = {"to": "owner@example.com", "from": "friend@example.com",
             "labelIds": ["INBOX"]}
    assert not manual_draft.is_bot_request(email, acct)


def test_a_message_with_no_labels_is_not_a_bot_request():
    acct = _acct()
    assert not manual_draft.is_bot_request({"to": ALIAS, "from": "x@y.com"}, acct)
