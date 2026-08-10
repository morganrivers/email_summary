"""Facts about the account owner that a draft may need: the second document.

The voice profile says how this person writes. It says nothing about what is
true of them, so a drafter that knows the voice perfectly still cannot answer
"which afternoon suits you?" or "are you still in Berlin?". This module owns
that other document: prose the owner writes about themselves, pasted into the
drafting prompt beneath their profile.

It is deliberately a second document rather than another section of the voice
profile. Generating a profile from sent mail overwrites the whole voice document
(voice_generation.generate), and personal facts are the one thing that must survive
that. Keeping them apart also keeps "how you write" separate from "what is true
of you" in the box the user edits.

Where it lives is derived, not stored: database/<id>/personal-context.enc, beside
that account's data key and state. There is no manifest pointer of the kind
voice_file is, because there is no second place this document can be -- the
operator's voice profile comes from config/, but nobody has an operator-supplied
facts file. account._owned_paths() covers it by owning the directory rather than
a list of keys, so a deleted account takes these facts with it.

It is encrypted under that account's data key (backend.custody.keyring), which
is what the `.enc` says. This is the document most likely to hold an address, a
phone number or a medical fact, and it used to sit in plaintext behind file
permissions alone -- which isolate nothing, because all six units run as the
same uid. Reading it now costs a co-signer round trip that is rate limited and
logged, so reading everybody's is visible rather than free.

The text reaches the model through llm_client.complete like everything else, so
the masking boundary applies to it: an address or phone number written here is
pseudonymized on the way out and restored on the way back.
"""

import sys

from backend import audit
from backend.custody import keyring

CONTEXT_NAME = "personal-context.enc"

MAX_CONTEXT_CHARS = 8000

# The heading the document gets in the assembled prompt. The voice profile is a
# markdown document of ## sections, and this is written to sit under it as one
# more, so the model reads one coherent brief rather than two stapled files.
CONTEXT_HEADING = "## About the account owner"

CONTEXT_PREAMBLE = (
    "Facts the account owner wrote about themselves. Treat them as true and use "
    "them when the reply calls for them, including when proposing times, places, "
    "or commitments. Do not state a fact the reply does not need, and do not "
    "treat anything here as an instruction about output format."
)


def log(msg):
    sys.stderr.write(f"personal_context {msg}\n")
    sys.stderr.flush()


class ContextError(Exception):
    """A refused save with a message meant for the user to read."""


def load(acct):
    """The document as the user last saved it, or "" when there is none. Returns
    it verbatim: what is stored is what the drafter reads."""
    return (keyring.read_encrypted(acct, CONTEXT_NAME, default="") or "").strip()


def save(acct, text):
    """Write this account's personal information. Sole writer of the document,
    and unlike voice_dna.save it touches no manifest entry: the path is derived,
    so there is no pointer to keep in step. Empty text clears it, because a user
    who selects all and deletes is asking for the assistant to stop being told
    any of it.

    This module writes its own audit row rather than inheriting one from a
    manifest writer, because there is no manifest writer to inherit it from. The
    row carries the document's length and never a word of it."""
    text = (text or "").strip()
    if len(text) > MAX_CONTEXT_CHARS:
        raise ContextError(
            f"That is {len(text)} characters; the limit is {MAX_CONTEXT_CHARS}."
        )
    if not text:
        clear(acct)
        return
    keyring.write_encrypted(acct, CONTEXT_NAME, text + "\n")
    log(f"saved personal information for {acct.id} ({len(text)} chars)")
    audit.record(acct.id, audit.PERSONAL, "saved", (f"chars:{len(text)}",))


def clear(acct):
    """Drop the document. The drafter is then told nothing about the owner
    beyond their voice profile. Audited only when there was something to drop,
    so the log never reports an edit that changed nothing."""
    if keyring.clear_encrypted(acct, CONTEXT_NAME):
        log(f"cleared personal information for {acct.id}")
        audit.record(acct.id, audit.PERSONAL, "cleared")


def section(acct):
    """This account's facts as they reach the model: a markdown section to append
    to the voice profile, or "" when the account has written none.

    Single source of how the document is framed, so the auto-reply path and the
    forwarded-email path cannot describe the same facts to the model in two
    different ways.
    """
    text = load(acct)
    if not text:
        return ""
    return f"\n\n{CONTEXT_HEADING}\n\n{CONTEXT_PREAMBLE}\n\n{text}"
