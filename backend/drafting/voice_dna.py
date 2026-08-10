"""The voice profile that applies to an account: where it lives and which applies.

The drafter reads one profile document per account, and `resolve()` decides which:
the account's own document, the operator's own file, or the neutral default. This
module is that resolution plus the load and save behind it, and it is the only
thing that writes a user's profile.

*How* a profile is made from an account's sent mail -- the Gmail sweep and the
synthesis completion -- lives in `backend.drafting.voice_generation`, kept apart
because generating a profile reads mail and runs inference, which the web tier
neither does nor should carry the code for: the web tier shows and saves a
profile through this module and hands generation to the mail role. Nothing here
imports that module; the dependency points the other way.

Where a generated profile lands matters. It goes to
`database/<id>/voice-dna.enc`, alongside that user's data key and state, and the
manifest's `voice_file` is repointed at it. Never into `config/`: deploy.sh
overwrites that directory from the operator's `~/.system_files` on every push, so
a profile written there would disappear on the next deploy.

A user's own profile is encrypted under that account's data key
(backend.custody.keyring), which is what the `.enc` says: it is a sample of how
that person writes, reconstructed from their sent mail, and it was plaintext on
disk until now. The operator's `config/` profile is the one document deliberately
left in the clear -- it is operator content rather than user content, and the
deploy overwrites it, so encrypting it would mean encrypting a file rsync
replaces with a plaintext copy on the next push. `load()` decides which of the
two it is holding by comparing against the account's own path.

`DEFAULT_CONSTRAINTS` is the starting Constraints section: the plain-text rules
a new profile begins with. It is part of the document, not something appended
behind the user's back at prompt time, so what the /voice box shows is exactly
what the drafter reads and every rule in it can be edited or deleted. The
em-dash ban is deliberately not among them: it is enforced by retrying and
rejecting drafts, so it belongs to the Settings switch that decides whether that
happens (`agentic_drafter.dashes_banned()`), not to prose the user could delete
while the rejections carried on. A generated profile is saved with this section
appended (`with_constraints`), which is why `voice_generation`'s prompt tells the
model not to write one of its own.
"""

import sys
from pathlib import Path

from backend import paths
from backend.accounts import account
from backend.custody import keyring

# Every place a voice profile can live, in one place. The neutral profile is for
# an account with none of its own and deliberately describes a plain
# correspondent rather than imitating anyone. The operator's personal profile is
# reachable only through their own manifest entry, which seed_owner points here.
# The default file holds drafting instructions and nothing else: it is what a new
# user sees in the /voice box and starts editing, so a note about the file itself
# would be both prompt text and something to explain away.
DEFAULT_PROFILE = Path(__file__).parent / "default_voice.md"
OWNER_PROFILE = paths.config_file("voice-dna-email.md")

PROFILE_NAME = "voice-dna.enc"

MAX_PROFILE_CHARS = 20000

# The output rules a profile starts with. They ship inside the document rather
# than around it: a user who wants a longer reply than the one it answers edits
# this section out and the drafter obeys. The dash ban is not here, because it is
# the one rule with teeth behind it (draft rejection); it lives in Settings, and
# agentic_drafter puts it into the prompt when that switch is on.
CONSTRAINTS_HEADING = "## Constraints"

DEFAULT_CONSTRAINTS = """## Constraints

- Never invent facts, commitments, dates, prices, or opinions the owner has not
  expressed. An honest "let me check and come back to you" beats a confident
  guess.
- No markdown, no bullet lists unless the incoming email used them, no subject
  line, no commentary about the draft itself.
- Keep it roughly as long as the email it answers. Shorter is usually better."""


class VoiceError(Exception):
    """A profile failure with a message meant for the user to read. Raised by the
    save path here and by generation in `voice_generation`, which imports it."""


def log(msg):
    sys.stderr.write(f"voice_dna {msg}\n")
    sys.stderr.flush()


def profile_path(acct):
    """Where this account's own profile lives, generated or hand-edited."""
    return keyring.path_for(acct, PROFILE_NAME)


def with_constraints(text):
    """A profile document that carries a Constraints section. Used where a
    document is first written, never on the way to the model: re-adding the
    section at read time would put back rules the user chose to delete."""
    body = (text or "").strip()
    if CONSTRAINTS_HEADING in body:
        return body
    return f"{body}\n\n{DEFAULT_CONSTRAINTS}"


def default_text():
    """The neutral profile, as the text a user starts editing from, constraints
    included: the box shows the whole document the drafter will read."""
    assert DEFAULT_PROFILE.exists(), f"default voice profile missing at {DEFAULT_PROFILE}"
    return with_constraints(DEFAULT_PROFILE.read_text())


def load(acct):
    """This account's own profile document, or None when it has none. Returns it
    verbatim: what is stored is what the drafter reads.

    Two kinds of pointer, and which one this is decides how it is read. A
    profile in the account's own directory is that user's writing and is
    encrypted under their data key. Anything else is the operator's file under
    `config/`, which the deploy owns and writes in the clear."""
    candidate = getattr(acct, "voice_file", None)
    if not candidate:
        return None
    path = Path(candidate)
    if path == profile_path(acct):
        text = keyring.read_encrypted(acct, PROFILE_NAME)
        if text is None:
            log(f"{acct.id} points at a missing profile {path}")
            return None
        return text.strip()
    if not path.exists():
        log(f"{acct.id} points at a missing profile {path}")
        return None
    return path.read_text().strip()


def resolve(acct):
    """The voice profile text as it reaches the model: the account's own document
    if it has one, else the neutral default. Nothing is added to it.

    Single source of the resolution order. The operator's personal profile is
    reachable only through their own manifest entry, never as an implicit
    fallback for other users."""
    return load(acct) or default_text()


def save(acct, text):
    """Write a profile for this account and point the manifest at it. Sole writer
    of the document, mirroring account.set_voice as the sole writer of the
    pointer. Returns the reloaded Account."""
    text = (text or "").strip()
    if not text:
        raise VoiceError("A voice profile cannot be empty.")
    if len(text) > MAX_PROFILE_CHARS:
        raise VoiceError(
            f"That profile is {len(text)} characters; the limit is {MAX_PROFILE_CHARS}."
        )
    path = keyring.write_encrypted(acct, PROFILE_NAME, text + "\n")
    log(f"saved profile for {acct.id} ({len(text)} chars)")
    return account.set_voice(acct.id, paths.relative_if_inside(path))


def clear(acct):
    """Drop this account's profile, putting it back on the default. Removes the
    generated document; a pointer at a file outside the account's own directory
    (the operator's config copy) is unlinked from but never deleted."""
    keyring.clear_encrypted(acct, PROFILE_NAME)
    return account.set_voice(acct.id, clear=True)
