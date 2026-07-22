"""Falsifiable masking recall over a public labeled corpus.

Every record in corpus.jsonl carries raw email text plus the exact PII literals
that must NOT survive masking. We run the real `pseudonymizer.pseudonymize`
pass (same code that guards the LLM boundary) and count, per entity type, how
many labeled values are actually gone from the masked output. Recall is that
caught fraction. Open code + open corpus so a skeptic reproduces the number.

A single synthetic identity (EVAL_IDENTITY) plays the account owner, so the
OWNER_* and CONTACT labels exercise the deterministic literal-scrub path while
the rest exercise Presidio NER/regex.
"""

import json
import re
from collections import defaultdict
from pathlib import Path

from backend.masking import pseudonymizer

CORPUS_PATH = Path(__file__).parent / "corpus.jsonl"

EVAL_IDENTITY = pseudonymizer.UserIdentity(
    first="Jordan",
    last="Avery",
    first_aliases=["Jordy"],
    emails=["jordan.avery@example.com"],
    phones=["+1 (617) 555-0148"],
    contacts=["Priya Sharma", "Wei Chen", "Bob"],
)

# Types the deterministic literal-scrub owns: it must catch these regardless of
# NER, so their recall is expected to be 1.0 and is enforced by the pytest gate.
DETERMINISTIC_TYPES = frozenset(
    {"OWNER_NAME", "OWNER_EMAIL", "OWNER_PHONE", "CONTACT", "API_KEY", "JWT"}
)


def load_corpus(path=CORPUS_PATH):
    records = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    assert records, "corpus is empty"
    return records


def _leaked(value, masked):
    """A value leaks if it still appears in the masked text, bounded so short
    names don't false-match inside longer words. Case-insensitive: a leak in any
    casing is still a leak."""
    return re.search(r"(?<!\w)" + re.escape(value) + r"(?!\w)", masked, re.IGNORECASE) is not None


def evaluate(records=None, identity=EVAL_IDENTITY):
    records = records if records is not None else load_corpus()
    by_type = defaultdict(lambda: {"caught": 0, "total": 0})
    by_tag = defaultdict(lambda: {"caught": 0, "total": 0})
    misses = []
    for rec in records:
        state = pseudonymizer.new_state(identity)
        masked = pseudonymizer.pseudonymize(rec["text"], state)
        for item in rec["pii"]:
            caught = not _leaked(item["value"], masked)
            for bucket in (by_type[item["type"]], by_tag[rec["tag"]]):
                bucket["total"] += 1
                bucket["caught"] += int(caught)
            if not caught:
                misses.append((rec["id"], rec["tag"], item["type"], item["value"]))
    return {"by_type": dict(by_type), "by_tag": dict(by_tag), "misses": misses,
            "n_records": len(records)}


def recall(bucket):
    return bucket["caught"] / bucket["total"] if bucket["total"] else 1.0
