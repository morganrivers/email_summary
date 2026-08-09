"""Gate on the public masking-recall corpus.

Deterministic literal-scrub types must stay at 100% (a drop is a real leak of
the owner or a known contact). NER/regex types get loose regression floors set
below the honest measured recall, so a big regression breaks the build without
the suite going flaky on inherently-missed adversarial cases (spelled-out PII).
"""

import pytest

from backend.masking import pseudonymizer
from backend.masking.masking_eval import evaluator

ANALYZER = pseudonymizer.analyzer_available()

# Loose floors for non-deterministic types: below current measured recall,
# present only to catch a large regression. Not a claim of guaranteed recall.
LOOSE_FLOORS = {
    "EMAIL": 0.80,
    "PHONE": 0.70,
    "PERSON": 0.80,
    "CREDIT_CARD": 0.90,
    "IBAN": 0.90,
}


@pytest.fixture(scope="module")
def result():
    return evaluator.evaluate()


@pytest.fixture(scope="module")
def result_no_analyzer():
    base = evaluator.EVAL_IDENTITY
    identity = pseudonymizer.UserIdentity(
        base.first, base.last, base.first_aliases, base.emails, [],
        base.contacts, base.account_id, analyzer=False,
    )
    return evaluator.evaluate(identity=identity)


def test_deterministic_types_hold_without_analyzer(result_no_analyzer):
    """The floor a small box still stands on. Everything the deterministic
    scrub and the secret regexes own must stay at 100% with NER switched off;
    only PERSON is allowed to fall, and it falls to zero."""
    for name in evaluator.DETERMINISTIC_TYPES:
        bucket = result_no_analyzer["by_type"].get(name)
        if bucket:
            assert evaluator.recall(bucket) == 1.0, (name, result_no_analyzer["misses"])
    for name in ("API_KEY", "JWT"):
        bucket = result_no_analyzer["by_type"].get(name)
        if bucket:
            assert evaluator.recall(bucket) == 1.0, (name, result_no_analyzer["misses"])


requires_analyzer = pytest.mark.skipif(
    not ANALYZER,
    reason="Presidio/spaCy not installed on this box; analyzer-path floors do not apply",
)


@requires_analyzer
def test_deterministic_types_fully_masked(result):
    for name, bucket in result["by_type"].items():
        if name in evaluator.DETERMINISTIC_TYPES:
            assert evaluator.recall(bucket) == 1.0, (name, result["misses"])


@requires_analyzer
def test_loose_floors_hold(result):
    for name, floor in LOOSE_FLOORS.items():
        bucket = result["by_type"].get(name)
        if bucket:
            assert evaluator.recall(bucket) >= floor, (name, evaluator.recall(bucket))


@requires_analyzer
def test_overall_recall_floor(result):
    total = sum(b["total"] for b in result["by_type"].values())
    caught = sum(b["caught"] for b in result["by_type"].values())
    assert caught / total >= 0.90, caught / total


def test_overall_recall_floor_without_analyzer(result_no_analyzer):
    """The floor on the path that actually ships. requirements.txt leaves the
    analyzer commented out, so this is the number a default box runs at; 0.90
    is unreachable there and asserting it against `result` is what made a clean
    checkout fail. Measured 0.74, the whole gap being PERSON."""
    total = sum(b["total"] for b in result_no_analyzer["by_type"].values())
    caught = sum(b["caught"] for b in result_no_analyzer["by_type"].values())
    assert caught / total >= 0.70, caught / total
