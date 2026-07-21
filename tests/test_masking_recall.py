"""Gate on the public masking-recall corpus.

Deterministic literal-scrub types must stay at 100% (a drop is a real leak of
the owner or a known contact). NER/regex types get loose regression floors set
below the honest measured recall, so a big regression breaks the build without
the suite going flaky on inherently-missed adversarial cases (spelled-out PII).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from masking_eval import evaluator

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


def test_deterministic_types_fully_masked(result):
    for name, bucket in result["by_type"].items():
        if name in evaluator.DETERMINISTIC_TYPES:
            assert evaluator.recall(bucket) == 1.0, (name, result["misses"])


def test_loose_floors_hold(result):
    for name, floor in LOOSE_FLOORS.items():
        bucket = result["by_type"].get(name)
        if bucket:
            assert evaluator.recall(bucket) >= floor, (name, evaluator.recall(bucket))


def test_overall_recall_floor(result):
    total = sum(b["total"] for b in result["by_type"].values())
    caught = sum(b["caught"] for b in result["by_type"].values())
    assert caught / total >= 0.90, caught / total
