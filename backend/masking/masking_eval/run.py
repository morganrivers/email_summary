"""Print masking recall over the public corpus.

    python -m backend.masking.masking_eval.run

Reports per-entity-type and per-adversarial-category recall plus every miss, so
the number is reproducible and falsifiable by anyone with the repo. Exit code is
non-zero with --strict if any deterministic-scrub type drops below 100%.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from backend.masking.masking_eval import evaluator


def main(argv):
    strict = "--strict" in argv
    result = evaluator.evaluate()

    print(f"masking recall over {result['n_records']} corpus records")

    print("\nby entity type")
    print(f"  {'entity':<16}{'recall':>9}{'caught/total':>16}")
    for name in sorted(result["by_type"]):
        b = result["by_type"][name]
        det = " *" if name in evaluator.DETERMINISTIC_TYPES else ""
        print(f"  {name:<16}{evaluator.recall(b):>9.2%}{b['caught']:>12}/{b['total']}{det}")
    print("  (* = deterministic literal-scrub type, expected 100%)")

    print("\nby adversarial category")
    print(f"  {'category':<16}{'recall':>9}{'caught/total':>16}")
    for name in sorted(result["by_tag"]):
        b = result["by_tag"][name]
        print(f"  {name:<16}{evaluator.recall(b):>9.2%}{b['caught']:>12}/{b['total']}")

    total_caught = sum(b["caught"] for b in result["by_type"].values())
    total = sum(b["total"] for b in result["by_type"].values())
    print(f"\noverall recall: {total_caught / total:.2%} ({total_caught}/{total})")

    if result["misses"]:
        print("\nmisses (id / category / type / value):")
        for rid, tag, etype, value in result["misses"]:
            print(f"  {rid:<18}{tag:<16}{etype:<14}{value!r}")

    if strict:
        broken = [
            name for name, b in result["by_type"].items()
            if name in evaluator.DETERMINISTIC_TYPES and evaluator.recall(b) < 1.0
        ]
        if broken:
            print(f"\nFAIL: deterministic types below 100%: {broken}")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
