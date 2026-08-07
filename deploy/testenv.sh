#!/usr/bin/env bash
# The environment CI runs the suite in, in one file so the four workflows cannot
# disagree about what "installed" means.
#
#   deploy/testenv.sh locked    what the image ships: deploy/phala/uv.lock,
#                               the full closure, exported without resolving
#   deploy/testenv.sh latest    the direct dependencies unpinned, resolved
#                               today; the weekly compatibility question
#
# Both add requirements-dev.txt, which is where pytest, pip-audit and uv are
# pinned. Installing it first is deliberate: it is what puts `uv` on PATH for
# the export below, so no third-party action is needed to get one and the uv
# that reads the lock is the uv version this repo pinned.
#
# Presidio and spaCy are absent here as they are absent on the box, so the three
# analyzer-path tests in tests/test_masking_recall.py skip. That is the same
# default the box and the enclave image run under.
set -euo pipefail

MODE="${1:?usage: testenv.sh locked|latest}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements-dev.txt

WANTED="$(mktemp)"
trap 'rm -f "$WANTED"' EXIT

case "$MODE" in
    locked)
        # --frozen reads the committed lock and resolves nothing, so a failure
        # here is a stale lock rather than a version that moved under us.
        uv export --directory deploy/phala \
            --frozen --no-hashes --no-emit-project > "$WANTED"
        python -m pip install --quiet -r "$WANTED"
        ;;
    latest)
        python -m deploy.requirements --names > "$WANTED"
        python -m pip install --quiet --upgrade -r "$WANTED"
        ;;
    *)
        echo "testenv.sh: unknown mode '$MODE'; expected locked or latest" >&2
        exit 2
        ;;
esac

python -m pip list
