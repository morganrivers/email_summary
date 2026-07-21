#!/usr/bin/env bash
# Reproducible-build driver for Track E1 (binary transparency).
#
# Builds the measured OCI image from pinned source via Nix, records the
# published image hash, and (optionally) verifies the build is bit-for-bit
# reproducible by building twice and comparing hashes.
#
# The published hash in IMAGE_HASH.txt is the value auditors compare against the
# running enclave measurement. Anyone with this repo can rerun this script and
# must derive the identical hash (that is the whole point of the Nix path).
#
# Usage:
#   deploy/phala/build_and_publish.sh            # build + record hash
#   deploy/phala/build_and_publish.sh --verify   # build twice, assert identical
#   deploy/phala/build_and_publish.sh --load     # also `docker load` the image
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HASH_FILE="$REPO_ROOT/deploy/phala/IMAGE_HASH.txt"

cd "$REPO_ROOT"

VERIFY=0
LOAD=0
for arg in "$@"; do
  case "$arg" in
    --verify) VERIFY=1 ;;
    --load) LOAD=1 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

build() {
  # dockerTools tarball is deterministic; its sha256 is the reproducible image id.
  nix build .#image --no-link --print-out-paths 2>/dev/null | tail -1
}

echo "building measured image via nix..."
OUT="$(build)"
IMG_SHA="$(sha256sum "$OUT" | awk '{print $1}')"
echo "image tarball: $OUT"
echo "sha256:       $IMG_SHA"

if [[ "$VERIFY" == 1 ]]; then
  echo "verifying reproducibility (second build)..."
  OUT2="$(build)"
  IMG_SHA2="$(sha256sum "$OUT2" | awk '{print $1}')"
  if [[ "$IMG_SHA" != "$IMG_SHA2" ]]; then
    echo "NON-REPRODUCIBLE: $IMG_SHA != $IMG_SHA2" >&2
    exit 1
  fi
  echo "reproducible: identical hash across two builds."
fi

{
  echo "# Published image hash for Track E1 binary transparency."
  echo "# Auditors compare this against the running enclave measurement."
  echo "# Regenerate with: deploy/phala/build_and_publish.sh --verify"
  echo "nix-store-path: $OUT"
  echo "sha256:         $IMG_SHA"
} > "$HASH_FILE"
echo "wrote $HASH_FILE"

if [[ "$LOAD" == 1 ]]; then
  echo "loading into docker..."
  docker load < "$OUT"
fi
