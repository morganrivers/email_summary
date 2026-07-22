#!/usr/bin/env bash
# Reproducible-build + publish driver for Track E (reproducible builds).
#
# Builds the measured OCI image from pinned source via Nix, optionally verifies
# it is bit-for-bit reproducible, and optionally pushes it to a container
# registry and pins docker-compose.yml to the pushed digest.
#
# Three distinct hashes are involved; keep them straight:
#   1. tarball sha256   - hash of the Nix build output. Proves the *build* is
#                         reproducible (anyone rebuilds from source, same value).
#   2. registry digest  - what the Phala CVM actually `docker pull`s. The
#                         registry re-packs layers, so this differs from (1).
#                         This is the value docker-compose.yml must pin.
#   3. dstack measurement - the TDX quote / compose-hash the KMS gates secret
#                         release on. Derived from the compose + running image;
#                         wiring (2)->(3) for auditors is Track F3/G, not here.
#
# Usage:
#   deploy/phala/build_and_publish.sh                 # build + record tarball hash
#   deploy/phala/build_and_publish.sh --verify        # build twice, assert identical
#   deploy/phala/build_and_publish.sh --load          # also `docker load` the image
#   REGISTRY=ghcr.io/you/tee-email-bot \
#     deploy/phala/build_and_publish.sh --push        # load, tag, push, pin compose
#
# --push requires REGISTRY (no default; must be a repo you can push to) and a
# prior `docker login`. TAG defaults to "latest".
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HASH_FILE="$REPO_ROOT/deploy/phala/IMAGE_HASH.txt"
COMPOSE_FILE="$REPO_ROOT/deploy/phala/docker-compose.yml"
LOCAL_IMAGE="tee-email-bot:latest"
TAG="${TAG:-latest}"

cd "$REPO_ROOT"

VERIFY=0
LOAD=0
PUSH=0
for arg in "$@"; do
  case "$arg" in
    --verify) VERIFY=1 ;;
    --load) LOAD=1 ;;
    --push) PUSH=1 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

if [[ "$PUSH" == 1 && -z "${REGISTRY:-}" ]]; then
  echo "--push requires REGISTRY=<repo> (e.g. ghcr.io/you/tee-email-bot)" >&2
  exit 2
fi

build() {
  nix build .#image --no-link --print-out-paths 2>/dev/null | tail -1
}

echo "building measured image via nix..."
OUT="$(build)"
IMG_SHA="$(sha256sum "$OUT" | awk '{print $1}')"
echo "image tarball: $OUT"
echo "tarball sha256: $IMG_SHA"

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

REGISTRY_REF=""
if [[ "$LOAD" == 1 || "$PUSH" == 1 ]]; then
  echo "loading tarball into docker..."
  docker load < "$OUT"
fi

if [[ "$PUSH" == 1 ]]; then
  DEST="$REGISTRY:$TAG"
  echo "tagging $LOCAL_IMAGE -> $DEST"
  docker tag "$LOCAL_IMAGE" "$DEST"
  echo "pushing $DEST ..."
  docker push "$DEST"
  # RepoDigests is populated after a successful push; take the one for our repo.
  DIGEST="$(docker inspect "$DEST" \
    --format '{{range .RepoDigests}}{{println .}}{{end}}' \
    | grep "^$REGISTRY@" | head -1 | cut -d@ -f2)"
  if [[ -z "$DIGEST" ]]; then
    echo "could not resolve registry digest after push" >&2
    exit 1
  fi
  REGISTRY_REF="$REGISTRY@$DIGEST"
  echo "registry digest: $DIGEST"
  echo "pinning compose image to $REGISTRY_REF"
  # Replace the first `image:` line under the service. `#` delimiter avoids the
  # slashes in the registry ref. The compose image line is the single source of
  # truth for what the CVM runs, so it must carry a literal digest (not a tag or
  # a variable an operator could swap).
  sed -i "0,/^\( *\)image: .*/s##\1image: $REGISTRY_REF#" "$COMPOSE_FILE"
  echo "updated $COMPOSE_FILE"
fi

{
  echo "# Published hashes for Track E reproducible builds."
  echo "#"
  echo "# tarball-sha256: hash of the Nix build output; proves the build is"
  echo "#   source-reproducible (rebuild from this repo -> identical value)."
  echo "#   Regenerate/verify with: deploy/phala/build_and_publish.sh --verify"
  echo "# registry-ref:   what the Phala CVM pulls; pinned into docker-compose.yml."
  echo "#   Populated by --push. Empty until first push."
  echo "nix-store-path: $OUT"
  echo "tarball-sha256: $IMG_SHA"
  echo "registry-ref:   ${REGISTRY_REF:-<not pushed>}"
} > "$HASH_FILE"
echo "wrote $HASH_FILE"
