#!/usr/bin/env bash
# Reproducible-build + publish driver for Track E (reproducible builds).
#
# Builds the four measured OCI images (one per enclave role: mail, web, hook,
# egress)
# from pinned source via Nix, optionally verifies each is bit-for-bit
# reproducible, and optionally pushes each to a container registry and pins its
# docker-compose.yml service to the pushed digest. Each role is pushed to
# "${REGISTRY}-${role}".
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
# Four images now, one per enclave role, each carrying only its reachable code.
# The registry destination for a role is "${REGISTRY}-${role}", matching the
# local image name tee-email-bot-${role} the flake produces.
ROLES=(mail web hook egress)
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
  echo "--push requires REGISTRY=<repo> base (e.g. ghcr.io/you/tee-email-bot); each role pushes to <repo>-<role>" >&2
  exit 2
fi

build_role() {
  nix build ".#image-$1" --no-link --print-out-paths 2>/dev/null | tail -1
}

# Pin one service's `image:` line, keyed on the `command: ["$role"]` line right
# below it so a re-pin matches whatever the current value is (a bare tag the
# first time, a digest after). The compose image line is the single source of
# truth for what the CVM runs, so it must carry a literal digest, never a tag or
# a variable an operator could swap.
#
# The role and the ref reach perl through the environment rather than through
# the -e text. Substituting them into the program was the obvious way to write
# this and it silently dropped the digest: a registry ref contains `@sha256`,
# perl read that as an array in the interpolated replacement, and every push
# pinned `repo:<64 hex>` -- a tag, and exactly the thing the pin exists to
# forbid. \Q..\E for the same class of reason on the pattern side.
pin_compose() {
  local role="$1" ref="$2"
  ROLE="$role" REF="$ref" perl -0pi -e '
    my ($role, $ref) = ($ENV{ROLE}, $ENV{REF});
    s{image: \S+\n(\s*)command: \["\Q$role\E"\]}{image: $ref\n$1command: ["$role"]}
  ' "$COMPOSE_FILE"
}

declare -A OUTS SHAS REFS
for role in "${ROLES[@]}"; do
  echo "building $role image via nix..."
  OUTS[$role]="$(build_role "$role")"
  SHAS[$role]="$(sha256sum "${OUTS[$role]}" | awk '{print $1}')"
  echo "  $role tarball: ${OUTS[$role]}"
  echo "  $role sha256:  ${SHAS[$role]}"
  REFS[$role]="<not pushed>"
done

if [[ "$VERIFY" == 1 ]]; then
  for role in "${ROLES[@]}"; do
    echo "verifying $role reproducibility (second build)..."
    OUT2="$(build_role "$role")"
    SHA2="$(sha256sum "$OUT2" | awk '{print $1}')"
    if [[ "${SHAS[$role]}" != "$SHA2" ]]; then
      echo "NON-REPRODUCIBLE ($role): ${SHAS[$role]} != $SHA2" >&2
      exit 1
    fi
  done
  echo "reproducible: identical hash across two builds, all roles."
fi

if [[ "$LOAD" == 1 || "$PUSH" == 1 ]]; then
  for role in "${ROLES[@]}"; do
    echo "loading $role tarball into docker..."
    docker load < "${OUTS[$role]}"
  done
fi

if [[ "$PUSH" == 1 ]]; then
  for role in "${ROLES[@]}"; do
    LOCAL="tee-email-bot-$role:latest"
    DEST="$REGISTRY-$role:$TAG"
    echo "tagging $LOCAL -> $DEST"
    docker tag "$LOCAL" "$DEST"
    echo "pushing $DEST ..."
    docker push "$DEST"
    # RepoDigests is populated after a successful push; take the one for our repo.
    DIGEST="$(docker inspect "$DEST" \
      --format '{{range .RepoDigests}}{{println .}}{{end}}' \
      | grep "^$REGISTRY-$role@" | head -1 | cut -d@ -f2)"
    if [[ -z "$DIGEST" ]]; then
      echo "could not resolve registry digest after pushing $role" >&2
      exit 1
    fi
    REFS[$role]="$REGISTRY-$role@$DIGEST"
    echo "  $role registry digest: $DIGEST"
    echo "  pinning $role compose image to ${REFS[$role]}"
    pin_compose "$role" "${REFS[$role]}"
  done
  echo "updated $COMPOSE_FILE"
fi

{
  echo "# Published hashes for Track E reproducible builds, one line per role."
  echo "#"
  echo "# tarball-sha256: hash of the Nix build output; proves the build is"
  echo "#   source-reproducible (rebuild from this repo -> identical value)."
  echo "#   Regenerate/verify with: deploy/phala/build_and_publish.sh --verify"
  echo "# registry-ref:   what the Phala CVM pulls; pinned into docker-compose.yml."
  echo "#   Populated by --push. <not pushed> until first push."
  for role in "${ROLES[@]}"; do
    echo "$role nix-store-path: ${OUTS[$role]}"
    echo "$role tarball-sha256: ${SHAS[$role]}"
    echo "$role registry-ref:   ${REFS[$role]}"
  done
} > "$HASH_FILE"
echo "wrote $HASH_FILE"
