"""The co-signer: the second half of split custody for Gmail refresh tokens.

The enclave seals a refresh token under a key derived from the dstack KMS
(`inner`), the co-signer wraps that ciphertext under a key of its own
(`outer`), and the enclave stores the result. Neither box can read a mailbox
alone: the co-signer holds a wrapping key with nothing to unwrap, the enclave
holds ciphertext it cannot strip a layer off.

Four invariants carry the whole property. A refactor that quietly breaks any
one of them leaves code that still passes its happy-path tests and protects
nothing (docs/plan_token_custody.md §1):

1. Layer order. The co-signer's wrap is the OUTER one. Reverse it and
   unwrapping here yields a refresh token, making this the single box that can
   read every mailbox.
2. The co-signer never receives plaintext. Not for validation, not for
   logging, not for a health check.
3. No bypass. Fail closed. A cached key on the enclave side, or a "co-signer
   unreachable, proceed anyway" path, collapses this to the status quo.
4. The co-signer persists no ciphertext. The audit log stores decisions and
   identifiers, never `inner`, `outer`, or a proof.

What the four do not add up to: they stop either box alone from reading a
mailbox, and they stop this box from reading one at all. They do not stop an
attacker who owns the enclave, because the enclave is the party legitimately
allowed to ask, and it must be able to. Against that the guarantee is weaker
and worth naming exactly: a breach reads accounts one at a time, no faster than
`policy.py` permits, with every account it touched named in `audit.py`. Bounded
exfiltration with evidence, not prevention. Nothing here should be described as
more than that.

This package imports nothing from `backend/` except the one Telegram seam in
`alerts.py`, so it can be lifted onto its own box under its own operator. The
dependency runs the other way: `backend/custody/client.py` imports
`cosigner.protocol` for the wire contract, and `backend/site.py` imports its
loopback port.

`runtime_guard` is the one other exception, and it is deliberately not under
`backend/`: invariants 1 and 4 are enforced here by asserts, and a co-signer
started with `-O` would wrap under an unchecked key and answer with an unpinned
JWK. It must refuse on its own rather than inherit the application's guard.
"""

from runtime_guard import require_asserts

require_asserts()
