"""The wire contract between the enclave and the co-signer.

Two processes on two boxes have to agree on paths, field names and how bytes
are spelled in JSON. Both sides read them from here: the co-signer's server and
the enclave's `backend/custody/client.py`. The import only ever points
enclave -> cosigner, so moving this service to its own host never drags
`backend/` with it.

The loopback port lives here rather than in `backend/site.py` for the same
reason -- the server that binds it is in this package. `backend/site.py`
imports it, so `deploy/render_caddyfile.py` still renders the proxy from one
value and cannot point at a port nothing listens on.

Everything binary crosses the wire as standard base64. There is exactly one
codec pair (`b64` / `unb64`) so a padding or urlsafe difference between the two
halves cannot turn into an unwrap failure that looks like a tampering alert.
"""

import base64

# 8788 is skipped: another product on the box has bound it for years, see
# backend/site.py. 8787/8789/8790 are Letterlock's other listeners.
PORT = 8791

WRAP_PATH = "/wrap"
UNWRAP_AND_SIGN_PATH = "/unwrap-and-sign"
# Releasing an account's data key without minting a DPoP proof. The documents an
# account owns are encrypted under the same key as its refresh token, and
# rendering the voice page needs the key but not the proof. Serving that from
# `/unwrap-and-sign` would mint a capability nobody asked for and write a row
# claiming a mail refresh that did not happen, so reading a user's own data is
# its own action, with its own ceiling and its own rows in the log.
UNWRAP_PATH = "/unwrap"
# Moving one record onto the current outer key version. Takes an `outer` and
# returns an `outer`: no proof, no plaintext on either box, and nothing
# introduced for an account that had no record.
REWRAP_PATH = "/rewrap"
# A proof with no token beside it. The authorization-code exchange needs one
# before any uid exists -- the mailbox is unknown until Google answers -- so
# `/unwrap-and-sign` cannot serve that call: there is nothing to unwrap yet.
# The DPoP-Nonce retry needs a second proof for the same reason, without paying
# for a second unwrap.
SIGN_DPOP_PATH = "/sign-dpop"
DPOP_JWK_PATH = "/dpop-jwk"
HEALTH_PATH = "/health"

# Caddy terminates TLS, so the enclave's client certificate reaches this
# service as a header. base64 DER rather than PEM: a PEM body carries newlines,
# which cannot survive an HTTP header, and DER is what the fingerprint and the
# quote extension are read out of anyway.
CLIENT_CERT_HEADER = "X-Client-Cert-Der"

# The only endpoint the co-signer will sign a DPoP proof for. Without this the
# service is a signing oracle for any URL an enclave-side attacker names, which
# would make "the co-signer signs no secrets" a claim about intent rather than
# about what the code can do.
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"  # nosec B105  # a URL

# A wrapped token is a couple of hundred bytes; a request carrying one is under
# a kilobyte. Reading an attacker-declared Content-Length unbounded is a free
# allocation.
MAX_BODY = 64 * 1024

# An opaque per-account handle the enclave minted, never an address and never
# anything this service can turn back into a person. The name is historical: it
# carried `account.id` until Track F, and it stays `uid` because the co-signer
# does not parse the value and a column rename buys nothing. What changed is
# what the enclave puts in it -- see backend.accounts.account.new_handle.
F_UID = "uid"
F_INNER = "inner"
F_OUTER = "outer"
F_HTM = "htm"
F_HTU = "htu"
F_NONCE = "nonce"
F_PROOF = "proof"
F_JWK = "jwk"
F_JKT = "jkt"
F_ERROR = "error"


def b64(raw):
    """Bytes as they travel in a JSON body."""
    assert isinstance(raw, (bytes, bytearray)), f"b64 expects bytes, got {type(raw).__name__}"
    return base64.b64encode(raw).decode()


def unb64(text):
    """Inverse of b64. Strict: a body that is not valid base64 is a malformed
    request, not something to salvage."""
    assert isinstance(text, str), f"unb64 expects str, got {type(text).__name__}"
    return base64.b64decode(text, validate=True)
