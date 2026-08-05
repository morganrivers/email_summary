"""The co-signer's HTTP surface: three RPCs and a health check.

    POST /wrap             {uid, inner}                   -> {outer}
    POST /unwrap-and-sign  {uid, outer, htm, htu, nonce?}  -> {inner, proof}
    POST /sign-dpop        {htm, htu, nonce?, uid?}        -> {proof}
    GET  /dpop-jwk                                         -> {jwk, jkt}
    GET  /health

`/unwrap-and-sign` is one call rather than an unwrap followed by a sign
because the proof and the token have to be combined anyway: one round trip is
fewer, and it makes the rate limit count refreshes instead of half-refreshes.

`/sign-dpop` exists because that pairing cannot cover every proof. At the
authorization-code exchange there is no uid yet -- which mailbox consented is
unknown until Google answers -- so there is nothing to unwrap and nobody to
charge. The DPoP-Nonce retry needs a second proof over the same request. Its
uid is optional and advisory: it lands in the audit row when the caller knows
one, and the ceiling in `policy.sign_limit()` is what actually bounds the
endpoint.

Caddy terminates TLS and requires a client certificate, then passes it here as
base64 DER in a header (`protocol.CLIENT_CERT_HEADER`). This service binds
loopback only, so the header is not attacker-supplied unless the proxy is
bypassed -- and a request that arrives without one is refused under
`required`, which is exactly what a bypass would look like.

Nothing here logs a body. `inner`, `outer` and the proof cross this module and
are never written down: not to stderr, not to the audit log. See the
invariants in `cosigner/__init__.py`.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cosigner import attest
from cosigner import audit
from cosigner import keys
from cosigner import policy
from cosigner import protocol

HOST = os.environ.get("COSIGNER_BIND", "127.0.0.1")
PORT = int(os.environ.get("COSIGNER_PORT", str(protocol.PORT)))

STATUS_FOR_KIND = {
    policy.KIND_DISABLED: 503,
    policy.KIND_ATTESTATION: 403,
    policy.KIND_REQUEST: 403,
    policy.KIND_RATE: 429,
}


def log(msg):
    sys.stderr.write(f"cosigner {msg}\n")
    sys.stderr.flush()


class RequestError(Exception):
    """A malformed request: answered with a status, never with a policy row.
    A body that does not parse is not a decision about a user."""

    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code
        self.msg = msg


def client_cert(headers):
    raw = headers.get(protocol.CLIENT_CERT_HEADER, "").strip()
    if not raw:
        return b""
    try:
        return protocol.unb64(raw)
    except Exception:
        raise RequestError(400, "client certificate header is not base64 DER")


def field(body, name, required=True):
    value = body.get(name)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value:
        raise RequestError(400, f"missing or non-string field {name!r}")
    return value


def binary_field(body, name):
    try:
        return protocol.unb64(field(body, name))
    except RequestError:
        raise
    except Exception:
        raise RequestError(400, f"field {name!r} is not base64")


def proof_request(body):
    """The three fields every proof is cut from, checked once for both
    endpoints that sign one."""
    htm = field(body, protocol.F_HTM)
    htu = field(body, protocol.F_HTU)
    nonce = field(body, protocol.F_NONCE, required=False)
    return htm, htu, nonce


def wrap_request(body, verdict):
    uid = field(body, protocol.F_UID)
    inner = binary_field(body, protocol.F_INNER)
    precheck = None
    if not inner:
        precheck = "empty inner"
    elif audit.ever_granted(uid, policy.ACTION_WRAP):
        # A second wrap for a user who already has one is either a bug or an
        # attacker asking us to re-wrap something. Refusing keeps the enclave's
        # stored `outer` the only one that exists.
        precheck = "already wrapped for this uid"
    refusal = policy.authorize(uid, policy.ACTION_WRAP, verdict, precheck)
    if refusal is not None:
        return refusal, None
    return None, {protocol.F_OUTER: protocol.b64(keys.wrap(uid, inner))}


def sign_request(body, verdict):
    """A proof and nothing else. No `outer` crosses this path, so the endpoint
    cannot be turned into an unwrap that skips the per-user limit; what it can
    be turned into is a proof for a refresh token the caller already holds,
    which is what the ceiling is for."""
    htm, htu, nonce = proof_request(body)
    uid = field(body, protocol.F_UID, required=False) or ""
    refusal = policy.authorize(uid, policy.ACTION_SIGN, verdict,
                               policy.allowed_target(htm, htu))
    if refusal is not None:
        return refusal, None
    return None, {protocol.F_PROOF: keys.dpop_proof(htm, htu, nonce)}


def unwrap_request(body, verdict):
    uid = field(body, protocol.F_UID)
    outer = binary_field(body, protocol.F_OUTER)
    htm, htu, nonce = proof_request(body)
    precheck = policy.allowed_target(htm, htu) or (None if outer else "empty outer")
    refusal = policy.authorize(uid, policy.ACTION_UNWRAP, verdict, precheck)
    if refusal is not None:
        return refusal, None
    try:
        inner = keys.unwrap(uid, outer)
    except Exception as err:
        # Deliberately says nothing about the ciphertext. A tag failure means
        # the record was tampered with, was wrapped under a different master
        # key, or belongs to another uid; none of those want detail on the wire.
        log(f"unwrap failed for uid={uid}: {type(err).__name__}")
        raise RequestError(400, "outer record did not open")
    return None, {
        protocol.F_INNER: protocol.b64(inner),
        protocol.F_PROOF: keys.dpop_proof(htm, htu, nonce),
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            raise RequestError(400, "bad Content-Length")
        if length <= 0 or length > protocol.MAX_BODY:
            raise RequestError(413, f"body length {length} out of range")
        try:
            return json.loads(self.rfile.read(length))
        except Exception:
            raise RequestError(400, "body is not JSON")

    def do_POST(self):
        try:
            handler = {
                protocol.WRAP_PATH: wrap_request,
                protocol.UNWRAP_AND_SIGN_PATH: unwrap_request,
                protocol.SIGN_DPOP_PATH: sign_request,
            }.get(self.path)
            if handler is None:
                raise RequestError(404, "no such endpoint")
            verdict = attest.verify_client(client_cert(self.headers))
            refusal, payload = handler(self._read_body(), verdict)
        except RequestError as err:
            log(f"{self.path} rejected: {err.msg}")
            return self._send(err.code, {protocol.F_ERROR: err.msg})
        except keys.NotConfigured as err:
            log(f"{self.path} unserviceable: {err}")
            return self._send(503, {protocol.F_ERROR: str(err)})
        except Exception as err:
            log(f"{self.path} failed: {type(err).__name__}: {err}")
            return self._send(500, {protocol.F_ERROR: "internal error"})
        if refusal is not None:
            log(f"{self.path} refused ({refusal.kind}): {refusal.reason}")
            return self._send(STATUS_FOR_KIND[refusal.kind], {protocol.F_ERROR: refusal.reason})
        self._send(200, payload)

    def do_GET(self):
        if self.path == protocol.HEALTH_PATH:
            return self._send(200, {
                "status": "ok",
                "attestation": attest.mode(),
                "keys": keys.configured() or "ok",
                "disabled": policy.disabled_reason(),
            })
        if self.path == protocol.DPOP_JWK_PATH:
            try:
                return self._send(200, {
                    protocol.F_JWK: keys.dpop_public_jwk(),
                    protocol.F_JKT: keys.dpop_jkt(),
                })
            except keys.NotConfigured as err:
                return self._send(503, {protocol.F_ERROR: str(err)})
        self._send(404, {protocol.F_ERROR: "no such endpoint"})

    def log_message(self, *args):
        pass


def main():
    reason = keys.configured()
    assert reason is None, f"co-signer cannot start: {reason}"
    mode = attest.mode()
    if mode == attest.DEV_INSECURE:
        log("WARNING attestation is DISABLED (dev). Every audit row is marked "
            "unattested. Never run this on a box the enclave trusts.")
    audit.connect()
    log(f"listening on {HOST}:{PORT}, attestation={mode}, audit={audit.db_path()}, "
        f"limits={policy.per_user_limit()}/user/h {policy.total_limit()}/h total "
        f"{policy.sign_limit()}/h bare signs")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
