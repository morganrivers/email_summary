"""Single source of truth for talking to the dstack guest agent.

The guest agent is an HTTP server the CVM reaches over a unix socket
(`/var/run/dstack.sock`, mounted into the container by docker-compose). It is
the in-enclave boundary for KMS key release and TDX attestation. Every caller
(F1 selftest, F3 boot gate, the G attestation endpoint) routes through this
module so the socket protocol lives in exactly one place.

Endpoints (dstack >= 0.5.x, `sdk/curl/api.md`):
  GET  /Info                 -> app_id, instance_id, compose_hash, mr_aggregated,
                                os_image_hash, key_provider_info, tcb_info, ...
  POST /GetKey {path,...}     -> KMS-derived key + signature_chain (the unseal
                                primitive; released only to an attested CVM)
  POST /GetQuote {report_data}-> TDX quote binding <=64 bytes of report_data
  POST /GetTlsKey {subject,..}-> RA-TLS key + certificate_chain (enclave keypair,
                                quote embedded in the cert by the guest agent)
"""

from __future__ import annotations

import http.client
import json
import os
import socket
from pathlib import Path

DEFAULT_SOCKET = "/var/run/dstack.sock"


class DstackError(RuntimeError):
    pass


class DstackUnavailable(DstackError):
    """Raised when the guest-agent socket is absent (not inside a dstack CVM)."""


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float):
        super().__init__("dstack", timeout=timeout)
        self._socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


class DstackClient:
    def __init__(self, socket_path: str | None = None, timeout: float = 15.0):
        self.socket_path = socket_path or os.environ.get("DSTACK_SOCKET", DEFAULT_SOCKET)
        self.timeout = timeout

    def available(self) -> bool:
        p = Path(self.socket_path)
        return p.exists() and p.is_socket()

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        if not self.available():
            raise DstackUnavailable(f"dstack socket not present at {self.socket_path}")
        conn = _UnixHTTPConnection(self.socket_path, self.timeout)
        try:
            payload = None
            headers = {}
            if body is not None:
                payload = json.dumps(body)
                headers["Content-Type"] = "application/json"
            conn.request(method, path, body=payload, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            if resp.status != 200:
                raise DstackError(f"{method} {path} -> HTTP {resp.status}: {raw[:200]!r}")
            parsed = json.loads(raw)
            assert isinstance(parsed, dict), f"{path} returned non-object: {parsed!r}"
            return parsed
        finally:
            conn.close()

    def info(self) -> dict:
        return self._request("GET", "/Info")

    def get_key(self, path: str, purpose: str = "", algorithm: str = "ed25519") -> dict:
        assert path, "get_key requires a non-empty derivation path"
        return self._request(
            "POST", "/GetKey", {"path": path, "purpose": purpose, "algorithm": algorithm}
        )

    def get_quote(self, report_data: bytes | str) -> dict:
        rd = report_data if isinstance(report_data, str) else report_data.hex()
        assert len(bytes.fromhex(rd)) <= 64, "report_data must be <= 64 bytes"
        return self._request("POST", "/GetQuote", {"report_data": rd})

    def get_tls_key(
        self,
        subject: str = "tee-email-bot",
        alt_names: list[str] | None = None,
        ra_tls: bool = True,
        server_auth: bool = True,
        client_auth: bool = False,
    ) -> dict:
        body = {
            "subject": subject,
            "alt_names": alt_names or [],
            "usage_ra_tls": ra_tls,
            "usage_server_auth": server_auth,
            "usage_client_auth": client_auth,
        }
        return self._request("POST", "/GetTlsKey", body)
