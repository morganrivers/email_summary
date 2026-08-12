"""The only process on this box allowed to open a connection to the internet.

An HTTP CONNECT proxy on loopback. Every other unit runs under
``IPAddressDeny=any`` plus ``IPAddressAllow=localhost`` with ``https_proxy``
pointed here, so the reachable destination set for the whole machine is exactly
``backend.egress.hosts()``.

CONNECT and nothing else. A forward proxy that also served absolute-URI GET
would have to parse and relay request bodies, which is both a larger parsing
surface and a second copy of every request inside a process that is meant to
see none of them. CONNECT reads one request line and a header block and then
moves opaque bytes: TLS is established end to end between the unit and the
destination, so this process never holds a decrypted byte and holds no key that
would let it.

Why this is written here rather than installed from apt. The proxy exists to
contain an attacker who already has code execution as ``letterlock``, and that
attacker speaks to it directly, with whatever bytes they choose. It is also the
one process with unrestricted network access, so a memory-safety bug in its
request parser hands back precisely the privilege the control was bought to
remove. A small C proxy is the larger version of that surface, not the smaller
one; the bugs reachable in this file are logic bugs in an allowlist check, and
those are the kind a test suite catches.

Two things it does not do, both deliberate, both worth knowing before relying
on it.

It does not authenticate its clients. Any local user can ask it for a tunnel.
The boundary being drawn is over destinations, not callers, and
``IPAddressAllow=localhost`` on the units is what stops them going around it.

It runs code out of ``/opt/letterlock``, which the application user owns. An
attacker with write access there who waits for a restart gets this process, and
the same is true of the co-signer, whose separation of privilege rests on the
same directory. Closing that means the source not being writable by the
accounts it sandboxes, which is a change to ``deploy/deploy.sh`` and not to
this file.
"""

import ipaddress
import os
import socket
import socketserver
import sys

import execguard
from backend import egress, procwatch, secrets, site
from backend.daemons import relay

HOST = os.environ.get("EGRESS_PROXY_BIND", "127.0.0.1")
PORT = int(os.environ.get("EGRESS_PROXY_PORT", str(site.EGRESS_PROXY_PORT)))

MAX_LINE_BYTES = 4096
MAX_HEADER_LINES = 64
HANDSHAKE_TIMEOUT = 10
CONNECT_TIMEOUT = 15
IDLE_TIMEOUT = relay.IDLE_TIMEOUT


def log(msg):
    sys.stderr.write(f"egress-proxy {msg}\n")
    sys.stderr.flush()


class Refused(Exception):
    """A request that will not be tunnelled, carrying the status to answer with
    and the reason to write down. The reason goes to the journal and a short
    form goes back over the socket: the caller is either one of our own units,
    which needs to know it was the allowlist rather than the network, or it is
    an attacker, who learns only that the name was refused."""

    def __init__(self, status, reason):
        super().__init__(reason)
        self.status = status
        self.reason = reason


class Handler(socketserver.StreamRequestHandler):
    """One CONNECT request and the tunnel it opens.

    ``rbufsize = 0`` is not a performance oversight. A buffered reader can pull
    the first bytes of the client's TLS ClientHello into Python's buffer while
    parsing the header block, and those bytes are then invisible to the socket
    the tunnel pumps -- a handshake that hangs, intermittently, under load. An
    unbuffered read is byte-at-a-time over a few hundred bytes of header and
    then never used again."""

    timeout = HANDSHAKE_TIMEOUT
    rbufsize = 0

    def handle(self):
        try:
            host, port = self._request()
            upstream = self._open(host, port)
        except Refused as err:
            log(f"deny {err.reason}")
            self._refuse(err.status, "denied by egress allowlist")
            return
        except (OSError, ValueError) as err:
            log(f"deny malformed request from {self.client_address}: {err}")
            self._refuse(400, "bad request")
            return
        log(f"allow {host}:{port}")
        self._send("HTTP/1.1 200 Connection established\r\n\r\n")
        try:
            relay.pump(self.connection, upstream)
        finally:
            upstream.close()

    def _send(self, text):
        try:
            self.connection.sendall(text.encode("ascii"))
        except OSError:
            pass

    def _refuse(self, status, text):
        """A refusal says only that the tunnel was refused.

        The caller is either one of our own units, which needs to know this was
        the allowlist rather than the network and gets that from the phrase, or
        it is an attacker, who learns nothing about the list from it. The
        journal line carries the host and the reason; this does not.

        ``Connection: close`` belongs on a refusal and must not appear on the
        200 above: after a successful CONNECT the socket is the tunnel, and a
        header telling the client the connection is closing is how a proxy
        makes a client tear down a session it just established."""
        self._send(f"HTTP/1.1 {status} {text}\r\nConnection: close\r\n\r\n")

    def _line(self):
        raw = self.rfile.readline(MAX_LINE_BYTES + 1)
        if len(raw) > MAX_LINE_BYTES:
            raise Refused(431, f"header line over {MAX_LINE_BYTES} bytes")
        if not raw:
            raise Refused(400, "client closed before sending a request")
        return raw.decode("latin-1").rstrip("\r\n")

    def _request(self):
        """The destination of a CONNECT, after the header block is consumed.

        The headers are read and dropped rather than skipped, because the bytes
        have to leave the socket before the tunnel starts either way. Nothing in
        them is honored: no Proxy-Authorization, no Host override. The target on
        the request line is the only thing that decides where this goes."""
        parts = self._line().split()
        if len(parts) != 3:
            raise Refused(400, "malformed request line")
        method, target, _version = parts
        if method != "CONNECT":
            raise Refused(405, f"method {method} is not supported; CONNECT only")
        for _ in range(MAX_HEADER_LINES):
            if not self._line():
                return egress.split_authority(target)
        raise Refused(431, f"over {MAX_HEADER_LINES} header lines")

    def _open(self, host, port):
        reason = egress.refusal(host, port)
        if reason:
            raise Refused(403, reason)
        return _connect(host, port)


def _routable(address):
    """Is this an address the proxy is willing to dial?

    An allowlisted name whose DNS answer points inside the machine or inside a
    private range is the shape of an SSRF: the allowlist was satisfied by a
    name, and the connection lands somewhere the units were denied by
    ``IPAddressDeny``. TLS would still refuse to authenticate the far end, but
    the connection is the thing being prevented here, not the disclosure."""
    ip = ipaddress.ip_address(address)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def _connect(host, port):
    """A connected socket to the first address that answers.

    Every candidate is checked, not just the one that connects, so a resolver
    that returns a good address and a loopback one cannot be raced into
    supplying the second."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as err:
        raise Refused(502, f"{host} did not resolve: {err}") from err
    assert infos, f"getaddrinfo returned nothing for {host}"
    for family, socktype, proto, _canonical, address in infos:
        if not _routable(address[0]):
            raise Refused(403, f"{host} resolved to non-routable {address[0]}")
    last = None
    for family, socktype, proto, _canonical, address in infos:
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(CONNECT_TIMEOUT)
            sock.connect(address)
            sock.settimeout(IDLE_TIMEOUT)
            return sock
        except OSError as err:
            sock.close()
            last = err
    raise Refused(502, f"{host}:{port} refused the connection: {last}")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    allowed = egress.hosts()
    assert allowed, "the egress allowlist is empty; every unit would be offline"
    log(f"listening on {HOST}:{PORT}, {len(allowed)} host(s) allowed: "
        f"{' '.join(sorted(allowed))}")
    Server((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    execguard.lock_down(secrets.tee_required())
    # No reporter: this role mounts no volume, so its report is the container
    # exiting and looping under `restart: always`. See backend/intrusion.py.
    procwatch.start(procwatch.role_of(__spec__.name))
    main()
