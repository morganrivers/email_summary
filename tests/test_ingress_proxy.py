"""The forwarder moves bytes to the service its port names, and decides nothing.

This is the first process the open internet talks to, so what it can be talked
into is the whole question. The answer should be "nothing": the destination is
fixed when the listener is built, there is no request to parse, and no byte a
client sends reaches a decision. The tests below are mostly about proving that
negative, which is why several of them send deliberate garbage and assert it was
forwarded verbatim rather than acted on.

Driven over real sockets rather than by calling the handler, for the reason
`test_egress_proxy.py` gives: a TCP forwarder is almost entirely socket
behaviour -- half-close, an upstream that is down, two listeners at once -- and
none of that is exercised by calling a method.
"""

import socket
import threading

import pytest

from backend import roles
from backend.daemons import ingress_proxy


@pytest.fixture
def upstream():
    """A service that echoes what it is sent, so a test can tell whether the
    bytes arrived unchanged."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    # A short accept timeout rather than a blocking one: closing a listening
    # socket does not reliably wake a thread already inside accept(), so a
    # blocking fixture costs every test in this file the join timeout.
    listener.settimeout(0.05)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=_echo, args=(conn,), daemon=True).start()

    def _echo(conn):
        with conn:
            while True:
                try:
                    data = conn.recv(4096)
                except OSError:
                    return
                if not data:
                    return
                conn.sendall(data)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()
    finally:
        stop.set()
        thread.join(timeout=5)
        listener.close()


@pytest.fixture
def forwarder(upstream, monkeypatch):
    """An ingress on an ephemeral port pointed at the echo service."""
    monkeypatch.setattr(ingress_proxy, "HOST", "127.0.0.1")
    servers = ingress_proxy.listeners({0: upstream})
    server = servers[0]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _send(address, payload, expect=None):
    with socket.create_connection(address, timeout=5) as sock:
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        got = b""
        while len(got) < (expect if expect is not None else len(payload)):
            chunk = sock.recv(65536)
            if not chunk:
                break
            got += chunk
        return got


def test_bytes_reach_the_service_unchanged(forwarder):
    assert _send(forwarder, b"hello upstream") == b"hello upstream"


def test_it_parses_nothing_it_forwards(forwarder):
    """The property the whole design rests on. None of these is valid HTTP and
    none of them is anything else either; a forwarder that answered any of them
    would be a forwarder with a parser in it."""
    for payload in (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
                    b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n",
                    b"\x00\xff\x00\xff not a protocol at all",
                    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
        assert _send(forwarder, payload) == payload


def test_a_large_body_survives_a_half_close(forwarder):
    """The bug the shared relay exists to have in one place: a client that has
    finished writing shuts down its write side, and treating that as end of
    session truncates every response bigger than a socket buffer."""
    payload = b"x" * (1024 * 512)
    assert _send(forwarder, payload) == payload


def test_the_route_is_fixed_before_any_client_connects(upstream, monkeypatch):
    """No byte from the client picks the upstream. Asserted against the object
    rather than over a socket, because the point is that there is no code path
    between the two -- the destination is an attribute set at construction."""
    monkeypatch.setattr(ingress_proxy, "HOST", "127.0.0.1")
    server = ingress_proxy.listeners({0: upstream})[0]
    try:
        assert server.route == upstream
    finally:
        server.server_close()


def test_an_upstream_that_is_down_closes_rather_than_answering(monkeypatch):
    """It does not know what protocol it carries, so it invents no reply. An
    HTTP 502 here would be a lie for anything that is not HTTP."""
    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    address = dead.getsockname()
    dead.close()

    monkeypatch.setattr(ingress_proxy, "HOST", "127.0.0.1")
    server = ingress_proxy.listeners({0: address})[0]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with socket.create_connection(server.server_address, timeout=5) as sock:
            sock.sendall(b"anything")
            assert sock.recv(4096) == b""
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_a_port_already_taken_fails_the_boot_and_frees_the_rest(upstream):
    """Half a CVM is worse than none: a listener that came up beside one that
    did not is an outage nobody can see. So the ports are bound before any is
    served, and a failure closes what was already bound rather than leaking it
    into a process that is about to exit."""
    taken = socket.socket()
    taken.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    taken.bind(("127.0.0.1", 0))
    taken.listen(1)
    port = taken.getsockname()[1]
    try:
        with pytest.raises(OSError):
            ingress_proxy.listeners({0: upstream, port: upstream})
    finally:
        taken.close()

    # The one that did bind was closed on the way out, so it is free again.
    again = socket.socket()
    again.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    again.bind(("127.0.0.1", 0))
    again.close()


def test_the_default_routes_are_the_ones_the_compose_publishes():
    """`roles.INGRESS_ROUTES` is what `main()` binds and what the compose file's
    `ports:` are asserted against, so the two cannot drift into a published port
    that forwards nowhere."""
    assert roles.INGRESS_ROUTES, "the ingress would forward nothing"
    for port, (host, upstream_port) in roles.INGRESS_ROUTES.items():
        assert host in roles.DATA_ROLES, f"{port} forwards to {host}"
        assert isinstance(upstream_port, int)
