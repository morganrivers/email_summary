"""The proxy refuses what the allowlist refuses, over a socket.

`test_egress.py` checks the list. This checks the process in front of it, which
is the part an attacker with code execution actually talks to: it is reachable
from every unit, it is the one thing on the box with a network, and its parser
reads bytes chosen by whoever holds the client end.

Every test here drives a real server over a real socket rather than calling the
handler directly. A CONNECT proxy is almost entirely socket behaviour -- when
the 200 goes out, what happens to a half-closed side, whether a refusal closes
or hangs -- and none of that is exercised by calling `_request()` in isolation.
"""

import socket
import threading

import pytest

from backend import egress
from backend.daemons import egress_proxy


@pytest.fixture
def proxy():
    """A proxy on an ephemeral port, torn down with the test."""
    server = egress_proxy.Server(("127.0.0.1", 0), egress_proxy.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def upstream():
    """A destination that answers with one known line and closes. Stands in for
    a TLS endpoint: the proxy never looks inside the tunnel, so bytes are bytes."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    received = []

    def serve():
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        with conn:
            received.append(conn.recv(65536))
            conn.sendall(b"pong")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname(), received
    finally:
        listener.close()
        thread.join(timeout=5)


def ask(address, request):
    """Send a raw request to the proxy and read what comes back."""
    sock = socket.create_connection(address, timeout=5)
    sock.sendall(request)
    return sock


def status_line(sock):
    data = b""
    while b"\r\n" not in data:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode("latin-1").strip()


def test_an_unlisted_host_gets_403_and_no_tunnel(proxy):
    sock = ask(proxy, b"CONNECT evil.example.com:443 HTTP/1.1\r\n\r\n")
    with sock:
        assert "403" in status_line(sock)


def test_a_non_connect_method_is_refused(proxy):
    """No absolute-URI forwarding. Serving GET would mean parsing and relaying
    bodies in a process meant to see none of them."""
    sock = ask(proxy, b"GET http://evil.example.com/ HTTP/1.1\r\nHost: x\r\n\r\n")
    with sock:
        assert "405" in status_line(sock)


def test_a_malformed_request_line_is_refused(proxy):
    sock = ask(proxy, b"NONSENSE\r\n\r\n")
    with sock:
        assert "400" in status_line(sock)


def test_an_overlong_request_line_is_refused(proxy):
    """The parser reads bytes an attacker chooses, so the line length is capped
    rather than left to however much they are willing to send."""
    target = b"a" * (egress_proxy.MAX_LINE_BYTES + 100)
    sock = ask(proxy, b"CONNECT " + target + b":443 HTTP/1.1\r\n\r\n")
    with sock:
        assert "431" in status_line(sock)


def test_too_many_headers_are_refused(proxy):
    headers = b"".join(b"X-Filler: 1\r\n" for _ in range(egress_proxy.MAX_HEADER_LINES + 5))
    sock = ask(proxy, b"CONNECT api.telegram.org:443 HTTP/1.1\r\n" + headers + b"\r\n")
    with sock:
        assert "431" in status_line(sock)


def test_an_allowed_host_resolving_to_loopback_is_refused(proxy, monkeypatch, upstream):
    """An allowlisted name whose DNS answer points inside the machine is the
    shape of an SSRF: the allowlist is satisfied by a name and the connection
    lands where IPAddressDeny denied the units."""
    (_host, port), _received = upstream
    monkeypatch.setattr(egress, "hosts", lambda: frozenset({"localhost"}))
    monkeypatch.setattr(egress, "CONNECT_PORT", port)
    sock = ask(proxy, f"CONNECT localhost:{port} HTTP/1.1\r\n\r\n".encode())
    with sock:
        assert "403" in status_line(sock)


def test_an_allowed_host_is_tunnelled_end_to_end(proxy, upstream, monkeypatch):
    """The success path, with `_routable` stood down so the destination can be
    a loopback listener. Everything else is the real thing: the proxy resolves,
    connects, answers 200, and then moves bytes it does not interpret."""
    (_host, port), received = upstream
    monkeypatch.setattr(egress, "hosts", lambda: frozenset({"localhost"}))
    monkeypatch.setattr(egress, "CONNECT_PORT", port)
    monkeypatch.setattr(egress_proxy, "_routable", lambda address: True)

    sock = ask(proxy, f"CONNECT localhost:{port} HTTP/1.1\r\n\r\n".encode())
    with sock:
        assert "200" in status_line(sock)
        assert sock.recv(2) == b"\r\n"
        sock.sendall(b"ping")
        assert sock.recv(64) == b"pong"
    assert received == [b"ping"]


def test_the_proxy_reads_no_credentials(proxy):
    """Proxy-Authorization is not honored, and neither is anything else in the
    header block. The target on the request line is the only input that decides
    where a tunnel goes; headers are drained because the bytes have to leave the
    socket, not because any of them mean something."""
    sock = ask(proxy, b"CONNECT evil.example.com:443 HTTP/1.1\r\n"
                      b"Proxy-Authorization: Basic YWRtaW46YWRtaW4=\r\n"
                      b"Host: api.telegram.org:443\r\n\r\n")
    with sock:
        assert "403" in status_line(sock)
