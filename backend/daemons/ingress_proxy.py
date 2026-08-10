"""The only container the outside world connects to, and the reason the roles
that hold data no longer need a route off the host.

The problem it solves. `egress_proxy` plus an `internal: true` network is a real
control for the `mail` role: docker installs no route off the host for that
network, so mail reaches the internet through the proxy or not at all. It was
not a control for `web` and `hook`. Both must *receive* traffic from outside the
CVM, a published port on an internal-only network never receives forwarded
ingress, so both had to sit on the ordinary bridge as well -- and a container on
the ordinary bridge has a route out. For those two the allowlist was a pair of
environment variables their own HTTP clients chose to honour, which an attacker
with code execution simply does not, and calling that enforcement would have
been the kind of claim this tree exists to refuse.

This closes it by taking the published ports away from them. The CVM publishes
to this container, this container is on both networks, and it forwards inward
over the internal one. `web` and `hook` move to the internal network alone: still
reachable, no longer routable outward. The allowlist becomes enforcement for
every role that holds anything.

What it is. A TCP forwarder and deliberately nothing more. It reads no request
line, parses no header, and terminates no TLS -- a connection arriving on a
published port is joined to a connection to the service that port belongs to,
and after that it moves opaque bytes. That is the whole design: the process the
open internet talks to first should have the smallest possible answer to "what
can I make it misinterpret", and the answer here is a port number it looks up in
a table it was born with.

Why in-repo rather than an off-the-shelf ingress. The same argument
`egress_proxy` makes and one more. The same argument: it faces an attacker with
whatever bytes they choose, so a memory-unsafe C parser is the wrong thing to
put there. The one more: an ingress from a public registry is an image we do not
build, and every image in this compose is measured into the `compose-hash` that
the KMS gates secret release on. Pinning somebody else's digest would make the
measurement mean "the bytes we were given" rather than "the bytes we can
rebuild".

What it does not do, stated because it is easy to assume otherwise. It does not
tell the web tier who connected. A pure TCP forwarder cannot add an
`X-Forwarded-For` without becoming an HTTP parser, which is the surface this
file exists to avoid, so `web` sees this container as its peer. That is not a
regression -- inside a CVM the peer was already dstack's ingress rather than a
browser, and `site.LETTERLOCK_TRUSTED_PROXIES` ships empty for exactly that
reason: an unnamed proxy costs a useless audit row and a wrongly named one costs
a forgeable one. It does not authenticate anybody, because everything it
forwards is a public endpoint whose own handler does the deciding. And it is not
a rate limiter or a WAF; it makes the reachable set smaller, not the requests
safer.
"""

import os
import socket
import socketserver
import sys
import threading

from backend import roles
from backend.daemons import relay

# 0.0.0.0 by default, unlike every other listener in this tree. This one is
# reached from outside the CVM by definition -- binding loopback would publish a
# port to a socket nothing off the host can reach, which is the bug this file
# was written to fix, not a safe default.
# nosec B104  # the one listener that has to accept from off the host
HOST = os.environ.get("INGRESS_PROXY_BIND", "0.0.0.0")  # nosec B104

CONNECT_TIMEOUT = 15
ACCEPT_BACKLOG = 128


def log(msg):
    print(f"[ingress] {msg}", file=sys.stderr, flush=True)


class Handler(socketserver.BaseRequestHandler):
    """One inbound connection, joined to the service its port names.

    `server.route` is set when the listener is built, so the destination is
    fixed at startup and no byte the client sends can influence it. That is the
    property that makes this safe to put in front of everything: there is no
    parsing step in which a request could name a different upstream."""

    def handle(self):
        host, port = self.server.route
        try:
            upstream = socket.create_connection((host, port), CONNECT_TIMEOUT)
        except OSError as err:
            # No error is written back. We do not know what protocol this
            # connection carries -- an HTTP status would be a lie for anything
            # that is not HTTP -- so the connection closes and the client sees
            # what it would see if the service were down, which is what is true.
            log(f"upstream {host}:{port} unreachable: {err}")
            return
        try:
            self.request.settimeout(relay.IDLE_TIMEOUT)
            relay.pump(self.request, upstream)
        finally:
            upstream.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = ACCEPT_BACKLOG

    def __init__(self, address, route):
        self.route = route
        super().__init__(address, Handler)


def listeners(routes=None):
    """One bound server per published port, not started.

    Built before any is served so a port already in use fails the boot rather
    than leaving the CVM half-reachable: a listener that came up and a listener
    that did not is the shape an operator debugs for an afternoon."""
    table = roles.INGRESS_ROUTES if routes is None else routes
    assert table, "the ingress has no routes and would forward nothing"
    built = []
    try:
        for port, (host, upstream_port) in sorted(table.items()):
            built.append(Server((HOST, port), (host, upstream_port)))
    except OSError:
        for server in built:
            server.server_close()
        raise
    return built


def main():
    servers = listeners()
    for server in servers:
        host, port = server.route
        log(f"listening on {HOST}:{server.server_address[1]} -> {host}:{port}")
    threads = [threading.Thread(target=s.serve_forever, daemon=True)
               for s in servers[1:]]
    for thread in threads:
        thread.start()
    servers[0].serve_forever()


if __name__ == "__main__":
    main()
