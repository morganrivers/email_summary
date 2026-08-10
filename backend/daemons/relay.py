"""Move bytes between two sockets until one side is done.

Both proxies in this tree do this and neither should own it. `egress_proxy`
relays a CONNECT tunnel outward; `ingress_proxy` relays a published port inward.
The interesting half of each is its own -- one checks a hostname against an
allowlist, the other has no choice to make at all -- but the loop underneath is
the same loop, and a half-close bug fixed in one copy and not the other is a
truncated HTTP response on whichever side nobody tested.

Nothing here parses anything. That is the property worth keeping: a relay that
understood the protocol it carries would be a second parser in a process whose
whole value is holding no state about what passes through it.
"""

import selectors
import socket

CHUNK = 65536
IDLE_TIMEOUT = 300


def pump(one, other, idle_timeout=IDLE_TIMEOUT):
    """Move bytes both ways until one side closes or the pair goes idle.

    Half-close is forwarded rather than treated as end of session: an HTTP
    client that has finished its request and is waiting on a response has shut
    down its write side, and tearing the whole relay down there would truncate
    every reply larger than a socket buffer.

    Returns rather than raises on a socket error. By the time bytes are moving
    there is no channel left to report a failure on -- the tunnel is established
    and the protocol inside it is not ours -- so a peer that vanishes ends the
    relay, and the caller closes both sides."""
    assert one is not other, "cannot relay a socket to itself"
    sockets = {one: other, other: one}
    selector = selectors.DefaultSelector()
    for sock in sockets:
        sock.settimeout(idle_timeout)
        selector.register(sock, selectors.EVENT_READ)
    try:
        while selector.get_map():
            ready = selector.select(idle_timeout)
            if not ready:
                return
            for key, _events in ready:
                source = key.fileobj
                try:
                    data = source.recv(CHUNK)
                except OSError:
                    return
                if not data:
                    selector.unregister(source)
                    try:
                        sockets[source].shutdown(socket.SHUT_WR)
                    except OSError:
                        return
                    continue
                try:
                    sockets[source].sendall(data)
                except OSError:
                    return
    finally:
        selector.close()
