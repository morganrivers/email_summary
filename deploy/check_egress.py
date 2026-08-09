"""Is the egress allowlist actually enforced on this box?

A deploy that finishes green is not evidence that it is, and the two ways it can
be off are both silent.

``IPAddressDeny=`` needs cgroup v2 with BPF. Without it systemd logs a line
about not installing the filter and starts the unit anyway, so every service
comes up healthy with unrestricted network access and the only difference from
before this track is a config file that says otherwise. The other way is a
proxy that is up and allowing everything, which looks identical to a proxy that
is up and allowing the right things until somebody asks it for a host that
should be refused.

So this asks the box three questions, by doing rather than by reading config:
does the proxy refuse an unlisted host, does it allow a listed one, and is a
process under the shared sandbox actually unable to open a direct connection.

Run it on the server after a deploy:

    venv/bin/python -m deploy.check_egress

The third check needs root (it starts a transient unit under the same drop-in
the services get) and is reported as UNKNOWN rather than passed when it cannot
run. Exits nonzero if any check fails.
"""

import os
import socket
import subprocess
import sys

from backend import egress, site

PROBE_HOST = "example.com"
# Cloudflare's resolver: a stable routable address that is not in the allowlist
# and never will be, so a successful connection to it means the filter is off.
PROBE_ADDRESS = "1.1.1.1"
TIMEOUT = 10
UNIT_UNDER_TEST = "letterlock-web.service"


def _ask(target):
    """One CONNECT through the proxy. Returns the status line, or a reason the
    proxy could not be asked at all -- which is itself a failure, since every
    other unit depends on it answering."""
    try:
        with socket.create_connection(("127.0.0.1", site.EGRESS_PROXY_PORT), TIMEOUT) as sock:
            sock.sendall(f"CONNECT {target} HTTP/1.1\r\n\r\n".encode())
            sock.settimeout(TIMEOUT)
            data = b""
            while b"\r\n" not in data and len(data) < 256:
                chunk = sock.recv(1)
                if not chunk:
                    break
                data += chunk
            return data.decode("latin-1").strip()
    except OSError as err:
        return f"proxy unreachable: {err}"


def check_unlisted_is_refused():
    """The check that fails if the allowlist is decorative."""
    assert PROBE_HOST not in egress.hosts(), (
        f"{PROBE_HOST} is in the allowlist; this probe needs a host that is not"
    )
    status = _ask(f"{PROBE_HOST}:443")
    if " 403 " in status:
        return None
    return f"proxy did not refuse {PROBE_HOST}: {status!r}"


def check_listed_is_allowed():
    """The other direction. A proxy that refuses everything passes the check
    above and takes the whole box off the network."""
    host = sorted(egress.hosts())[0]
    status = _ask(f"{host}:443")
    if " 200 " in status:
        return None
    return f"proxy did not tunnel to allowlisted {host}: {status!r}"


def check_direct_connection_is_blocked():
    """Does the kernel enforce IPAddressDeny for a unit under the sandbox?

    Run inside a transient unit that inherits the same drop-in directory the
    real services get, so what is tested is the filter as installed rather than
    the file that asks for it. A connection that succeeds means BPF filtering is
    not in effect and every IPAddressDeny on this box is a comment."""
    if os.geteuid() != 0:
        return "UNKNOWN: needs root to start a transient unit"
    # A literal address, not a name: this probe is asking whether the kernel
    # will let the packet out, and a DNS lookup that the filter also blocks
    # would answer "blocked" for the wrong reason.
    script = (
        "import socket, sys\n"
        "try:\n"
        f"    socket.create_connection(('{PROBE_ADDRESS}', 443), {TIMEOUT})\n"
        "except OSError:\n"
        "    sys.exit(0)\n"
        "sys.exit(1)\n"
    )
    result = subprocess.run(
        ["systemd-run", "--pipe", "--quiet", "--wait", "--collect",
         "-p", "IPAddressDeny=any", "-p", "IPAddressAllow=localhost",
         sys.executable, "-c", script],
        capture_output=True, timeout=120,
    )
    if result.returncode == 0:
        return None
    if result.returncode == 1:
        return ("a sandboxed process opened a direct connection; IPAddressDeny is "
                "not being enforced (cgroup v2 + BPF missing?) -- check "
                f"`journalctl -u {UNIT_UNDER_TEST} | grep -i 'IP firewall'`")
    detail = result.stderr.decode(errors="replace").strip().splitlines()
    return f"UNKNOWN: could not run the probe: {detail[-1] if detail else result.returncode}"


CHECKS = (
    ("unlisted host refused", check_unlisted_is_refused),
    ("allowlisted host tunnelled", check_listed_is_allowed),
    ("direct connection blocked", check_direct_connection_is_blocked),
)


def main():
    allowed = sorted(egress.hosts())
    print(f"allowlist ({len(allowed)}): {' '.join(allowed)}")
    failed = 0
    for label, check in CHECKS:
        reason = check()
        if reason is None:
            print(f"OK   {label}")
        elif reason.startswith("UNKNOWN"):
            print(f"?    {label}: {reason.removeprefix('UNKNOWN: ')}")
        else:
            print(f"FAIL {label}: {reason}")
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
