"""Every hostname anything on this box is allowed to open a connection to.

Nothing constrained that until now. ``deploy/hetzner/hardening.conf`` restricted
the filesystem, the privileges and the kernel interfaces of every unit and said
nothing at all about where a socket could point, so code execution in the web UI
or the Gmail push webhook -- two stdlib HTTP servers reachable from the internet
through Caddy, running as the user that can read ``database/`` -- was one POST
away from taking every user's wrapped token off the machine.

This module and ``backend/daemons/egress_proxy.py`` close that. The units run
under ``IPAddressDeny=any`` plus ``IPAddressAllow=localhost`` and have their
HTTP clients pointed at a loopback CONNECT proxy, so the set of destinations
reachable from this machine is exactly ``hosts()`` and everything else is a
refused tunnel with a line in the journal naming what was asked for.

The list is derived, not typed, and derived at render time rather than here.
Every entry comes from the module that already names the host for its own
reasons -- ``llm_client.PROVIDERS`` for inference, ``oauth_app`` for Google's
OAuth endpoints, ``telegram.API_ROOT``, ``polar_api``'s two bases, both TDX
allowlists' ``pccs_url``, ``site.COSIGNER_HOST`` -- so adding a provider cannot
leave the allowlist behind. There is nothing here to forget to edit.
``deploy/render_egress_allowlist.py`` does that walk and writes
``egress_allowlist.json``; this module reads it and imports nothing else.

That split is not tidiness. Those imports are import edges whether they sit at
module level or inside a function, and the enclave ships one image per role, so
while the walk lived here the container holding the only route off the host
carried ``custody.keyring``, ``custody.client``, ``secrets_checks``, billing and
the inference client in its filesystem -- to compute thirteen strings. The
process that holds the network is deliberately not the process that holds the
API keys, and under a per-role image that has to be true of the filesystem too.
``tests/test_egress.py`` still checks the shipped list against the live
constants, so a provider added without a re-render fails there rather than in
production.

Exact matches only. No wildcards, no suffix rules, no regexes: every
destination this system has is a specific name, and a suffix rule is how an
allowlist for ``near.ai`` comes to permit an attacker's ``evil.near.ai``. One
consequence is worth stating because it is the property that survives an RCE:
this list holds names and no addresses, so there is no way to reach a bare IP
through the proxy at all, and ``refusal()`` rejects one before it ever resolves.

What this does not defend. The drafter's tools are ``search_emails``,
``get_calendar_events`` and ``get_email_thread``; none of them fetches a URL, so
prompt injection in an email body could not open a connection before this
existed and cannot now. The control is for the post-compromise case and for a
dependency that ships a release which phones home. Do not describe it as
anything wider.
"""

import json
import os
from pathlib import Path

CONNECT_PORT = 443

ALLOWLIST_FILE = Path(__file__).resolve().parent / "egress_allowlist.json"

# Additional hostnames, comma-separated. The escape hatch exists for one
# specific reason rather than as general configurability: the proxy runs as its
# own user and deliberately cannot read `.env`, so a host that only exists
# because of an override in that file (LETTERLOCK_COSIGNER_HOST, say) is
# invisible to it. Setting this on the proxy unit is how such a host gets in.
EXTRA_HOSTS_ENV = "LETTERLOCK_EGRESS_EXTRA"


class AllowlistInvalid(Exception):
    """The committed allowlist is missing or not what this module expects.

    A raise and not an assert: the file crossed a trust boundary the moment it
    became something on disk rather than something in this process, and it is
    the one input whose absence must stop the proxy rather than open it. Raising
    at read time is fail-closed in the direction that matters -- the proxy
    refuses to start and nothing leaves the machine, which is louder and safer
    than starting with an empty list and refusing every tunnel one at a time."""


def _listed():
    """The committed hostnames, as a frozenset.

    Read on every call rather than cached, because the call sites are a CONNECT
    handler and a test, the file is thirteen short strings, and a cache here is
    a second thing to invalidate when `render_egress_allowlist` rewrites it."""
    try:
        raw = json.loads(ALLOWLIST_FILE.read_text())
    except OSError as e:
        raise AllowlistInvalid(
            f"cannot read the egress allowlist at {ALLOWLIST_FILE}: {e}") from e
    except ValueError as e:
        raise AllowlistInvalid(
            f"{ALLOWLIST_FILE} is not valid JSON: {e}") from e
    found = raw.get("hosts") if isinstance(raw, dict) else None
    if not isinstance(found, list) or not found:
        raise AllowlistInvalid(
            f"{ALLOWLIST_FILE} carries no 'hosts' list; run "
            "python -m deploy.render_egress_allowlist")
    for host in found:
        if not isinstance(host, str) or not host or host != host.strip().lower():
            raise AllowlistInvalid(
                f"{ALLOWLIST_FILE} lists {host!r}, which is not a bare "
                "lowercased hostname")
    return frozenset(found)


def _extra_hosts():
    raw = os.environ.get(EXTRA_HOSTS_ENV, "")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def hosts():
    """The whole allowlist, as a frozenset of lowercased hostnames: what was
    rendered, plus whatever the proxy's own unit adds through the environment."""
    found = set(_listed()) | _extra_hosts()
    assert all(found), "an empty hostname reached the allowlist"
    return frozenset(found)


def split_authority(target):
    """``host, port`` from a CONNECT target, or a ValueError naming the problem.

    Deliberately strict about shapes rather than permissive: a bracketed IPv6
    literal, a userinfo prefix and a trailing dot are all things a parser can be
    talked into accepting differently from the check that follows it, and this
    string comes from whoever holds the client end of the socket."""
    assert isinstance(target, str), "CONNECT target must be a string"
    if "/" in target or "@" in target or "[" in target or "]" in target:
        raise ValueError(f"unsupported CONNECT target {target!r}")
    host, sep, port = target.rpartition(":")
    if not sep or not host or not port.isdigit():
        raise ValueError(f"CONNECT target must be host:port, got {target!r}")
    number = int(port)
    if not 1 <= number <= 65535:
        raise ValueError(f"port {port} out of range")
    return host.rstrip(".").lower(), number


def refusal(host, port):
    """Why this destination is not allowed, or None if it is.

    A reason rather than a bool because the reason is the whole operational
    value of the control: the failure this produces looks like a provider
    outage until somebody reads a log line that says which name was refused."""
    assert host, "refusal() needs a hostname"
    if port != CONNECT_PORT:
        return f"port {port} is not {CONNECT_PORT}"
    allowed = hosts()
    if host not in allowed:
        return f"{host} is not in the egress allowlist"
    return None
