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

The list is derived, not typed. Every entry comes from the module that already
names the host for its own reasons -- ``llm_client.PROVIDERS`` for inference,
``oauth_app`` for Google's OAuth endpoints, ``telegram.API_ROOT``,
``polar_api``'s two bases, both TDX allowlists' ``pccs_url``,
``site.COSIGNER_HOST`` -- so adding a provider cannot leave the allowlist
behind. There is nothing here to forget to edit. ``GOOGLE_API_HOSTS`` is the
one exception and says why in its own comment.

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

import importlib.util
import os
from urllib.parse import urlsplit

from backend import site

CONNECT_PORT = 443

# Google's two API hosts are the only entries not read off a constant, because
# there is no constant to read: googleapiclient takes the root URL out of the
# discovery document bundled in the library, so the name lives in a vendored
# JSON blob rather than in any module of ours. Naming them here would be a
# drift risk exactly like the rest, so `test_egress.py` reads those documents
# for the api/version pairs in `google_client.APIS` and fails if a rootUrl host
# is missing from this tuple.
GOOGLE_API_HOSTS = ("www.googleapis.com", "gmail.googleapis.com")

# Additional hostnames, comma-separated. The escape hatch exists for one
# specific reason rather than as general configurability: the proxy runs as its
# own user and deliberately cannot read `.env`, so a host that only exists
# because of an override in that file (LETTERLOCK_COSIGNER_HOST, say) is
# invisible to it. Setting this on the proxy unit is how such a host gets in.
EXTRA_HOSTS_ENV = "LETTERLOCK_EGRESS_EXTRA"


def _host(url):
    """The hostname in a URL, lowercased. Asserts rather than returning None:
    every caller below passes a constant that is supposed to be an https URL,
    and a silent empty string here would quietly shrink the allowlist."""
    assert url, "cannot take a hostname out of an empty URL"
    host = urlsplit(url).hostname
    assert host, f"no hostname in {url!r}"
    return host.lower()


def _provider_hosts():
    """Inference. Both the completions endpoint and, for a confidential
    provider, the attestation endpoint: refusing the second would fail
    ``inference_attestation.require()`` and take the provider down just as
    surely as refusing the first."""
    from backend.integrations import llm_client

    hosts = set()
    for provider in llm_client.PROVIDERS.values():
        hosts.add(_host(provider.base_url))
        if provider.attestation_url:
            hosts.add(_host(provider.attestation_url))
    return hosts


def _google_hosts():
    """Consent, token exchange and the token-info check the Pub/Sub webhook
    runs, plus the two API roots. ``oauth_app.TOKEN_ENDPOINT`` is
    ``cosigner.protocol``'s, which is the same string the co-signer's policy
    pins ``htu`` against, so one edit moves the allowlist and the policy
    together.

    ``calendar_public.ICS_ROOT`` is a different host from the API roots because
    it is a different kind of request: no credentials, the public feed as a
    stranger sees it. It is listed unconditionally rather than behind
    ``oauth_app.acl_scope_registered()``, for the reason ``_billing_hosts``
    lists both Polar deployments -- the proxy cannot read the app's environment,
    and an allowlist that flips with a toggle breaks the first time the toggle
    moves."""
    from backend.daemons import gmail_hook_server
    from backend.integrations.gmail_gcal import calendar_public, oauth_app

    return {
        _host(oauth_app.AUTH_ENDPOINT),
        _host(oauth_app.TOKEN_ENDPOINT),
        _host(gmail_hook_server.CERTS_URL),
        _host(calendar_public.ICS_ROOT),
    } | set(GOOGLE_API_HOSTS)


def _billing_hosts():
    """Both Polar deployments, not whichever one ``POLAR_SANDBOX`` currently
    selects. The proxy cannot read that flag, they are the same operator, and
    an allowlist that flips with a toggle is one that breaks the first time the
    toggle moves."""
    from backend.billing import polar_api

    return {_host(polar_api.PROD_BASE), _host(polar_api.SANDBOX_BASE)}


def _pccs_hosts():
    """The provisioning certification caching service each quote verifier on
    this machine fetches collateral from. Asked of the allowlist files rather
    than hardcoded, since re-pinning against a different PCCS is a thing those
    files are allowed to do.

    "On this machine" is the whole of the guard below. The co-signer is a
    separate service on a separate box, and the enclave image deliberately
    carries only its wire contract (`cosigner/protocol.py`) -- so where its code
    is absent, the process that would fetch that collateral is absent too, and
    an entry for it would be a host allowed for nobody. `find_spec` asks exactly
    that question; the import that follows is by name so a static import graph
    does not pull the module into an image that has no co-signer to run it.
    Every other failure still raises: this is a deployment question, not an
    exception to swallow."""
    from backend.integrations import inference_attestation

    urls = [inference_attestation.policy().get("pccs_url")]
    if importlib.util.find_spec("cosigner.attest") is not None:
        urls.append(importlib.import_module("cosigner.attest").policy().get("pccs_url"))
    return {_host(url) for url in urls if url}


def _alert_hosts():
    """Telegram. Both trust domains reach it -- the app for a user's summary,
    the co-signer for the one seam it keeps into ``backend/`` -- and both do it
    through this same constant."""
    from backend.integrations import telegram

    return {_host(telegram.API_ROOT)}


def _extra_hosts():
    raw = os.environ.get(EXTRA_HOSTS_ENV, "")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def hosts():
    """The whole allowlist, as a frozenset of lowercased hostnames.

    Computed on every call rather than at import, so a test can set
    ``LETTERLOCK_EGRESS_EXTRA`` and a long-lived proxy that is restarted picks
    up a re-pinned PCCS without anyone remembering this module caches."""
    found = set()
    found |= _provider_hosts()
    found |= _google_hosts()
    found |= _billing_hosts()
    found |= _pccs_hosts()
    found |= _alert_hosts()
    found.add(site.COSIGNER_HOST.lower())
    found |= _extra_hosts()
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
