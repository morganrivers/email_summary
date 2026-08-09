"""The egress allowlist covers what this box actually dials, and nothing wider.

Two failure shapes are worth a test, and they point in opposite directions.

Too narrow is an outage that reads as a provider being down: a host added to
some module and not to the allowlist means the proxy refuses a tunnel nobody
was expecting it to refuse. The derivation in `backend/egress.py` is what stops
that for every host named by one of our own constants, so what is left to test
is the pair it cannot derive -- Google's API roots, which live in a discovery
document inside googleapiclient -- and the systemd drop-in, which is static
text holding a port number that has to match `site.EGRESS_PROXY_PORT`.

Too wide is the control quietly not being one. `refusal()` taking a suffix, a
bare IP or a second port would each turn the allowlist into something that
looks enforced and is not, so those are asserted directly rather than left to
the shape of the list.
"""

import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from backend import egress, site
from backend.integrations import llm_client
from backend.integrations.gmail_gcal import google_client

HARDENING = Path(__file__).resolve().parent.parent / "deploy" / "hetzner" / "hardening.conf"
PROXY_DROPIN = (Path(__file__).resolve().parent.parent / "deploy" / "hetzner"
                / "egress-proxy.service.d" / "20-egress-proxy.conf")


def test_every_provider_endpoint_is_allowed():
    """The derivation's whole purpose. A provider added to PROVIDERS with no
    edit here must already be reachable, completions endpoint and attestation
    endpoint alike -- refusing the second fails `require()` and takes the
    provider down exactly as thoroughly as refusing the first."""
    allowed = egress.hosts()
    for provider in llm_client.PROVIDERS.values():
        assert urlsplit(provider.base_url).hostname in allowed, provider.name
        if provider.attestation_url:
            assert urlsplit(provider.attestation_url).hostname in allowed, provider.name


def test_google_api_roots_are_allowed():
    """The one set of hosts no constant of ours produces.

    googleapiclient takes each API's root URL out of a discovery document
    bundled in the library, so the names sit in vendored JSON. This reads that
    JSON for the api/version pairs `google_client` actually builds, which is
    what makes `egress.GOOGLE_API_HOSTS` a checked copy rather than a guess."""
    import googleapiclient.discovery

    documents = Path(googleapiclient.discovery.__file__).parent / "discovery_cache" / "documents"
    allowed = egress.hosts()
    for api, version in google_client.APIS:
        path = documents / f"{api}.{version}.json"
        assert path.exists(), f"no bundled discovery document at {path}"
        root = json.loads(path.read_text())["rootUrl"]
        assert urlsplit(root).hostname in allowed, f"{api} {version} dials {root}"


def test_the_cosigner_is_allowed():
    """Custody is a hard dependency with no bypass, and in production the
    co-signer is a public hostname through Caddy rather than a loopback port,
    so it goes through the proxy like any third party."""
    assert site.COSIGNER_HOST.lower() in egress.hosts()


def test_both_polar_environments_are_allowed():
    """The proxy cannot read POLAR_SANDBOX and must not have to. Same operator,
    two deployments; an allowlist that flipped with the toggle would break the
    first time the toggle moved."""
    allowed = egress.hosts()
    assert "api.polar.sh" in allowed
    assert "sandbox-api.polar.sh" in allowed


def test_extra_hosts_come_from_the_environment(monkeypatch):
    """The escape hatch for a host that only exists because of a .env override
    the proxy's account is not allowed to read."""
    monkeypatch.setenv(egress.EXTRA_HOSTS_ENV, "example.invalid, other.invalid")
    allowed = egress.hosts()
    assert "example.invalid" in allowed
    assert "other.invalid" in allowed


def test_an_unlisted_host_is_refused():
    assert egress.refusal("evil.example.com", 443)


def test_a_suffix_of_an_allowed_host_is_refused():
    """Exact matches only. A suffix rule is how an allowlist for near.ai comes
    to permit an attacker's near.ai.evil.com, and how one written the other way
    permits evil.near.ai."""
    for host in sorted(egress.hosts()):
        assert egress.refusal(f"{host}.evil.example", 443)
        assert egress.refusal(f"evil-{host}", 443)


def test_a_bare_address_is_refused():
    """The list holds names and no addresses, so this is a property rather than
    a rule that had to be written: there is nothing an IP could match."""
    assert egress.refusal("203.0.113.7", 443)
    assert egress.refusal("127.0.0.1", 443)


def test_only_443_is_allowed():
    host = sorted(egress.hosts())[0]
    assert egress.refusal(host, 443) is None
    for port in (22, 80, 8792, 9001):
        assert egress.refusal(host, port), port


@pytest.mark.parametrize("target", [
    "example.com", "example.com:", ":443", "example.com:https",
    "http://example.com:443", "user@example.com:443", "[::1]:443",
    "example.com:0", "example.com:70000",
])
def test_malformed_connect_targets_are_rejected(target):
    """The CONNECT target comes from whoever holds the client end of the
    socket. Anything the parser and the allowlist check could read differently
    is refused rather than normalized into something one of them accepts."""
    with pytest.raises(ValueError):
        egress.split_authority(target)


def test_connect_target_is_normalized_the_way_the_allowlist_is():
    """Case and a trailing root dot are the two forms a client can send that
    resolve to the same name; both have to reach the check lowercased and
    stripped or the allowlist is bypassed by typing a capital letter."""
    assert egress.split_authority("Api.Telegram.Org:443") == ("api.telegram.org", 443)
    assert egress.split_authority("api.telegram.org.:443") == ("api.telegram.org", 443)


def test_the_sandbox_points_at_the_port_the_proxy_binds():
    """hardening.conf is static text and site.py owns the port. There is no
    renderer between them, so this is what stops the units being pointed at a
    port nothing listens on."""
    text = HARDENING.read_text()
    expected = f"http://127.0.0.1:{site.EGRESS_PROXY_PORT}"
    assigned = [line.split("=", 1)[1] for line in text.splitlines()
                if line.startswith("Environment=") and "_proxy=" in line.lower()]
    assert assigned, "hardening.conf sets no proxy environment"
    for line in assigned:
        name, _, value = line.partition("=")
        if name.lower() == "no_proxy":
            continue
        assert value == expected, f"{name} points at {value}, not {expected}"


def test_the_sandbox_denies_every_address_but_loopback():
    text = HARDENING.read_text()
    assert "IPAddressDeny=any" in text
    assert "IPAddressAllow=localhost" in text


def test_the_proxy_opts_out_of_the_sandbox_it_enforces():
    """Applied unchanged, the shared sandbox would leave the proxy able to
    reach only loopback and proxying to itself. Each reset is what makes it the
    enforcement point rather than another unit behind one."""
    text = PROXY_DROPIN.read_text()
    for reset in ("IPAddressDeny=\n", "IPAddressAllow=any\n", "Environment=\n",
                  "After=\n", "Wants=\n"):
        assert reset in text, f"missing {reset.strip()!r} in {PROXY_DROPIN.name}"
    assert "User=egress" in text


def test_the_proxy_runs_as_nobody_elses_account():
    """The unit exists so that the process with unrestricted network access is
    not the process holding the API keys. Sharing letterlock would make the
    separation decorative, which is the same argument 20-cosigner.conf makes."""
    text = PROXY_DROPIN.read_text()
    assert "User=letterlock" not in text
    assert "SupplementaryGroups=letterlock" in text
