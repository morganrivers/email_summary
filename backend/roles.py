"""Which roles the enclave is split into, and which of them takes traffic.

The names were spelled in six places -- `flake.nix`'s entrypoint `case`, its
usage line, `deploy/phala/build_and_publish.sh`, `deploy/render_image_manifest`,
`backend/secrets_checks.REQUIRED_BY_ROLE` and the boundary tests -- and a role
added to five of them is a role that ships with no image, or no boot gate, or no
push. So the names live here, once, and everything else either imports this or
is asserted against it. The first two of those six are gone entirely: there is
no entrypoint script any more, and each service's `command:` in
`docker-compose.yml` names the module it starts rather than a role. The
generated `deploy/phala/image_files.nix` is an attrset keyed by exactly these
names, which is how `flake.nix` and the publish script derive the list without
reading Python.

This module imports `site` and nothing else, deliberately: every enclave image
carries what its role imports, and the role holding the network must not gain a
fan-out because it needed to know its own name.
"""

from backend import site

# Every role the enclave has, in the order `docker-compose.yml` states them:
# the one that opens a mailbox, the two that serve a person, then the two that
# hold only network position and no data at all. The order is not decorative --
# `tests/test_enclave_boundary.py` compares this list against the services in
# that file, so a role added here and given no service fails rather than
# silently having no way to start.
ROLES = ("mail", "web", "hook", "egress", "ingress")

# The roles that hold account data or a key, and so must not also hold a route
# off the host. Stated as its own set because it is the sentence the network
# partition enforces, and a role added to ROLES without a decision here should
# be a failing test rather than a container that quietly got the internet.
DATA_ROLES = frozenset({"mail", "web", "hook"})

# The roles whose whole job is network position: no volume, no secret, no
# guest-agent socket, and so no attestation gate to run.
NETWORK_ROLES = frozenset({"ingress", "egress"})

# What the CVM publishes, and where each published port goes. The ingress role
# is the only container with both a published port and a route off the host, so
# this is the complete list of ways in -- port on the outside, then the service
# name docker's embedded DNS resolves on the internal network, and its port.
#
# Keyed by the outside port and not by the role, because that is the direction
# the question is asked in: a packet arrives on a port and has to be given a
# destination. The upstream host is the compose service name, which is why these
# are role names and not addresses.
INGRESS_ROUTES = {
    site.WEB_PORT: ("web", site.WEB_PORT),
    site.GMAIL_PUSH_PORT: ("hook", site.GMAIL_PUSH_PORT),
}

assert DATA_ROLES | NETWORK_ROLES == set(ROLES), (
    "every role either holds data or holds network position; "
    f"unclassified: {sorted(set(ROLES) - DATA_ROLES - NETWORK_ROLES)}"
)
assert not (DATA_ROLES & NETWORK_ROLES), (
    "a role holding data and the network is the arrangement this split removed"
)
assert all(role in DATA_ROLES for _port, (role, _up) in INGRESS_ROUTES.items()), (
    "the ingress forwards to a role that is not one of the data roles"
)
