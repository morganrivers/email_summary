"""The enclave's compose file is a security statement, so it is pinned here.

Inside a CVM there are no file modes to enforce anything: dstack injects secrets
as environment and a container receives exactly what its own `environment:`
block names. So `deploy/phala/docker-compose.yml` *is* the partition -- which
process runs as which account, which one may reach the guest-agent socket, and
which secrets each is handed. Unlike the modes on the Hetzner box, that file's
hash is extended as the dstack `compose-hash` and measured into RTMR3, which
makes the partition attested rather than merely configured. It also makes a
careless edit to this file a change of measurement, so it is worth failing here
rather than in a CVM.

Read as text and not as YAML on purpose: pyyaml is in neither requirements.txt
nor requirements-dev.txt, and a boundary test is a bad reason to add a
dependency to a list whose whole point is being the only list.
"""

import re
from pathlib import Path

import pytest

from backend import secrets

REPO = Path(__file__).resolve().parent.parent
COMPOSE = REPO / "deploy" / "phala" / "docker-compose.yml"
FLAKE = REPO / "flake.nix"

ROLES = ("mail", "web", "hook")


def _service_blocks():
    """Each service's own lines, keyed by name.

    A service is a two-space key under `services:`; its block runs to the next
    key at that indent. Enough structure for what is asserted below and no
    parser to keep correct."""
    text = COMPOSE.read_text()
    body = text.split("\nservices:\n", 1)
    assert len(body) == 2, "compose file has no services: section"
    blocks, current = {}, None
    for line in body[1].splitlines():
        # The next top-level key ends the section. Checked before anything else:
        # the file ends with a `volumes:` block whose own two-space keys would
        # otherwise read as services named `database` and `state`.
        if line.strip() and not line.startswith(" "):
            break
        if re.match(r"^ {2}\S", line) and line.rstrip().endswith(":"):
            current = line.strip().rstrip(":")
            blocks[current] = []
        elif current:
            blocks[current].append(line)
    return {name: "\n".join(lines) for name, lines in blocks.items()}


def test_every_role_is_present_and_none_of_them_is_root():
    """One uid per role was the entire point. The image sets no `config.User`,
    so a service that forgets `user:` runs as root and silently rejoins the
    arrangement this split replaced."""
    blocks = _service_blocks()
    assert set(blocks) == set(ROLES), f"unexpected services: {sorted(blocks)}"
    uids = {}
    for role, block in blocks.items():
        found = re.search(r'^\s+user:\s*"(\d+):(\d+)"', block, re.M)
        assert found, f"{role} names no user and would run as root"
        assert found.group(1) != "0", f"{role} runs as root"
        uids[role] = found.group(1)
    assert len(set(uids.values())) == len(ROLES), f"roles share a uid: {uids}"


def test_the_push_receiver_reaches_no_account_data_and_no_kms():
    """The process Google posts to is the most exposed and needs the least.

    No database volume, because it does not resolve the address it receives --
    that reads the manifest and the mail role does it. No guest-agent socket,
    which is the sharp one: that socket is unauthenticated and GetKey takes a
    caller-supplied derivation path, so anything that can open it derives this
    app's sealing key regardless of which uid it runs as."""
    hook = _service_blocks()["hook"]
    assert "dstack.sock" not in hook, "the push receiver can reach the KMS"
    assert not re.search(r"^\s+-\s+database:", hook, re.M), (
        "the push receiver can read the account store")


def test_no_role_holds_a_secret_it_has_no_use_for():
    """The reason to split the environment at all, asserted per direction.

    Each name is one a compromise of the wrong role would turn into something:
    SESSION_SECRET mints a login cookie for any account, the Google client
    secret is the widest-blast-radius value in the system, the Telegram token
    reaches every linked chat, and an inference key is someone else's spend on a
    confidential endpoint.

    The inference keys are on the web list because that role no longer decides
    which providers exist. It asks the mail role over `handoff.OP_PROVIDERS` and
    gets catalog names back, so a key reappearing here is that round trip having
    been quietly replaced by a local read.

    `POLAR_` is on it for the same shape of reason and a wider blast radius:
    POLAR_API_TOKEN is organization-wide, so the web role holding one made a
    parsing bug there reach every customer in the billing org rather than this
    deployment's own accounts. Its three billing calls cross over
    `handoff.OP_CHECKOUT_URL`, `OP_CHECKOUT_CONFIRM` and `OP_PORTAL_URL`."""
    blocks = _service_blocks()
    forbidden = {
        "mail": ["SESSION_SECRET"],
        "web": ["GOOGLE_OAUTH_CLIENT", "TELEGRAM_", "POLAR_",
                "DEEPSEEK_API_KEY", "NEARAI_API_KEY"],
        "hook": ["SESSION_SECRET", "GOOGLE_OAUTH_CLIENT", "TELEGRAM_",
                 "POLAR_", "DEEPSEEK_API_KEY", "NEARAI_API_KEY"],
    }
    for role, names in forbidden.items():
        for name in names:
            assert name not in blocks[role], f"{role} is handed {name}"


def test_supplementary_groups_are_spelled_out_and_match_the_image():
    """A numeric `user:` makes the runtime skip the /etc/group lookup a username
    would trigger, so membership has to be stated as `group_add:` or the
    accounts baked into the image carry none of it and database/ at 2770 is
    unreadable. The numbers are checked against flake.nix because two files
    holding the same gid is exactly how one of them drifts."""
    flake = FLAKE.read_text()
    gids = dict(re.findall(r"(letterlock-(?:data|wake))\s*=\s*(\d+);", flake))
    assert set(gids) == {"letterlock-data", "letterlock-wake"}, gids

    blocks = _service_blocks()
    expected = {
        "mail": {gids["letterlock-data"], gids["letterlock-wake"]},
        # Not letterlock-wake: writing that spool starts a drafting pass against
        # an account of the writer's choosing and spends its co-signer budget.
        "web": {gids["letterlock-data"]},
        # Not letterlock-data, which is what keeps the account list out of reach.
        "hook": {gids["letterlock-wake"]},
    }
    for role, want in expected.items():
        line = re.search(r"^\s+group_add:\s*\[(.*)\]", blocks[role], re.M)
        assert line, f"{role} states no group_add and would have no membership"
        assert set(re.findall(r"\d+", line.group(1))) == want, (
            f"{role} group_add does not match flake.nix")


_ENV_NAME = re.compile(r"^\s+([A-Z][A-Z0-9_]*):", re.M)


def _common_env():
    """The `x-common` anchor every service merges in."""
    text = COMPOSE.read_text()
    anchor = text.split("environment: &common-env", 1)
    assert len(anchor) == 2, "compose file has no common-env anchor"
    return set(_ENV_NAME.findall(anchor[1].split("\nservices:", 1)[0]))


def _role_env(role):
    """Every variable name a role's container is handed."""
    block = _service_blocks()[role]
    own = block.split("environment:", 1)
    assert len(own) == 2, f"{role} names no environment block"
    return set(_ENV_NAME.findall(own[1])) | _common_env()


@pytest.fixture
def only(monkeypatch):
    """Run with exactly one role's environment and nothing else.

    TEE_REQUIRED is set because that is the condition being modelled: inside the
    CVM `secrets.load()` reads no file and `oauth_app.load_keys()` refuses the
    one on the volume, so a developer's own .env cannot make a role look
    provisioned when its compose block does not provision it."""
    every = set().union(*(_role_env(r) for r in ROLES))

    def apply(role):
        for name in every:
            monkeypatch.delenv(name, raising=False)
        for name in _role_env(role):
            monkeypatch.setenv(name, "0" if name == "POLAR_SANDBOX" else "x")
        monkeypatch.setenv("TEE_REQUIRED", "1")

    return apply


@pytest.mark.parametrize("role", ROLES)
def test_each_role_is_handed_what_its_boot_gate_asks_for(only, role):
    """The compose file and `secrets.REQUIRED_BY_ROLE` are one statement read
    from two sides, and they were not: the gate asked every role for the union
    of the box's secrets, so mail failed on SESSION_SECRET, web on four, and no
    container in the enclave could boot at all. Failing closed is not a
    vulnerability, but the repair it invites is widening these blocks, which is
    the partition RTMR3 measures.

    Read forwards here -- everything the role's gate asks for is in its own
    block -- so adding a check to a role without handing that role the value is
    caught in the suite rather than in a CVM."""
    only(role)
    assert secrets.missing(role) == []


def test_no_role_is_provisioned_for_another_role_s_work():
    """The partition read backwards. Without it the test above passes on a
    compose file that hands every container everything, which is the shape this
    split replaced."""
    assert set(secrets.REQUIRED_BY_ROLE) == set(ROLES), "roles have drifted"
    for role in ROLES:
        others = set().union(*(set(_role_env(r)) for r in ROLES if r != role))
        assert not others <= _role_env(role), (
            f"{role} is handed every other role's environment")


def test_the_image_offers_no_role_that_starts_everything():
    """The shape this replaced: four processes, one uid, one environment holding
    every secret. Leaving a combined role in the entrypoint would leave that one
    compose edit away, and the edit would still measure as a valid image."""
    flake = FLAKE.read_text()
    entry = flake.split("email-bot-entrypoint", 1)[1]
    cases = re.findall(r"^\s{12}(\w+)\)", entry, re.M)
    assert cases == list(ROLES), f"entrypoint roles are {cases}"
