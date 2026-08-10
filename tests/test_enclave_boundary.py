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

import os
import re
from pathlib import Path
from unittest import mock

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


def _common_env_names():
    """Names in the `x-common` anchor every service merges. They are handed to
    all three roles, so a per-role check that ignored them would call
    TEE_REQUIRED absent."""
    text = COMPOSE.read_text()
    block = text.split("\nx-common:", 1)[1].split("\nservices:", 1)[0]
    return set(re.findall(r"^\s+([A-Z][A-Z0-9_]*):\s", block, re.M))


def _env_names(role):
    """Every variable a role's container actually receives."""
    return _common_env_names() | set(
        re.findall(r"^\s+([A-Z][A-Z0-9_]*):\s", _service_blocks()[role], re.M))


def test_each_role_is_handed_exactly_the_secrets_its_boot_gate_demands():
    """The gate and the partition, checked against each other.

    These are the two halves of one fact and they used to be written
    independently: `tee_boot` applied the whole-box `secrets.REQUIRED`, which no
    role satisfies -- `web` is deliberately handed no inference key and `mail`
    no SESSION_SECRET -- so both crash-looped on first boot behind
    `restart: always`. The repair an operator reaches for under that pressure is
    to give every container every variable, which is the partition RTMR3
    measures, undone.

    Answered by running the real checks against an environment holding exactly
    what the compose file interpolates, rather than by a second list of variable
    names here: a list is the drift. Values are dummies because every check asks
    only whether a value arrived."""
    for role in ROLES:
        env = {name: "x" for name in _env_names(role)}
        # `hook` merges the common block and nothing else, so it inherits
        # TEE_REQUIRED from there; spelled out so the intent survives an edit.
        env["TEE_REQUIRED"] = "1"
        with mock.patch.dict(os.environ, env, clear=True):
            gaps = secrets.missing(role)
        assert gaps == [], f"the {role} container cannot pass its own boot gate: {gaps}"


def test_no_enclave_role_is_asked_for_the_polar_webhook_secret():
    """The one check no role can satisfy, named rather than quietly dropped.

    No role is a Polar receiver: entitlement in the enclave is `confirm_checkout()`
    in `web` plus the reconcile in `mail`, both of which read Polar's API. So
    there is no correct value of POLAR_WEBHOOK_SECRET to inject, and a gate that
    demanded one would be unsatisfiable by construction."""
    assert secrets.polar_webhook_configured in secrets.ROLE_EXEMPT
    for role in ROLES:
        assert "POLAR_WEBHOOK_SECRET" not in _env_names(role)


def test_the_gate_runs_per_role_and_the_entrypoint_says_which():
    """A gate given no role cannot know what to require, so it refuses. The
    entrypoint has to pass the compose `command:` through for that to work."""
    flake = FLAKE.read_text()
    assert 'python -m backend.tee.tee_boot "$role"' in flake, (
        "the entrypoint runs the gate without naming the role")


def test_every_role_names_this_deployments_hostnames():
    """`backend/site.py` compiles in the Hetzner hosts, and every externally
    visible URL is built from them. A role left on the defaults sends its users
    to the other box, which holds a different SESSION_SECRET -- so the consent
    round trip either refuses as "did not start in this browser" or lets the box
    exchange the authorization code and take custody of the refresh token.

    Interpolated with no `:-` default on purpose: an unset value must be visibly
    empty rather than quietly the box's hostname."""
    blocks = _service_blocks()
    for role in ("mail", "web"):
        for name in ("LETTERLOCK_HOST", "LETTERLOCK_API_HOST"):
            assert f'{name}: "${{{name}}}"' in blocks[role], (
                f"{role} does not name {name}, or gives it a fallback")


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
    been quietly replaced by a local read."""
    blocks = _service_blocks()
    forbidden = {
        "mail": ["SESSION_SECRET"],
        "web": ["GOOGLE_OAUTH_CLIENT", "TELEGRAM_",
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


def test_the_image_offers_no_role_that_starts_everything():
    """The shape this replaced: four processes, one uid, one environment holding
    every secret. Leaving a combined role in the entrypoint would leave that one
    compose edit away, and the edit would still measure as a valid image."""
    flake = FLAKE.read_text()
    entry = flake.split("email-bot-entrypoint", 1)[1]
    cases = re.findall(r"^\s{12}(\w+)\)", entry, re.M)
    assert cases == list(ROLES), f"entrypoint roles are {cases}"
