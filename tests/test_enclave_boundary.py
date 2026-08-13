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
import shutil
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from backend import roles, secrets_checks

REPO = Path(__file__).resolve().parent.parent
COMPOSE = REPO / "deploy" / "phala" / "docker-compose.yml"
FLAKE = REPO / "flake.nix"
PUBLISH = REPO / "deploy" / "phala" / "build_and_publish.sh"

# Imported, not restated. This list used to be written out in six places -- the
# flake's `case`, its usage line, the publish script, the manifest renderer, the
# boot gate's table and here -- and a role added to five of them ships with no
# image, or no boot gate, or no push.
ROLES = roles.ROLES


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


def _uncommented():
    """The compose file with its comment lines removed.

    Every rule below is stated in prose at the top of that file, so a check
    reading the raw text cannot tell the statement of a rule from a breach of
    it -- and a test that forbids naming the thing it forbids is one nobody can
    write the rule in front of."""
    return "\n".join(line for line in COMPOSE.read_text().splitlines()
                     if not line.lstrip().startswith("#"))


def _anchor():
    """The `x-common` block every role merges. Read as its own block so a rule
    can ask "does this role have it" and get the same answer whether the line
    is in the anchor or in the service."""
    text = COMPOSE.read_text()
    return text.split("\nx-common:", 1)[1].split("\nservices:", 1)[0]


def _list_under(block, key):
    """The list items under `key:` in one block, unquoted.

    Ends at the next line indented no further than the key, which is what keeps
    a service's `tmpfs:` out of its `volumes:` when both are lists of strings
    that begin with a slash. Comment lines are skipped, so the prose above each
    of these keys cannot read as an entry under it."""
    items, depth = [], None
    for line in block.splitlines():
        stripped = line.strip()
        if depth is None:
            found = re.match(r"^(\s*)%s:\s*$" % re.escape(key), line)
            if found:
                depth = len(found.group(1))
            continue
        if not stripped or stripped.startswith("#"):
            continue
        if len(line) - len(line.lstrip()) <= depth:
            break
        assert stripped.startswith("- "), (
            f"{key} holds {stripped!r}, which this reader does not parse")
        items.append(stripped[2:].strip().strip('"').strip("'"))
    return items


def _settings_for(role):
    """The scalar `key: value` settings a role ends up with, its own winning
    over the anchor's. Scalars only; lists are `_list_under`."""
    pairs = {}
    for block in (_anchor(), _service_blocks()[role]):
        for line in block.splitlines():
            found = re.match(r"^\s{2,4}([a-z_]+):\s+(\S+)\s*$", line)
            if found:
                pairs[found.group(1)] = found.group(2)
    return pairs


def _networks_of(block):
    """The networks one service attaches to, in the order it names them."""
    found = re.search(r"^\s+networks:\n((?:\s+-\s+\S+\n?)+)", block, re.M)
    return tuple(re.findall(r"-\s+(\S+)", found.group(1))) if found else ()


def _common_env_names():
    """Names in the `x-common-env` anchor. A role that merges it receives them,
    so a per-role check that ignored them would call TEE_REQUIRED absent."""
    text = COMPOSE.read_text()
    block = text.split("\nx-common:", 1)[1].split("\nservices:", 1)[0]
    return set(re.findall(r"^\s+([A-Z][A-Z0-9_]*):\s", block, re.M))


def _env_names(role):
    """Every variable a role's container actually receives.

    The merge is read rather than assumed: `egress` deliberately does not take
    `*common-env`, because the one container holding a route off the host must
    not be pointed at itself, and a check that handed it the anchor anyway would
    be reading a partition the compose file does not describe."""
    block = _service_blocks()[role]
    own = set(re.findall(r"^\s+([A-Z][A-Z0-9_]*):\s", block, re.M))
    return (own | _common_env_names()) if "*common-env" in block else own


def test_each_role_is_handed_exactly_the_secrets_its_boot_gate_demands():
    """The gate and the partition, checked against each other.

    These are the two halves of one fact and they used to be written
    independently: `tee_boot` applied the whole-box `secrets_checks.REQUIRED`,
    which no role satisfies -- `web` is deliberately handed no inference key and
    `mail` no SESSION_SECRET -- so both crash-looped on first boot behind
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
            gaps = secrets_checks.missing(role)
        assert gaps == [], f"the {role} container cannot pass its own boot gate: {gaps}"


def test_no_enclave_role_is_asked_for_the_polar_webhook_secret():
    """The one check no role can satisfy, named rather than quietly dropped.

    No role is a Polar receiver: entitlement in the enclave is
    `confirm_checkout()` plus the reconcile, both in `mail` and both reading
    Polar's API. So there is no correct value of POLAR_WEBHOOK_SECRET to inject,
    and a gate that demanded one would be unsatisfiable by construction."""
    assert secrets_checks.polar_webhook_configured in secrets_checks.ROLE_EXEMPT
    for role in ROLES:
        assert "POLAR_WEBHOOK_SECRET" not in _env_names(role)


GATED_ROLES = {"mail": "backend/daemons/daemon_loop.py",
               "web": "frontend/web_server.py"}
UNGATED_ROLES = {"hook": "backend/daemons/gmail_hook_server.py",
                 "egress": "backend/daemons/egress_proxy.py",
                 "ingress": "backend/daemons/ingress_proxy.py"}


def test_the_two_data_holding_roles_gate_themselves_before_they_serve():
    """A gate given no role cannot know what to require, so it refuses. It used
    to be a separate `python -m` in the entrypoint shell, which passed the
    compose `command:` through; with no shell, each role calls it from its own
    `__main__` and takes the role from the module that was started.

    Asserted in the `__main__` block and not merely somewhere in the file: a
    gate imported and never called is the failure this is looking for."""
    for role, path in GATED_ROLES.items():
        block = (REPO / path).read_text().split('if __name__ == "__main__":')[1]
        assert "tee_boot.gate_or_exit(_role)" in block, (
            f"{role} serves without attesting first")
        assert "procwatch.role_of(__spec__.name)" in block, (
            f"{role} gates against a role it did not derive from its own module")


def test_the_three_ungated_roles_do_not_pretend_to_attest():
    """`hook`, `egress` and `ingress` are deliberately handed no guest-agent
    socket, so a gate here could only fail closed or no-op. They hold nothing to
    release: no account, no secret, no key. A gate call in one of them would be
    a container that cannot start rather than a container that is safer."""
    for role, path in UNGATED_ROLES.items():
        assert "gate_or_exit" not in (REPO / path).read_text(), (
            f"{role} runs a gate it has no socket for")


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


def test_each_role_runs_its_own_image():
    """One image per role now, each carrying only its reachable code (flake.nix,
    deploy/phala/image_files.nix). The compose names a distinct image per service
    and each is measured into the compose-hash, so the receiver's image cannot
    silently gain the mail role's custody stack the way one shared image left it
    able to. A service that inherited a single shared image, or two services
    naming the same one, would undo that."""
    blocks = _service_blocks()
    images = {}
    for role, block in blocks.items():
        found = re.search(r"^\s+image:\s*(\S+)", block, re.M)
        assert found, f"{role} names no image of its own"
        images[role] = found.group(1)
    assert len(set(images.values())) == len(ROLES), (
        f"roles share an image: {images}")
    for role, ref in images.items():
        assert f"tee-email-bot-{role}" in ref, (
            f"{role} runs {ref}, not its own tee-email-bot-{role} image")


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
        # The one with the network. It is a separate account for the same
        # reason it is on the box: the process holding the network must not be
        # the one holding the API keys.
        "egress": ["SESSION_SECRET", "GOOGLE_OAUTH_CLIENT", "TELEGRAM_",
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
        # No group at all: it mounts nothing and reads no file of ours.
        "egress": set(),
    }
    for role, want in expected.items():
        line = re.search(r"^\s+group_add:\s*\[(.*)\]", blocks[role], re.M)
        if not want:
            assert not line, f"{role} needs no group and states one"
            continue
        assert line, f"{role} states no group_add and would have no membership"
        assert set(re.findall(r"\d+", line.group(1))) == want, (
            f"{role} group_add does not match flake.nix")


def test_no_role_is_provisioned_for_another_role_s_work():
    """The partition read backwards. Without it
    `test_each_role_is_handed_exactly_the_secrets_its_boot_gate_demands` passes
    on a compose file that hands every container everything, which is the shape
    this split replaced."""
    assert set(secrets_checks.REQUIRED_BY_ROLE) == set(ROLES), "roles have drifted"
    for role in ROLES:
        others = set().union(*(_env_names(r) for r in ROLES if r != role))
        assert not others <= _env_names(role), (
            f"{role} is handed every other role's environment")


def test_every_service_starts_one_module_and_no_service_starts_everything():
    """The shape this replaced: four processes, one uid, one environment holding
    every secret. It used to be kept away by an entrypoint `case` with no
    combined branch; now there is no dispatcher to add one to, and the argv is
    here in the measured file.

    One module per service, and the interpreter directly: a `command:` that ran
    a shell would be back to a parent process `execguard.py`'s filter is not
    installed in, whatever the shell went on to start."""
    blocks = _service_blocks()
    assert set(blocks) == set(ROLES), f"unexpected services: {sorted(blocks)}"
    started = {}
    for role, block in blocks.items():
        found = re.findall(r'^\s+command:\s*(\[.*\])\s*$', block, re.M)
        assert len(found) == 1, f"{role} has {len(found)} command: lines"
        argv = re.findall(r'"([^"]*)"', found[0])
        assert argv[:2] == ["python", "-m"] and len(argv) == 3, (
            f"{role} does not start one module directly: {argv}")
        started[role] = argv[2]
    assert len(set(started.values())) == len(ROLES), (
        f"two roles start the same module: {started}")


def test_the_image_carries_no_shell_and_no_entrypoint_to_dispatch_with():
    """`command:` above is the whole argv only while the image sets neither, and
    the reason to want that is one process per container. The shell is gone from
    `contents` for the same reason: it is the program a payload wants, and an
    image that does not carry it cannot be made to run it."""
    text = FLAKE.read_text()
    assert "Entrypoint = [ ];" in text, "the image sets an Entrypoint again"
    # Comments stripped, for the reason the security_opt rule below reads the
    # parsed value: every rule here is explained in prose beside the thing it
    # governs, and a check reading raw text cannot tell a rule from a breach.
    code = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    assert "writeShellApplication" not in code, "an entrypoint script is back"
    assert "bashInteractive" not in code, "the images carry a shell again"
    assert "/bin/sh" not in code, "passwd promises a shell the image lacks"


def test_nothing_mounts_the_decrypted_environment():
    """The first of the two rules this file's header states, and until now the
    header was the whole of the enforcement.

    dstack decrypts the *entire* secret set to
    /dstack/.host-shared/.decrypted-env with a bare fs::write and no mode. The
    partition below is interpolation -- a container gets what its own
    `environment:` block names -- so one bind mount of that directory hands
    every role every secret and leaves each service block reading exactly as it
    does today."""
    assert "/dstack/.host-shared" not in _uncommented()


def test_the_interpolated_names_are_the_deploy_time_checklist():
    """The second rule the header states, and the half of it this repository
    can check.

    Every `${NAME}` below is read out of the *compose process* environment,
    which holds only what `allowed_envs` in app-compose.json names -- and that
    file is set by the phala CLI at deploy time and is not in this tree. A name
    interpolated here and missing there decrypts to nothing and the role starts
    unconfigured, which for `SESSION_SECRET` or a Polar credential is a service
    that comes up looking fine.

    So the list lives here, one place, and the failure prints it: adding a
    variable to a service block is what makes this test fail, and the message is
    what gets pasted into `allowed_envs`."""
    names = set(re.findall(r"\$\{([A-Z_][A-Z0-9_]*)", _uncommented()))
    expected = {
        "EXPECTED_COMPOSE_HASH",
        "DEEPSEEK_API_KEY", "NEARAI_API_KEY",
        "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID",
        "GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET",
        "POLAR_API_TOKEN", "POLAR_ORGANIZATION_ID", "POLAR_PRODUCT_ID",
        "POLAR_CHECKOUT_URL", "POLAR_SANDBOX",
        "SESSION_SECRET", "SESSION_SECRET_PREVIOUS",
        "LETTERLOCK_HOST", "LETTERLOCK_API_HOST",
        "LETTERLOCK_COSIGNER_URL", "WEB_TRUSTED_PROXIES",
        "WEBHOOK_AUD", "PUBSUB_SERVICE_ACCOUNT",
    }
    assert names == expected, (
        "the compose file interpolates a different set of names than this test "
        "records. Every one of them has to be in `allowed_envs` in "
        f"app-compose.json at deploy time:\n{sorted(names)}"
    )


def test_the_only_host_path_any_role_mounts_is_the_guest_agent_socket():
    """The general form of the rule above: a bind mount reaches out of the
    partition, so each one has to be a decision. Today there is one, and `hook`
    deliberately does not have it."""
    for role, block in _service_blocks().items():
        for entry in _list_under(block, "volumes"):
            source = entry.split(":", 1)[0]
            if not source.startswith("/"):
                continue
            assert source == "/var/run/dstack.sock", (
                f"{role} bind-mounts {source} from the guest filesystem")


def test_no_role_asks_for_privilege_the_partition_would_not_survive():
    """Each of these is a one-line way back to the arrangement the split
    replaced -- a shared namespace, an ambient capability, or the host's own
    network stack, which would put every role back outside the proxy."""
    text = _uncommented()
    for setting in ("privileged:", "cap_add:", "network_mode:", "pid:",
                    "userns_mode:", "devices:"):
        assert setting not in text, f"the compose file asks for {setting}"


def test_security_opt_is_checked_by_value_and_not_forbidden_outright():
    """`security_opt:` used to be on the list above, as a bare substring.

    The intent was right -- `seccomp:unconfined` and `apparmor:unconfined` are
    each a one-word way out of the runtime's own sandbox -- but banning the key
    banned `no-new-privileges:true` with it, so the rule forbade the fix as
    firmly as the breach and the only way to harden the file was to edit the
    test that guards it. A control whose test cannot tell tightening from
    loosening is a control nobody tightens. So the values are the subject."""
    allowed = {"no-new-privileges:true"}
    for name, block in list(_service_blocks().items()) + [("x-common", _anchor())]:
        for value in _list_under(block, "security_opt"):
            assert value in allowed, (
                f"{name} sets security_opt {value!r}, which is not one of "
                f"{sorted(allowed)}")


def test_every_role_runs_in_the_same_sandbox():
    """The lines that make a container hard to run a program in, checked per
    role rather than trusted to the anchor: a service that stops merging
    `*common` keeps its image and its secrets and silently loses these.

    They are not the exec control -- `execguard.py` is, because seccomp is the
    only thing that denies `execve` and this deploy path cannot carry a profile.
    These cover what that filter is not installed in, and they are what makes a
    payload that does get written have nowhere to be written to."""
    for role in ROLES:
        settings = _settings_for(role)
        assert settings.get("read_only") == "true", (
            f"{role} does not run on a read-only rootfs")
        assert settings.get("pids_limit"), f"{role} has no pids_limit"
        assert _list_under(_service_blocks()[role], "cap_drop") == ["ALL"] or \
            _list_under(_anchor(), "cap_drop") == ["ALL"], (
                f"{role} does not drop all capabilities")
        assert "no-new-privileges:true" in (
            _list_under(_service_blocks()[role], "security_opt")
            + _list_under(_anchor(), "security_opt")), (
                f"{role} does not set no-new-privileges")


def test_every_writable_path_outside_a_volume_is_noexec():
    """With `read_only` above, a container's writable paths are its volumes and
    its tmpfs mounts. Docker's local volume driver takes no mount options, so
    `database/` and `state/` cannot be made noexec and are not claimed to be --
    `backend/procwatch.py` is what covers a payload run from one. Everything
    here can be, and a writable path a payload can be executed from is the path
    it will be written to."""
    for role in ROLES:
        entries = _list_under(_service_blocks()[role], "tmpfs")
        assert entries, f"{role} has no tmpfs, so read_only leaves it no /tmp"
        targets = [entry.split(":", 1)[0] for entry in entries]
        assert "/tmp" in targets, f"{role} has no writable /tmp"
        for entry in entries:
            for option in ("noexec", "nosuid", "nodev"):
                assert option in entry, f"{role} mounts {entry!r} without {option}"


def test_the_attestation_tmpfs_is_private_to_the_role_that_writes_it():
    """It held a client certificate's private key at mode 0777, excused by
    there being no second process in the container to read it. That excuse is
    exactly what an intrusion removes, and it is the assumption this file must
    never rest on. The long `volumes:` tmpfs syntax takes only `size` and
    `mode`, which is why the directory is declared in the service-level `tmpfs:`
    key instead: that one takes `uid` and `gid`, so the mount is owned by the
    role rather than by root and world-writable."""
    owners = {"mail": 10001, "web": 10002}
    assert "0777" not in _uncommented(), (
        "a mode 0777 is back in the compose file")
    for role in ROLES:
        entries = {entry.split(":", 1)[0]: entry
                   for entry in _list_under(_service_blocks()[role], "tmpfs")}
        if role not in owners:
            assert "/app/attestation" not in entries, (
                f"{role} runs no attestation gate and should hold no key")
            continue
        entry = entries.get("/app/attestation")
        assert entry, f"{role} runs the gate and has nowhere to put its key"
        assert "mode=0700" in entry, f"{role} attestation tmpfs is not 0700"
        assert f"uid={owners[role]}" in entry, (
            f"{role} attestation tmpfs is not owned by its own uid")
        assert f"gid={owners[role]}" in entry, (
            f"{role} attestation tmpfs is not grouped to its own uid")


def test_every_image_is_pinned_by_digest_or_is_the_pre_publish_placeholder():
    """One `image:` line per role, and each names bytes rather than a name
    somebody can repoint. A mutable tag or a `${VAR}` would let the operator swap
    an image under a compose file whose hash is what the KMS gates secret release
    on, so the digest is the difference between the measurement meaning the code
    and the measurement meaning the intention. Per role, because one image per
    role means one chance per role to leave a swappable name behind.

    The placeholder is allowed because it is what the tree carries before the
    first push, and `build_and_publish.sh --push` rewrites these exact lines;
    that script is checked here so what it targets cannot drift from what this
    test reads. It keys its rewrite on the image name itself, which carries the
    role, and matches either form of reference -- which is what lets it re-pin a
    digest as readily as a first tag. It used to key on the `command:` line
    below, back when that line was the role name."""
    images = re.findall(r"^\s*image:\s*(\S+)", COMPOSE.read_text(), re.M)
    assert len(images) == len(ROLES), (
        f"expected one image reference per role, found {images}")
    for ref in images:
        if not re.fullmatch(r"tee-email-bot-(?:%s):latest" % "|".join(ROLES), ref):
            assert re.fullmatch(r"[^\s$]+@sha256:[0-9a-f]{64}", ref), (
                f"the compose image {ref!r} is neither the pre-publish "
                "placeholder nor a literal registry digest")
    publish = PUBLISH.read_text()
    assert 'LOCAL="tee-email-bot-$role:latest"' in publish
    # The script reads its role list out of the generated manifest rather than
    # carrying one. A hand-written list here is how a role reaches the compose
    # file and never the registry, which fails at boot in a CVM instead of in
    # this suite.
    assert not re.search(r"^ROLES=\(\w", publish, re.M), (
        "build_and_publish.sh hardcodes a role list instead of deriving it")
    assert "image_files.nix" in publish, (
        "build_and_publish.sh does not derive its roles from the manifest")


def test_the_push_actually_writes_a_digest_into_every_service(tmp_path):
    """What the rule above forbids, checked by running the rewrite rather than
    by reading it.

    It is checked this way because reading it was not enough. The rewrite
    substituted the registry ref into the perl program text, a registry ref
    contains `@sha256`, and perl read that as an array interpolation in the
    replacement -- so every `--push` wrote `repo:<64 hex>`, a mutable tag, into
    the one line whose whole job is to name bytes. The compose still parsed and
    the CVM would still have booted something."""
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(COMPOSE.read_text())
    body = re.search(r"^pin_compose\(\) \{\n(.*?)^\}", PUBLISH.read_text(),
                     re.M | re.S)
    assert body, "pin_compose is no longer a shell function in the publish script"
    digest = "sha256:" + "ab" * 32
    script = "pin_compose() {\n%s}\n" % body.group(1) + "".join(
        f'pin_compose {role} "ghcr.io/x/tee-email-bot-{role}@{digest}"\n'
        for role in ROLES)
    run = subprocess.run(["bash", "-c", script], env={"COMPOSE_FILE": str(compose),
                                                      "PATH": os.environ["PATH"]},
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stderr

    # Matched by name and not by position: which service comes first in the file
    # is not a thing this test should have an opinion about, and a pin that
    # landed on the wrong service is exactly what it must catch.
    pinned = dict(re.findall(r"^\s*image:\s*\S+?-(\w+)@(\S+)",
                             compose.read_text(), re.M))
    assert set(pinned) == set(ROLES), (
        f"pinned {sorted(pinned)}, expected every role in {sorted(ROLES)}")
    for role, ref in pinned.items():
        assert ref == digest, (
            f"{role} was pinned to {ref!r}, which is not the digest it was given")


@pytest.mark.skipif(not shutil.which("docker"), reason="needs a docker daemon")
@pytest.mark.parametrize("role", ROLES)
def test_the_tmpfs_options_do_what_the_file_says_they_do(tmp_path, role):
    """The rules above read the compose file as text, which proves the lines are
    written and not that docker honours them. This mounts each role's real tmpfs
    entries in a throwaway container and reads /proc/mounts back.

    Worth the docker dependency because the two claims being made are easy to
    write and wrong: that `noexec` reaches a tmpfs declared this way, and that
    `uid=`/`gid=` are accepted at all -- the long `volumes:` tmpfs syntax takes
    neither, which is why /app/attestation sat at 0777 owned by root. Skipped
    rather than failed without a daemon, since it checks the runtime's
    behaviour rather than this repository's contents."""
    entries = _list_under(_service_blocks()[role], "tmpfs")
    compose = tmp_path / "docker-compose.yml"
    targets = [entry.split(":", 1)[0] for entry in entries]
    compose.write_text(
        "services:\n"
        "  probe:\n"
        "    image: busybox:latest\n"
        "    command: [\"sh\", \"-c\", \"cat /proc/mounts; stat -c '%%n %%a %%u %%g' %s\"]\n"
        "    tmpfs:\n" % " ".join(sorted(set(targets)))
        + "".join(f'      - "{entry}"\n' for entry in entries))
    run = subprocess.run(
        ["docker", "compose", "-f", str(compose), "run", "--rm", "probe"],
        capture_output=True, text=True, timeout=180)
    if run.returncode != 0:
        pytest.skip(f"docker unavailable to this test: {run.stderr[-300:]}")
    mounts = {line.split()[1]: line.split()[3].split(",")
              for line in run.stdout.splitlines() if line.startswith("tmpfs ")}
    # The mode, uid and gid are read off the directory rather than out of
    # /proc/mounts: the kernel omits an option there when it matches the tmpfs
    # default, so /tmp at the mode it asked for reports no mode at all. What is
    # being claimed is the state of the directory anyway.
    stated = {}
    for line in run.stdout.splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[0].startswith("/"):
            stated[parts[0]] = (parts[1], parts[2], parts[3])
    for entry in entries:
        target, options = entry.split(":", 1)
        assert target in mounts, f"{target} was not mounted at all"
        for option in ("noexec", "nosuid", "nodev"):
            assert option in mounts[target], (
                f"docker did not apply {option} to {target}")
        mode, uid, gid = stated[target]
        for option in options.split(","):
            key, _, value = option.partition("=")
            got = {"mode": mode.lstrip("0"), "uid": uid, "gid": gid}.get(key)
            if got is not None:
                assert got == value.lstrip("0"), (
                    f"{target} has {key}={got}, not the {value} it asked for")


def test_no_role_that_holds_data_has_a_route_off_the_host():
    """The enclave's answer to `IPAddressDeny=any` on the box, and now a real
    one for every role rather than for `mail` alone.

    `inner` is internal, so docker installs no route off the host for it: a
    container attached to it alone reaches the internet through `egress` or not
    at all. That was only ever true of `mail`. `web` and `hook` had to be on
    `edge` too, because a published port on an internal-only network never
    receives forwarded ingress and both must be reached from outside the CVM --
    and `edge` is a route out, so for those two the allowlist was a pair of
    environment variables their own HTTP clients honoured. An attacker with code
    execution does not honour them, which made it configuration and not a
    control, on precisely the two roles facing the internet.

    `ingress` closed it by taking the published ports, so this asserts the thing
    that is now true: every role holding a token, a session secret or an
    account's data is on `inner` and nothing else, and publishes nothing."""
    text = COMPOSE.read_text()
    assert re.search(r"^  inner:\n    internal: true$", text, re.M), (
        "the inner network is not internal, so nothing is enforced")
    blocks = _service_blocks()
    for role in sorted(roles.DATA_ROLES):
        assert _networks_of(blocks[role]) == ("inner",), (
            f"{role} holds data and can leave the host without the proxy")
        assert not re.search(r"^\s+ports:", blocks[role], re.M), (
            f"{role} publishes a port, which is what being on `inner` forbids")
    for role in sorted(roles.NETWORK_ROLES):
        assert set(_networks_of(blocks[role])) == {"inner", "edge"}, (
            f"{role} is the network's job and is not on both networks")


def test_only_the_ingress_is_reachable_from_outside_the_cvm():
    """One way in, and it is the container that holds nothing.

    The published ports are the CVM's whole attack surface, so which container
    owns them is the question. `egress` must not: it is the one with a route
    out, and publishing a port on it would let the outside reach the thing whose
    entire job is leaving. Everything else holds data."""
    blocks = _service_blocks()
    publishing = {role for role, block in blocks.items()
                  if re.search(r"^\s+ports:", block, re.M)}
    assert publishing == {"ingress"}, (
        f"something other than the ingress is published: {sorted(publishing)}")

    ingress = blocks["ingress"]
    for port in sorted(roles.INGRESS_ROUTES):
        assert re.search(rf'^\s+-\s+"{port}:{port}"$', ingress, re.M), (
            f"port {port} is in roles.INGRESS_ROUTES and is not published")
    assert 'INGRESS_PROXY_BIND: "0.0.0.0"' in ingress, (
        "the forwarder binds loopback and the published ports reach nothing")


def test_the_ingress_holds_nothing_worth_reaching_it_for():
    """It is the first process an attacker talks to, so what it has is what a
    bug in it is worth. No volume, so no account store and no spool; no
    guest-agent socket, which is the sharp one, since that socket is
    unauthenticated and GetKey takes a caller-supplied derivation path; no
    group, so nothing shared; and no secret beyond the flag that stops
    backend/secrets.py reading a file."""
    ingress = _service_blocks()["ingress"]
    assert not re.search(r"^\s+volumes:", ingress, re.M), "the ingress mounts a volume"
    assert "dstack.sock" not in ingress, "the ingress can reach the KMS"
    assert not re.search(r"^\s+group_add:", ingress, re.M), "the ingress states a group"
    assert secrets_checks.REQUIRED_BY_ROLE["ingress"] == (), (
        "the ingress is gated on a secret it should not have")
    for name in ("SESSION_SECRET", "GOOGLE_OAUTH_CLIENT", "TELEGRAM_", "POLAR_",
                 "DEEPSEEK_API_KEY", "NEARAI_API_KEY", "PROXY"):
        assert name not in ingress.replace("INGRESS_PROXY_BIND", ""), (
            f"the ingress is handed {name}")


def test_every_role_that_runs_our_http_clients_is_pointed_at_the_proxy():
    """Enforcement is the network; this is the half that decides where the
    traffic actually goes. Both cases of every variable, because the clients in
    this tree disagree about which they read -- the same six lines as
    deploy/hetzner/hardening.conf."""
    text = COMPOSE.read_text()
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        assert f'{name}: "http://egress:8792"' in text, f"{name} is not set"
    egress = _service_blocks()["egress"]
    assert "PROXY" not in egress.replace("EGRESS_PROXY_BIND", ""), (
        "the proxy is pointed at itself")
    assert 'EGRESS_PROXY_BIND: "0.0.0.0"' in egress, (
        "the proxy binds loopback and no other container can reach it")


def test_the_web_role_is_reachable_and_says_who_may_forward_for_it():
    """A UI bound to the container's own loopback answers nobody, and one that
    believes an X-Forwarded-For from an unnamed peer lets a client choose what
    the audit log says about them.

    It binds 0.0.0.0 and publishes nothing: the interface it answers on is the
    internal network, where `ingress` is what connects to it.
    `LETTERLOCK_TRUSTED_PROXIES` is where the second question is decided, and
    empty is still the right default -- the forwarder parses nothing, so it adds
    no X-Forwarded-For to believe, and the peer is a container rather than a
    browser either way."""
    web = _service_blocks()["web"]
    assert 'WEB_HOST: "0.0.0.0"' in web
    assert "LETTERLOCK_TRUSTED_PROXIES" in web
    upstream = {host for host, _port in roles.INGRESS_ROUTES.values()}
    assert "web" in upstream, "nothing forwards to the web role and it publishes nothing"
