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
import subprocess
from pathlib import Path
from unittest import mock

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


def test_the_image_offers_no_role_that_starts_everything():
    """The shape this replaced: four processes, one uid, one environment holding
    every secret. Leaving a combined role in the entrypoint would leave that one
    compose edit away, and the edit would still measure as a valid image."""
    flake = FLAKE.read_text()
    entry = flake.split("email-bot-entrypoint", 1)[1]
    cases = re.findall(r"^\s{12}(\w+)\)", entry, re.M)
    assert cases == list(ROLES), f"entrypoint roles are {cases}"


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
        for source in re.findall(r"^\s+-\s+(/\S+):", block, re.M):
            assert source == "/var/run/dstack.sock", (
                f"{role} bind-mounts {source} from the guest filesystem")


def test_no_role_asks_for_privilege_the_partition_would_not_survive():
    """Each of these is a one-line way back to the arrangement the split
    replaced -- a shared namespace, an ambient capability, or the host's own
    network stack, which would put every role back outside the proxy."""
    text = COMPOSE.read_text()
    for setting in ("privileged:", "cap_add:", "network_mode:", "pid:",
                    "userns_mode:", "devices:", "security_opt:"):
        assert setting not in text, f"the compose file asks for {setting}"


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
    test reads. It keys its rewrite on the `command: ["<role>"]` line below the
    image, which is what lets it re-pin a digest as readily as a first tag."""
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
