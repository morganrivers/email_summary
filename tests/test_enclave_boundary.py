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

REPO = Path(__file__).resolve().parent.parent
COMPOSE = REPO / "deploy" / "phala" / "docker-compose.yml"
FLAKE = REPO / "flake.nix"

ROLES = ("mail", "web", "hook", "egress")


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


def test_the_image_is_pinned_by_digest_or_is_the_pre_publish_placeholder():
    """One `image:` line, and it names bytes rather than a name somebody can
    repoint. A mutable tag or a `${VAR}` would let the operator swap the image
    under a compose file whose hash is what the KMS gates secret release on, so
    the digest is the difference between the measurement meaning the code and
    the measurement meaning the intention.

    The placeholder is allowed because it is what the tree carries before the
    first push, and `build_and_publish.sh --push` rewrites this exact line;
    that script is checked here so the line it targets cannot drift from the
    line this test reads."""
    images = re.findall(r"^\s*image:\s*(\S+)", COMPOSE.read_text(), re.M)
    assert len(images) == 1, f"expected one image reference, found {images}"
    ref = images[0]
    if ref != "tee-email-bot:latest":
        assert re.fullmatch(r"[^\s$]+@sha256:[0-9a-f]{64}", ref), (
            f"the compose image {ref!r} is neither the pre-publish placeholder "
            "nor a literal registry digest")
    publish = (REPO / "deploy" / "phala" / "build_and_publish.sh").read_text()
    assert "LOCAL_IMAGE=\"tee-email-bot:latest\"" in publish
    assert "s##\\1image: $REGISTRY_REF#" in publish


def test_the_mail_role_has_no_route_off_the_host_except_the_proxy():
    """The enclave's answer to `IPAddressDeny=any` on the box, and the reason
    `egress` exists in here at all.

    `inner` is internal, so docker installs no route off the host for it and a
    container attached to it alone reaches the internet through the proxy or not
    at all. `mail` is that container: it publishes no port, so nothing has to
    reach it from outside.

    `web` and `hook` are on `edge` as well, because a published port on an
    internal-only network never receives forwarded ingress -- so for those two
    the allowlist is configuration and not enforcement, which is the header's
    claim and is asserted here rather than left to be read as more than it is."""
    text = COMPOSE.read_text()
    assert re.search(r"^  inner:\n    internal: true$", text, re.M), (
        "the inner network is not internal, so nothing is enforced")
    blocks = _service_blocks()
    assert _networks_of(blocks["mail"]) == ("inner",), (
        "the mail role can leave the host without the proxy")
    assert set(_networks_of(blocks["egress"])) == {"inner", "edge"}
    for role in ("web", "hook"):
        assert "inner" in _networks_of(blocks[role]), (
            f"{role} cannot reach the proxy")
    assert not re.search(r"^\s+ports:", blocks["mail"], re.M), (
        "the mail role publishes a port, which is what its network forbids")
    assert not re.search(r"^\s+ports:", blocks["egress"], re.M), (
        "the proxy is reachable from outside the CVM")


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
    the audit log says about them. Publishing the port is what makes the first
    true; `LETTERLOCK_TRUSTED_PROXIES` is where the second is decided, and
    empty is the honest default until somebody has watched a real CVM."""
    web = _service_blocks()["web"]
    assert 'WEB_HOST: "0.0.0.0"' in web
    assert re.search(r'^\s+-\s+"8790:8790"$', web, re.M), (
        "the web role publishes no port")
    assert "LETTERLOCK_TRUSTED_PROXIES" in web
