"""Each measured image carries what its role runs, and nothing else.

Code in an image is code an attacker with execution in that container can call,
and a dependency bump touching code that never runs there still changes the
measurement. So each role's file list is derived from the entry points flake.nix
starts for that role rather than described as a pattern over filenames.

The pattern it replaced was wrong in both directions. It shipped `cosigner/`
whole -- the outer key derivation, the request policy, the audit store -- into
the one machine that is supposed to hold ciphertext and not keys, plus the
billing webhook and poller and the by-hand tools. And it
shipped no data file at all, because a filter for `.py` and `.css` matches
neither `default_voice.md` nor `inference_allowlist.json` nor a favicon.

Now the list is per role, so the guarantees below are asserted per role too --
including that the Pub/Sub receiver, the most exposed and least privileged
container, carries none of the inference, custody or billing code that the mail
role's imports pull in.
"""

import ast

from deploy import render_image_manifest
from tools import reachability

ROLES = render_image_manifest.ROLES

# Trees that exist to be run by hand by an operator, or to test. None of them
# belongs in a measured image, and `tests/test_lint.py` skips the subprocess
# checks for the first two on exactly that basis, so the two statements have to
# agree.
NOT_IN_THE_IMAGE = ("deploy/", "tests/", "tools/", "docs/")

# Ways to start another program, and ways to run text as code. The enclave is a
# measured image whose whole claim is that what runs inside it is what was
# built; a module that shells out or evals runs something the measurement never
# covered. Nothing shipped does either today.
FORBIDDEN_IMPORTS = {"subprocess", "pty", "commands", "popen2"}

# Bare names only. `exec` and `eval` are matched as `ast.Name` and the rest as
# whole dotted chains, because an attribute matched on its last name alone reads
# every `re.compile` in the tree as the builtin.
FORBIDDEN_NAMES = {"eval", "exec"}
FORBIDDEN_CHAINS = {
    "os.system", "os.popen", "os.execv", "os.execve", "os.execvp", "os.execvpe",
    "os.spawnv", "os.spawnve", "os.spawnl", "os.fork", "os.forkpty",
    "platform.popen", "commands.getoutput", "commands.getstatusoutput",
}


def _listed_files():
    """Every file any role's image carries, with the roles that carry it. The
    two rules below hold per image, so the subject is the union rather than one
    role's list."""
    out = {}
    for role in ROLES:
        for rel in render_image_manifest.render_paths(role):
            out.setdefault(rel, []).append(role)
    return out


def _listed_modules():
    for rel, roles in _listed_files().items():
        if rel.endswith(".py"):
            source = (render_image_manifest.paths.REPO_ROOT / rel).read_text()
            yield rel, roles, ast.parse(source)


def _chain(node):
    """`a.b.c` for an attribute access, or the bare name, or None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def test_committed_manifest_matches_what_the_entry_points_reach():
    current = render_image_manifest.MANIFEST_FILE.read_text()
    assert render_image_manifest.render() == current, (
        "deploy/phala/image_files.nix is stale; run "
        "`python -m deploy.render_image_manifest`"
    )


def test_every_listed_file_exists():
    """A renamed asset drops out of an image with no error anywhere else."""
    for role in ROLES:
        for rel in render_image_manifest.render_paths(role):
            assert (render_image_manifest.paths.REPO_ROOT / rel).is_file(), (
                f"{rel} is in the {role} image manifest but not in the tree")


def test_no_role_carries_more_of_the_cosigner_than_its_wire_contract():
    """The split is the product: the co-signer holds the outer wrapping key and
    decides each request, the enclave holds the ciphertext. Only the wire
    contract belongs in any enclave image."""
    for role in ROLES:
        listed = set(render_image_manifest.render_paths(role))
        cosigner_files = {rel for rel in listed if rel.startswith("cosigner/")}
        assert cosigner_files <= {"cosigner/__init__.py", "cosigner/protocol.py"}, (
            f"the {role} image carries more of the co-signer than its wire "
            f"contract: {sorted(cosigner_files)}"
        )


def test_the_egress_proxy_is_in_its_own_image_and_no_other():
    """It ships because the enclave now runs it, and it ships into exactly one
    image -- the `egress` role, on the two networks docker-compose.yml defines,
    with the mail role on the internal one alone.

    The per-role split is what lets both halves of that be true at once. While
    the image was shared, running the proxy in the enclave meant an HTTP CONNECT
    proxy in the same filesystem as the code that reads mail, which is why it was
    deliberately absent then; now the container holding the network carries the
    proxy and the allowlist and nothing else carries them at all."""
    egress = set(render_image_manifest.render_paths("egress"))
    assert "backend/daemons/egress_proxy.py" in egress
    assert "backend/egress.py" in egress
    # That the enclave starts it, read where it is now stated: the compose
    # `command:`, in the file whose hash is measured. It used to be a branch of
    # the entrypoint `case` in flake.nix.
    assert "backend.daemons.egress_proxy" in reachability.enclave_roots()
    for role in ROLES:
        if role == "egress":
            continue
        listed = set(render_image_manifest.render_paths(role))
        assert "backend/daemons/egress_proxy.py" not in listed, role


def test_the_proxy_carries_the_allowlist_and_nothing_that_derives_it():
    """The reason it is a container and not a thread in the mail daemon: the
    process holding the network must not be the one holding the API keys, and
    under a per-role image that becomes a statement about the filesystem and not
    only about the uid and the environment.

    That statement was false when the split landed. `backend/egress.py` derived
    the allowlist at runtime from the modules that name the hosts, and
    `calendar_public` reaches `account` and through it the co-signer client,
    `secrets_checks`, billing and the inference client -- so the image was 39
    files, and the container with the only route off the host held the custody
    stack in order to compute thirteen strings. The derivation moved to
    `deploy/render_egress_allowlist.py`, which ships into no image, and the
    proxy reads `backend/egress_allowlist.json`.

    So this is two assertions that only hold together: the list is there, and
    what would have produced it is not."""
    egress = set(render_image_manifest.render_paths("egress"))
    assert "backend/egress_allowlist.json" in egress, (
        "the proxy has no allowlist to read and would refuse every tunnel")
    forbidden = {
        "backend/custody/keyring.py",
        "backend/custody/client.py",
        "backend/custody/tokens.py",
        "backend/custody/wrapping.py",
        "backend/accounts/account.py",
        "backend/integrations/llm_client.py",
        "backend/integrations/telegram.py",
        "backend/integrations/inference_attestation.py",
        "backend/billing/billing.py",
        "backend/secrets_checks.py",
        "backend/tee/tee_boot.py",
        "backend/drafting/agentic_drafter.py",
        "backend/integrations/gmail_gcal/gmail_api.py",
        "backend/integrations/gmail_gcal/google_client.py",
    }
    leaked = forbidden & egress
    assert not leaked, f"the proxy image carries what it must not: {sorted(leaked)}"


def test_the_receiver_carries_none_of_the_mail_roles_reach():
    """The step this pins: the Pub/Sub receiver's one use of `secrets` is
    `load()`, so once the presence checks that fan out to inference, Telegram,
    billing and custody moved to `backend.secrets_checks`, none of that code is
    on the receiver's import graph. Its image is a JWT verifier and a spool
    writer, and carrying the custody stack or the inference client would be a
    regression back toward the receiver reaching what it must never hold."""
    hook = set(render_image_manifest.render_paths("hook"))
    forbidden = {
        "backend/custody/keyring.py",
        "backend/custody/tokens.py",
        "backend/custody/wrapping.py",
        "backend/custody/client.py",
        "backend/integrations/llm_client.py",
        "backend/integrations/telegram.py",
        "backend/integrations/inference_attestation.py",
        "backend/billing/billing.py",
        "backend/accounts/account.py",
        "backend/secrets_checks.py",
    }
    leaked = forbidden & hook
    assert not leaked, f"the receiver image carries mail-role code: {sorted(leaked)}"


def test_the_data_files_each_role_reads_are_listed_for_it():
    """The half the old filter got wrong in the other direction: a role that
    reaches a data file's reader must carry the file. The web role serves the
    static assets; the mail and web roles both render the default voice."""
    web = set(render_image_manifest.render_paths("web"))
    for rel in render_image_manifest.DATA_FILES:
        if render_image_manifest.DATA_FILES[rel] == "frontend.web_server":
            assert rel in web, f"{rel} is read by web and not in its image"


def test_no_operator_tooling_or_test_reaches_the_image():
    """True today because the manifest is derived from what starts, so this
    states it as a rule rather than as a coincidence that holds.

    It is also the premise `tests/test_lint.py` runs bandit on: the subprocess
    checks are skipped for `deploy/` and `tools/` because those are run by hand
    by an operator and are not in the image. If one ever were, that skip would
    be covering code inside the measurement."""
    for rel, roles in _listed_files().items():
        assert not rel.startswith(NOT_IN_THE_IMAGE), (
            f"{rel} is operator tooling or a test and must not be in the "
            f"measured image, and the {sorted(roles)} manifest lists it"
        )


def test_nothing_in_the_image_can_start_another_program():
    """The measurement covers the image's own files. A shipped module that
    shells out, or that runs a string as code, runs something it does not cover,
    and there is no reason for anything in the enclave to do either: every
    `subprocess` import in this tree is in `deploy/` or `tests/`.

    Read from the manifest rather than from a package list, so the subject is
    exactly what the image carries."""
    offences = []
    for rel, _roles, tree in _listed_modules():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in FORBIDDEN_IMPORTS:
                        offences.append(f"{rel}:{node.lineno} imports {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "").split(".")[0] in FORBIDDEN_IMPORTS:
                    offences.append(f"{rel}:{node.lineno} imports from {node.module}")
            elif isinstance(node, ast.Call):
                chain = _chain(node.func)
                if chain in FORBIDDEN_CHAINS or (
                        isinstance(node.func, ast.Name) and chain in FORBIDDEN_NAMES):
                    offences.append(f"{rel}:{node.lineno} calls {chain}()")
    assert not offences, (
        "the measured image would carry a way to run code the measurement does "
        "not cover:\n" + "\n".join(offences)
    )
