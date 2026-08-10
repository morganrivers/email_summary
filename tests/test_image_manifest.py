"""The measured image carries what the enclave runs, and nothing else.

Code in the image is code an attacker with execution inside the enclave can
call, and a dependency bump touching code that never runs there still changes
the measurement. So the file list is derived from the entry points flake.nix
starts rather than described as a pattern over filenames.

The pattern it replaced was wrong in both directions. It shipped `cosigner/`
whole -- the outer key derivation, the request policy, the audit store -- into
the one machine that is supposed to hold ciphertext and not keys, plus the
egress proxy, the billing webhook and poller and the by-hand tools. And it
shipped no data file at all, because a filter for `.py` and `.css` matches
neither `default_voice.md` nor `inference_allowlist.json` nor a favicon: the
first account without its own voice profile would have asserted, no confidential
provider could have been authorized, and every page would have 500'd on its own
icon.
"""

import ast

from deploy import render_image_manifest

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


def _listed_modules():
    for rel in render_image_manifest.render_paths():
        if rel.endswith(".py"):
            yield rel, ast.parse((render_image_manifest.paths.REPO_ROOT / rel).read_text())


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
    """A renamed asset drops out of the image with no error anywhere else."""
    for rel in render_image_manifest.render_paths():
        assert (render_image_manifest.paths.REPO_ROOT / rel).is_file(), (
            f"{rel} is in the image manifest but not in the tree")


def test_the_cosigners_keys_and_policy_are_not_in_the_image():
    """The split is the product: the co-signer holds the outer wrapping key and
    decides each request, the enclave holds the ciphertext. Shipping that code
    into the enclave does not hand over the key, but it puts the one package
    that is supposed to live under a different operator inside the image the
    other operator builds. Only the wire contract belongs here."""
    listed = set(render_image_manifest.render_paths())
    cosigner_files = {rel for rel in listed if rel.startswith("cosigner/")}
    assert cosigner_files == {"cosigner/__init__.py", "cosigner/protocol.py"}, (
        f"the enclave image carries more of the co-signer than its wire "
        f"contract: {sorted(cosigner_files)}"
    )


def test_the_egress_proxy_is_not_in_the_image():
    """It is the box's control, it runs under its own uid there, and no entry
    point in flake.nix starts it. In the image it would be an HTTP CONNECT
    proxy sitting in the address space that reads mail."""
    listed = set(render_image_manifest.render_paths())
    assert "backend/daemons/egress_proxy.py" not in listed
    assert "backend/egress.py" not in listed


def test_the_data_files_the_enclave_reads_are_all_listed():
    """The half the old filter got wrong in the other direction."""
    listed = set(render_image_manifest.render_paths())
    for rel in render_image_manifest.DATA_FILES:
        assert rel in listed, f"{rel} is read at runtime and is not in the image"


def test_no_operator_tooling_or_test_reaches_the_image():
    """True today because the manifest is derived from what starts, so this
    states it as a rule rather than as a coincidence that holds.

    It is also the premise `tests/test_lint.py` runs bandit on: the subprocess
    checks are skipped for `deploy/` and `tools/` because those are run by hand
    by an operator and are not in the image. If one ever were, that skip would
    be covering code inside the measurement."""
    for rel in render_image_manifest.render_paths():
        assert not rel.startswith(NOT_IN_THE_IMAGE), (
            f"{rel} is operator tooling or a test and must not be in the "
            f"measured image"
        )


def test_nothing_in_the_image_can_start_another_program():
    """The measurement covers the image's own files. A shipped module that
    shells out, or that runs a string as code, runs something it does not cover,
    and there is no reason for anything in the enclave to do either: every
    `subprocess` import in this tree is in `deploy/` or `tests/`.

    Read from the manifest rather than from a package list, so the subject is
    exactly what the image carries."""
    offences = []
    for rel, tree in _listed_modules():
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
