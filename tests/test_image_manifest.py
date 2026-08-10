"""The measured image carries what the enclave runs, and nothing else.

Code in the image is code an attacker with execution inside the enclave can
call, and a dependency bump touching code that never runs there still changes
the measurement. So the file list is derived from the entry points flake.nix
starts rather than described as a pattern over filenames.

The pattern it replaced was wrong in both directions. It shipped `cosigner/`
whole -- the outer key derivation, the request policy, the audit store -- into
the one machine that is supposed to hold ciphertext and not keys, plus the
billing webhook and poller and the by-hand tools. And it
shipped no data file at all, because a filter for `.py` and `.css` matches
neither `default_voice.md` nor `inference_allowlist.json` nor a favicon: the
first account without its own voice profile would have asserted, no confidential
provider could have been authorized, and every page would have 500'd on its own
icon.
"""

from deploy import render_image_manifest


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


def test_the_egress_proxy_is_in_the_image_and_is_its_own_role():
    """It ships because the enclave now runs it, and it runs in a container of
    its own -- the `egress` role in flake.nix, on the two networks
    docker-compose.yml defines, with the mail role on the internal one alone.

    It was deliberately absent while nothing started it, and the reason it was
    absent is the reason it must not be a thread: an HTTP CONNECT proxy in the
    address space that reads mail is the process holding the network being the
    process holding the keys."""
    listed = set(render_image_manifest.render_paths())
    assert "backend/daemons/egress_proxy.py" in listed
    assert "backend/egress.py" in listed
    assert "egress)" in render_image_manifest.paths.REPO_ROOT.joinpath(
        "flake.nix").read_text()


def test_the_data_files_the_enclave_reads_are_all_listed():
    """The half the old filter got wrong in the other direction."""
    listed = set(render_image_manifest.render_paths())
    for rel in render_image_manifest.DATA_FILES:
        assert rel in listed, f"{rel} is read at runtime and is not in the image"
