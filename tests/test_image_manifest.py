"""Each measured image carries what its role runs, and nothing else.

Code in an image is code an attacker with execution in that container can call,
and a dependency bump touching code that never runs there still changes the
measurement. So each role's file list is derived from the entry points flake.nix
starts for that role rather than described as a pattern over filenames.

The pattern it replaced was wrong in both directions. It shipped `cosigner/`
whole -- the outer key derivation, the request policy, the audit store -- into
the one machine that is supposed to hold ciphertext and not keys, plus the
egress proxy, the billing webhook and poller and the by-hand tools. And it
shipped no data file at all, because a filter for `.py` and `.css` matches
neither `default_voice.md` nor `inference_allowlist.json` nor a favicon.

Now the list is per role, so the guarantees below are asserted per role too --
including that the Pub/Sub receiver, the most exposed and least privileged
container, carries none of the inference, custody or billing code that the mail
role's imports pull in.
"""

from deploy import render_image_manifest

ROLES = render_image_manifest.ROLES


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


def test_no_role_carries_the_egress_proxy():
    """It is the box's control, it runs under its own uid there, and no enclave
    entry point starts it. In an image it would be an HTTP CONNECT proxy sitting
    in the address space that reads mail."""
    for role in ROLES:
        listed = set(render_image_manifest.render_paths(role))
        assert "backend/daemons/egress_proxy.py" not in listed, role
        assert "backend/egress.py" not in listed, role


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
