"""The Hetzner box and the measured enclave image install the same dependencies.

They are provisioned by different tools -- pip from requirements.txt, uv2nix
from deploy/phala/pyproject.toml -- and when those were maintained separately
they drifted: the image pinned presidio, which is off by default because it
does not fit a 2 GB confidential VM, and it lacked `standardwebhooks` and
`certifi`. Nothing failed until a service imported something that existed on
one box and not the other, which is the failure this file turns into a test.
"""

import pytest

from deploy import render_pyproject
from deploy import requirements


def test_committed_pyproject_matches_requirements():
    current = requirements.PYPROJECT_FILE.read_text()
    assert render_pyproject.render(current, requirements.pins()) == current, (
        "deploy/phala/pyproject.toml is stale; run "
        "`python -m deploy.render_pyproject` and then `cd deploy/phala && uv lock`"
    )


def test_commented_out_pins_are_installed_nowhere():
    """The analyzer is opt-in, and the opt-out has to reach both environments:
    a pin commented out here must not appear in the image's manifest."""
    optional = [line.lstrip("#").strip()
                for line in requirements.REQUIREMENTS_FILE.read_text().splitlines()
                if line.startswith("#") and "==" in line and " " not in line.strip("# ")]
    assert optional, "expected at least the presidio block to be commented out"
    rendered = requirements.PYPROJECT_FILE.read_text()
    for pin in optional:
        name = pin.split("==")[0]
        assert f'"{pin}"' not in rendered, f"{pin} is off in requirements.txt but in the image"
        assert f'"{name}==' not in rendered, f"{name} is off in requirements.txt but in the image"


def test_every_pin_is_exact():
    """A floating version would change the image hash without a source change,
    which breaks the reproducible-build claim rather than merely surprising
    someone. parse() asserts it; this pins that it does."""
    with pytest.raises(AssertionError, match="not a `name==version` pin"):
        requirements.parse("requests>=2.0\n")
    assert requirements.parse("# a comment\n\nrequests==2.34.2\n") == ["requests==2.34.2"]
