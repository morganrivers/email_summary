"""What this app depends on, parsed from requirements.txt.

Two environments install the same code and used to be told about it twice:
`deploy.sh` pip-installs `requirements.txt` on the Hetzner box, and
`deploy/phala/pyproject.toml` feeds uv2nix (`flake.nix`) for the measured
enclave image. They had already drifted -- the image still pinned presidio,
which is off by default precisely because it does not fit a 2 GB confidential
VM, and it was missing `standardwebhooks` and `certifi`. That failure mode is
silent until a service imports something that exists on one box and not the
other.

So requirements.txt is the source and the pyproject dependency list is
generated from it, the same arrangement `deploy/render_caddyfile.py` has with
`backend/site.py`. A commented-out pin is an uninstalled dependency in both
places, which is what makes the analyzer's default off everywhere at once.

    python -m deploy.render_pyproject      # rewrite deploy/phala/pyproject.toml
    (cd deploy/phala && uv lock)           # then re-pin the lock it feeds

`tests/test_requirements.py` fails if the committed pyproject stops matching,
so drift is caught here rather than in an image that is missing a module.

`requirements-dev.txt` is parsed by the same rules and rendered into nothing: it
holds the tools that check this code rather than run it, and the same test fails
if one of its pins turns up in either shipped list.
"""

import re

from backend import paths

REQUIREMENTS_FILE = paths.REPO_ROOT / "requirements.txt"
PYPROJECT_FILE = paths.REPO_ROOT / "deploy" / "phala" / "pyproject.toml"

# Test-only pins, parsed by the same rules and rendered into nothing. They are a
# separate file rather than an extra in the pyproject because that pyproject is
# the image manifest: an extra declared there is a package uv2nix can pull into
# a measured build.
DEV_REQUIREMENTS_FILE = paths.REPO_ROOT / "requirements-dev.txt"

# A requirement line: name, optional extras, then a pinned version. Everything
# here is `==` pinned on purpose (the image is measured, so a floating version
# changes the hash), and this asserts that rather than assuming it.
_PIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9,._-]+\])?==[^\s#]+$")


def parse(text, source=REQUIREMENTS_FILE):
    """The installable pins in a requirements file, in order. Comments and blank
    lines are dropped, which is also how a commented-out optional dependency
    stays out of the generated image."""
    pins = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        assert _PIN.match(line), (
            f"{source.name} line is not a `name==version` pin: {line!r}. "
            "Ranges and URLs cannot be rendered into the measured image's manifest."
        )
        pins.append(line)
    assert pins, f"no dependencies found in {source}"
    return pins


def pins():
    return parse(REQUIREMENTS_FILE.read_text())


def dev_pins():
    """The test-only pins. Never rendered, never installed on the box."""
    return parse(DEV_REQUIREMENTS_FILE.read_text(), DEV_REQUIREMENTS_FILE)


def names(pins_):
    """Just the distribution names, lowercased, for comparing two pin lists."""
    return {pin.split("==")[0].split("[")[0].strip().lower() for pin in pins_}


def main(argv):
    """`python -m deploy.requirements --names` prints what we depend on without
    the versions. That is the weekly compatibility job's whole question: install
    the same distributions unpinned and see whether the code still passes, which
    is what the next security bump will do to you. Stripping the versions
    belongs here rather than in a sed in a workflow file, next to the parser
    that decided what a pin is."""
    print("\n".join(sorted(names(pins())) if "--names" in argv else pins()))
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main(sys.argv[1:]))
