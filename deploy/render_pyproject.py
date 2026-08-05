"""Render deploy/phala/pyproject.toml's dependency list from requirements.txt.

uv2nix reads the pyproject to build the measured enclave image (`flake.nix`),
and pip reads requirements.txt to provision the Hetzner box. One of them has to
be the source; see deploy/requirements.py for why it is requirements.txt.

    python -m deploy.render_pyproject      # rewrite the file in place
    python -m deploy.render_pyproject --check   # exit 1 if it is stale

Only the `dependencies = [...]` array is generated. The rest of the file --
`requires-python`, `[tool.uv]`, any `[tool.uv.sources]` -- is build
configuration rather than a dependency list, so it is edited by hand and left
alone here.

Changing dependencies means re-pinning the lock uv2nix actually consumes:

    (cd deploy/phala && uv lock)
"""

import re
import sys

from deploy import requirements

GENERATED_NOTE = (
    "# Generated from requirements.txt by deploy/render_pyproject.py -- do not\n"
    "# edit this array. Add the pin there, re-render, then `cd deploy/phala &&\n"
    "# uv lock` so the lock this feeds is re-pinned too.\n"
)

_DEPENDENCIES = re.compile(
    r"(?ms)^(?:#[^\n]*\n)*^dependencies\s*=\s*\[.*?^\]\n"
)


def render_array(pins):
    body = "".join(f'    "{pin}",\n' for pin in pins)
    return f"{GENERATED_NOTE}dependencies = [\n{body}]\n"


def render(current, pins):
    """The pyproject text with its dependency array replaced."""
    assert _DEPENDENCIES.search(current), (
        f"no `dependencies = [...]` array in {requirements.PYPROJECT_FILE}"
    )
    return _DEPENDENCIES.sub(lambda _: render_array(pins), current, count=1)


def main(argv):
    current = requirements.PYPROJECT_FILE.read_text()
    rendered = render(current, requirements.pins())
    if "--check" in argv:
        if rendered != current:
            print(
                f"{requirements.PYPROJECT_FILE} is stale; run "
                "`python -m deploy.render_pyproject`",
                file=sys.stderr,
            )
            return 1
        return 0
    requirements.PYPROJECT_FILE.write_text(rendered)
    print(f"wrote {requirements.PYPROJECT_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
