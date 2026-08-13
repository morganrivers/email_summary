"""What of this repository can actually be reached, and from where.

Code that ships is code an attacker can call, and in the measured enclave it is
also code whose next security bump changes the image hash for nothing. This
answers which modules and which functions are reachable from the entry points
that really start, so the two questions that look alike stay apart:

  * unreachable  -- nothing calls it. A deletion candidate.
  * untested     -- reachable but never executed by the suite. A test to write.

Coverage alone cannot tell those apart, which is why a coverage-only pruner
deletes working code the moment a test errors during collection. Three signals
decide instead, and all three have to agree before anything is even proposed:

  1. reachability, from an import + call graph rooted at the real entry points
     (``deploy/hetzner/*.service`` for the box, ``flake.nix`` for the enclave);
  2. coverage, read from ``coverage json`` and keyed on the same dotted names
     coverage itself uses (``Class.method``, ``outer.inner``);
  3. an explicit keep list, because a framework callback and a feature-gated
     path are called by code this graph cannot see.

Nothing here deletes anything. It prints, and a person decides.

    python -m tools.reachability                       # both worlds, no coverage
    python -m tools.reachability --coverage cov.json   # add the dynamic signal
    python -m tools.reachability --world enclave --modules

Produce the coverage input with::

    coverage run --branch --source=backend,frontend,cosigner,tools,deploy -m pytest tests/
    coverage json -o cov.json

The call graph is deliberately over-approximate: an attribute call this cannot
resolve marks *every* function of that name reachable. Over-marking costs a
deletion candidate; under-marking costs working code, so the bias only points
one way.
"""

import argparse
import ast
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from backend import paths

REPO_ROOT = paths.REPO_ROOT

PACKAGES = ("backend", "frontend", "cosigner", "tools", "deploy")

SKIP_DIRS = {"__pycache__", "venv", ".git", "tests", "docs", "database",
             "state", ".pytest_cache", ".obsidian", "phala"}

UNIT_DIR = REPO_ROOT / "deploy" / "hetzner"
FLAKE = REPO_ROOT / "flake.nix"
COMPOSE = REPO_ROOT / "deploy" / "phala" / "docker-compose.yml"

# The `python -m <module>` argument out of a unit file, and what one is allowed
# to look like. Both are public because `deploy/preflight.py` reads the same
# lines out of the same files: it interpolates the name it finds into a string
# an interpreter then executes, so the shape has to be checked there, and two
# modules with two ideas of what a module name is would be two answers to one
# question.
EXEC_MODULE_RE = re.compile(r"^ExecStart=.*?\s-m\s+(\S+)", re.MULTILINE)
MODULE_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
# A service's `command:` in the compose file, which is the enclave's whole argv:
# the images set no Entrypoint and no Cmd. Anchored on `command:` rather than on
# `python -m` anywhere, so a module named in a comment is not a root.
_COMPOSE_MODULE = re.compile(
    r'^\s*command:\s*\[\s*"python"\s*,\s*"-m"\s*,\s*"([A-Za-z_][\w.]*)"\s*\]',
    re.MULTILINE)


def check_module_name(module, source):
    """`module`, or `ValueError` naming where the bad one came from.

    A unit file that runs something other than a dotted module is a broken
    repository rather than one unit to skip, so this stops the caller."""
    if not MODULE_NAME_RE.fullmatch(module):
        raise ValueError(
            f"{source} runs `-m {module}`, which is not a dotted module name"
        )
    return module


FRAMEWORK_METHODS = {
    "do_GET", "do_POST", "do_PUT", "do_DELETE", "do_HEAD", "do_OPTIONS",
    "log_message", "log_error", "handle", "handle_one_request", "setup",
    "finish", "server_bind", "server_close", "verify_request",
    "operate", "validate", "operator_name", "operator_type",
}

KEEP_NAME_RE = re.compile(r"^(reset_\w*for_test|main|__\w+__)$")

KEEP_FUNCTIONS = {
    "backend.masking.pseudonymizer:_build_engines":
        "the Presidio path, uninstalled by default and switched on by "
        "uncommenting three pins; nothing calls it on a box without the analyzer",
    "backend.masking.pseudonymizer:_pseudonymize_patterns":
        "the other half of the same switch: the regex-only path a box without "
        "the analyzer runs",
}

KEEP_MODULES = {
    "backend.masking.masking_eval.evaluator":
        "measures masking recall against the committed corpus; run by hand, "
        "not by a service",
    "backend.masking.masking_eval.run":
        "entry point for the recall measurement above",
    "tools.render_brand":
        "regenerates the committed brand assets; run by hand so the server "
        "never renders at runtime",
    "tools.render_pages":
        "renders the static marketing pages by hand",
    "tools.reachability":
        "this module",
    "deploy.check_egress":
        "proves the egress sandbox is on; run on the box after a deploy",
    "deploy.audit":
        "the dependency advisory audit, run from CI and by hand",
    "deploy.render_caddyfile":
        "generates the Caddy config, run by hand before a reload",
    "deploy.render_pyproject":
        "generates the image's dependency manifest, run by hand and in CI",
    "deploy.requirements":
        "parses the dependency lists for the two renderers above",
    "deploy.preflight":
        "run on the box by deploy.sh, not by a unit",
    "backend.accounts.whois":
        "deliberately a command rather than a route: maps a handle back to a "
        "person",
    "backend.accounts.seed_owner":
        "seeds the first account, run once by hand",
    "backend.accounts.unlink_telegram":
        "detaches a chat without the confirmation the rule needs; a command and "
        "never a route, for a user who has lost the Telegram account itself",
    "backend.custody.rotate":
        "moves every record onto a new co-signer key, run by hand at rotation",
}


def module_name(path):
    rel = path.relative_to(REPO_ROOT).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def source_files():
    """Every first-party module, packages plus the loose top-level ones."""
    found = []
    for package in PACKAGES:
        root = REPO_ROOT / package
        if not root.is_dir():
            continue
        for path in root.rglob("*.py"):
            if SKIP_DIRS & set(path.relative_to(REPO_ROOT).parts):
                continue
            found.append(path)
    for path in REPO_ROOT.glob("*.py"):
        found.append(path)
    assert found, f"no first-party source found under {REPO_ROOT}"
    return sorted(set(found))


def test_files():
    """The suite, named the way it imports itself. pytest puts ``tests/`` on the
    path, so ``harness`` is the module name there, not ``tests.harness``."""
    root = REPO_ROOT / "tests"
    if not root.is_dir():
        return {}
    return {p: p.stem for p in sorted(root.rglob("*.py"))}


class Module:
    """One first-party module: its imports, its functions, and what each calls.

    Names are the ones coverage uses, so the two signals join without a
    translation step -- that mismatch is what makes a bare-name pruner silently
    skip every method it was pointed at."""

    def __init__(self, path, name, known):
        self.path = path
        self.name = name
        self.tree = ast.parse(path.read_text(), filename=str(path))
        self.known = known
        self.module_aliases = {}
        self.symbol_origins = {}
        self.functions = {}
        self.classes = {}
        self.body_calls = set()
        self.imports = set()
        self._collect_imports()
        self._collect_functions()

    def qualified(self, func):
        return f"{self.name}:{func}"

    def _resolve(self, dotted):
        if dotted in self.known:
            return dotted
        head, _, tail = dotted.rpartition(".")
        if head in self.known:
            return head, tail
        return None

    def _record_import(self, dotted, alias, imported_name=None):
        if dotted in self.known:
            self.imports.add(dotted)
            if imported_name is None:
                self.module_aliases[alias] = dotted
            else:
                self.symbol_origins[alias] = (dotted, imported_name)
            return True
        return False

    def _collect_imports(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self._record_import(a.name, a.asname or a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    continue
                base = node.module or ""
                for a in node.names:
                    alias = a.asname or a.name
                    submodule = f"{base}.{a.name}"
                    if self._record_import(submodule, alias):
                        continue
                    self._record_import(base, alias, imported_name=a.name)

    def _collect_functions(self):
        def visit(node, prefix, container_calls):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    name = f"{prefix}{child.name}"
                    calls = set()
                    self.functions[name] = calls
                    for deco in child.decorator_list:
                        container_calls.update(_called_names(deco))
                    visit(child, f"{name}.", calls)
                    calls.update(_called_names(child, skip_nested=True))
                elif isinstance(child, ast.ClassDef):
                    name = f"{prefix}{child.name}"
                    external = [b for b in child.bases
                                if _dotted(b) and not _dotted(b).startswith(
                                    tuple(f"{p}." for p in PACKAGES))]
                    self.classes[name] = bool(external) or not child.bases
                    for base in child.bases:
                        container_calls.update(_called_names(base))
                    visit(child, f"{name}.", container_calls)
                else:
                    container_calls.update(_called_names(child, skip_nested=True))

        visit(self.tree, "", self.body_calls)


def _dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _called_names(node, skip_nested=False):
    """Every name this node calls, as ``('attr', 'mod.fn')`` or ``('name', 'fn')``.

    Also counts a bare reference to a function, because a callback handed to
    another function is a call the caller makes later. Missing those is how a
    tool proposes deleting an ``on_iteration`` hook."""
    out = set()
    stack = [node]
    first = True
    while stack:
        cur = stack.pop()
        if not first and skip_nested and isinstance(
                cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        first = False
        if isinstance(cur, ast.Call):
            dotted = _dotted(cur.func)
            if dotted and "." in dotted:
                out.add(("attr", dotted))
            elif dotted:
                out.add(("name", dotted))
        elif isinstance(cur, ast.Attribute):
            dotted = _dotted(cur)
            if dotted and "." in dotted:
                out.add(("attr", dotted))
        elif isinstance(cur, ast.Name):
            out.add(("name", cur.id))
        for child in ast.iter_child_nodes(cur):
            stack.append(child)
    return out


class Graph:
    def __init__(self):
        named = {p: module_name(p) for p in source_files()}
        self.shipped = set(named.values())
        named.update(test_files())
        known = set(named.values())
        self.modules = {}
        for path, name in named.items():
            mod = Module(path, name, known)
            self.modules[name] = mod
        self.by_function_name = defaultdict(set)
        for name, mod in self.modules.items():
            if name not in self.shipped:
                continue
            for func in mod.functions:
                self.by_function_name[func.rpartition(".")[2]].add(
                    mod.qualified(func))

    def reachable_modules(self, roots):
        for root in roots:
            assert root in self.modules, (
                f"entry point {root!r} is not a first-party module; the unit "
                f"files and flake.nix are the only source of roots")
        seen = set()
        queue = list(roots)
        while queue:
            name = queue.pop()
            if name in seen:
                continue
            seen.add(name)
            mod = self.modules.get(name)
            if mod is None:
                continue
            queue.extend(mod.imports)
            for parent in _parents(name):
                if parent in self.modules:
                    queue.append(parent)
        return seen

    def _targets(self, mod, kind, dotted, scope=""):
        """What a call site could mean, resolved innermost scope outwards.

        The scope walk is what makes a nested helper resolvable: a callback
        defined inside a function and handed to ``re.sub`` is named ``phone``
        at the call site and ``_pseudonymize_patterns.phone`` in the coverage
        report, and a resolver comparing those two directly finds nothing and
        calls a live function dead."""
        if kind == "name":
            for prefix in _scopes(scope):
                if f"{prefix}{dotted}" in mod.functions:
                    return {mod.qualified(f"{prefix}{dotted}")}
                if f"{prefix}{dotted}" in mod.classes:
                    return self._class_targets(mod, f"{prefix}{dotted}")
            origin = mod.symbol_origins.get(dotted)
            if origin:
                return self._in_module(origin[0], origin[1])
            return set()
        head, _, attr = dotted.rpartition(".")
        target_module = mod.module_aliases.get(head)
        if target_module:
            return self._in_module(target_module, attr)
        origin = mod.symbol_origins.get(head)
        if origin:
            return self._in_module(origin[0], f"{origin[1]}.{attr}")
        for prefix in _scopes(scope):
            if f"{prefix}{head}" in mod.classes or f"{prefix}{dotted}" in mod.functions:
                return {mod.qualified(f"{prefix}{dotted}")}
        return set(self.by_function_name.get(attr, ()))

    def _in_module(self, module_name_, attr):
        target = self.modules.get(module_name_)
        if target is None:
            return set()
        if attr in target.functions:
            return {target.qualified(attr)}
        if attr in target.classes:
            return self._class_targets(target, attr)
        return set()

    def _class_targets(self, mod, cls):
        out = set()
        for func in mod.functions:
            if func == f"{cls}.__init__" or (
                    func.startswith(f"{cls}.") and mod.classes.get(cls)):
                out.add(mod.qualified(func))
        return out

    def reachable_functions(self, modules):
        queue = []
        for name in modules:
            mod = self.modules.get(name)
            if mod is None:
                continue
            for kind, dotted in mod.body_calls:
                queue.extend(self._targets(mod, kind, dotted))
        seen = set()
        while queue:
            qual = queue.pop()
            if qual in seen:
                continue
            seen.add(qual)
            module_part, _, func = qual.partition(":")
            mod = self.modules.get(module_part)
            if mod is None:
                continue
            scope = f"{func}." if func else ""
            for kind, dotted in mod.functions.get(func, ()):
                queue.extend(self._targets(mod, kind, dotted, scope))
        return seen

    def all_functions(self):
        out = set()
        for name in self.shipped:
            mod = self.modules[name]
            for func in mod.functions:
                out.add(mod.qualified(func))
        return out


def _parents(name):
    parts = name.split(".")
    return [".".join(parts[:i]) for i in range(1, len(parts))]


def _scopes(scope):
    """Enclosing scopes of a call site, innermost first, module last."""
    out = []
    parts = [p for p in scope.split(".") if p]
    for i in range(len(parts), 0, -1):
        out.append(".".join(parts[:i]) + ".")
    out.append("")
    return out


def box_roots():
    """What systemd actually starts, read from the unit files rather than
    listed here, so a new unit is a new root without touching this."""
    assert UNIT_DIR.is_dir(), f"no unit directory at {UNIT_DIR}"
    roots = set()
    for unit in UNIT_DIR.glob("*.service"):
        m = EXEC_MODULE_RE.search(unit.read_text())
        if m:
            roots.add(check_module_name(m.group(1), unit.name))
    assert roots, f"no ExecStart -m module found in {UNIT_DIR}"
    return roots


def enclave_roots():
    """What the measured images start: one `command:` per service, read out of
    docker-compose.yml.

    This used to read flake.nix, because the images ran a shell there that
    dispatched on a role name. There is no such shell: each `command:` is the
    argv, and it is in the file whose hash is measured into RTMR3 -- so the
    roots are now read from the same statement the enclave is attested against.

    Comments are stripped first. A file whose comments explain the partition
    talks about running modules, and a root read out of prose is a module
    shipped because someone described it."""
    assert COMPOSE.is_file(), f"no compose file at {COMPOSE}"
    code = "\n".join(line.split("#", 1)[0]
                     for line in COMPOSE.read_text().splitlines())
    roots = set(_COMPOSE_MODULE.findall(code))
    assert roots, f"no `command: [\"python\", \"-m\", ...]` found in {COMPOSE}"
    return roots


def command_roots():
    """Modules a person runs by hand and CI runs on a schedule. Nothing starts
    them, so no graph finds them, which is exactly why they are written down
    with a reason each instead of inferred."""
    return set(KEEP_MODULES)


def test_roots(graph):
    """The suite, as its own root set. What only the tests reach is dead in
    production but not safe to delete, and calling that out is the difference
    between "delete this" and "delete this and the test that pins it"."""
    return set(test_files().values()) & set(graph.modules)


WORLDS = {"box": box_roots, "enclave": enclave_roots}


def keep_reason(graph, qual):
    module_part, _, func = qual.partition(":")
    if module_part in KEEP_MODULES:
        return KEEP_MODULES[module_part]
    if qual in KEEP_FUNCTIONS:
        return KEEP_FUNCTIONS[qual]
    leaf = func.rpartition(".")[2]
    if KEEP_NAME_RE.match(leaf):
        return "an entry point or a test hook, called by name from outside"
    if leaf in FRAMEWORK_METHODS:
        return "a framework callback: the base class calls it, not our code"
    mod = graph.modules[module_part]
    cls = func.rpartition(".")[0]
    if cls and mod.classes.get(cls) and leaf.startswith("__"):
        return "a dunder on a class with an external base"
    return None


class Coverage:
    """The dynamic signal, keyed the way coverage keys it."""

    def __init__(self, path):
        data = json.loads(Path(path).read_text())
        self.executed = {}
        for filename, entry in data["files"].items():
            name = module_name((REPO_ROOT / filename).resolve())
            for func, stats in entry.get("functions", {}).items():
                if not func:
                    continue
                self.executed[f"{name}:{func}"] = bool(
                    stats["summary"]["covered_lines"])
        assert self.executed, f"{path} carries no per-function coverage"

    def ran(self, qual):
        return self.executed.get(qual)


def module_scope(graph):
    """Which modules each deployment target actually loads.

    The enclave's answer is the interesting one: it is the file list the
    measured image should carry, and every module outside it is code that
    changes the image hash without ever running there."""
    print("=== module scope per deployment target")
    scoped = {}
    for world in sorted(WORLDS):
        roots = WORLDS[world]()
        scoped[world] = graph.reachable_modules(roots)
        print(f"    {world:8} {len(scoped[world]):3} modules "
              f"from {len(roots)} entry points")
    box_only = scoped["box"] - scoped["enclave"]
    enclave_only = scoped["enclave"] - scoped["box"]
    neither = graph.shipped - scoped["box"] - scoped["enclave"]
    print(f"\n--- loaded on the box, never in the enclave ({len(box_only)})")
    for name in sorted(box_only):
        print(f"    {name}")
    if enclave_only:
        print(f"\n--- loaded in the enclave, never on the box ({len(enclave_only)})")
        for name in sorted(enclave_only):
            print(f"    {name}")
    print(f"\n--- no service loads these anywhere ({len(neither)})")
    for name in sorted(neither):
        note = KEEP_MODULES.get(name)
        print(f"    {name}" + (f"\n        {note}" if note else ""))
    return scoped


def report(graph, coverage):
    service_roots = box_roots() | enclave_roots()
    command = command_roots() & set(graph.modules)
    tests = test_roots(graph)

    service_mods = graph.reachable_modules(service_roots)
    live_mods = graph.reachable_modules(service_roots | command)
    test_mods = graph.reachable_modules(tests)

    service_funcs = graph.reachable_functions(service_mods)
    live_funcs = graph.reachable_functions(live_mods)
    test_funcs = graph.reachable_functions(test_mods)

    dead, test_only, command_only, untested, kept = [], [], [], [], []
    for qual in sorted(graph.all_functions()):
        reason = keep_reason(graph, qual)
        if qual in service_funcs:
            if coverage is not None and coverage.ran(qual) is False:
                untested.append(qual)
            continue
        if reason:
            kept.append((qual, reason))
            continue
        if qual in live_funcs:
            command_only.append(qual)
        elif qual in test_funcs or (coverage is not None and coverage.ran(qual)):
            test_only.append(qual)
        else:
            dead.append(qual)

    print(f"\n=== functions, against {len(service_roots)} service entry points, "
          f"{len(command)} hand-run commands and {len(tests)} test modules")

    print(f"\n--- DELETION CANDIDATES: nothing reaches these, not even a test "
          f"({len(dead)})")
    for qual in dead:
        print(f"    {qual}")

    print(f"\n--- only the suite reaches these: dead in production, but a test "
          f"pins them ({len(test_only)})")
    for qual in test_only:
        print(f"    {qual}")

    print(f"\n--- only a hand-run command reaches these: not in either service "
          f"({len(command_only)})")
    for qual in command_only:
        print(f"    {qual}")

    if coverage is not None:
        print(f"\n--- TEST GAPS: a service reaches these and nothing executed "
              f"them ({len(untested)})")
        for qual in untested:
            print(f"    {qual}")
    else:
        print("\n--- TEST GAPS: pass --coverage to get this list")

    print(f"\n--- kept by rule, never proposed ({len(kept)})")
    for qual, reason in kept:
        print(f"    {qual}\n        {reason}")
    return 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--coverage", help="a coverage json report")
    parser.add_argument("--modules", action="store_true",
                        help="only the per-target module scope")
    args = parser.parse_args(argv)
    graph = Graph()
    module_scope(graph)
    if args.modules:
        return 0
    coverage = Coverage(args.coverage) if args.coverage else None
    return report(graph, coverage)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
