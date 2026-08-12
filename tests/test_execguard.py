"""The filter that makes process creation impossible, and the entry points that
install it.

Run in child processes on purpose. A seccomp filter cannot be removed by the
process that installed one, so a test that called `lock_down()` in the runner
would take the rest of the suite with it -- pytest forks, and forking is what
the filter refuses.
"""

import ast
import subprocess  # nosec B404  # test tooling, never in a measured image
import sys
from pathlib import Path

import pytest

import execguard
from deploy import render_image_manifest

REPO = Path(__file__).resolve().parent.parent

# How `subprocess` reports a process the kernel killed with SIGSYS: the negated
# signal number, where a shell would print 128+31.
SIGSYS_EXIT = -31


def _run(body):
    """A child python that locks down and then does something."""
    return subprocess.run(  # nosec B603  # fixed argv, no shell, test-only
        [sys.executable, "-c",
         "import execguard\nexecguard.lock_down(required=True)\n" + body],
        cwd=REPO, capture_output=True, text=True, timeout=60)


def test_the_program_is_well_formed_bpf():
    """Every `struct sock_filter` is eight bytes and the kernel is handed a
    count, so a program that is not a multiple of eight is one the kernel reads
    off the end of."""
    program = execguard._program()
    assert len(program) % 8 == 0
    assert len(program) // 8 == 16


def test_exec_kills_the_process():
    """The whole point. Not an errno the caller can retry around: by the time
    this fires the process is presumed compromised."""
    done = _run("import os\nos.execv('/bin/true', ['/bin/true'])\nprint('ALIVE')")
    assert done.returncode == SIGSYS_EXIT, done
    assert "ALIVE" not in done.stdout


def test_starting_a_subprocess_kills_the_process():
    """The same rule reached the way an attacker would reach it, through the
    library rather than the syscall. `subprocess` is `vfork` plus `execve` and
    both are refused."""
    done = _run("import subprocess\nsubprocess.run(['/bin/true'])\nprint('ALIVE')")
    assert done.returncode == SIGSYS_EXIT, done
    assert "ALIVE" not in done.stdout


def test_fork_kills_the_process():
    done = _run("import os\nos.fork()\nprint('ALIVE')")
    assert done.returncode == SIGSYS_EXIT, done


def test_threads_still_work():
    """The filter has to tell a thread from a process. glibc creates threads
    with `clone3` where it can and falls back to `clone` on ENOSYS, which is
    why `clone3` returns that rather than dying: a filter that killed it would
    take down every threaded server in this tree."""
    done = _run("import threading\n"
                "t = threading.Thread(target=lambda: None)\n"
                "t.start(); t.join()\nprint('THREADS OK')")
    assert done.returncode == 0, done
    assert "THREADS OK" in done.stdout


def test_a_kernel_that_refuses_the_filter_is_refused_back_when_required(monkeypatch):
    """The enclave passes `required=True` and gets a raise, which behind
    `restart: always` is a crash loop and a log line rather than a container
    quietly serving mail with a shell available in it."""
    def refuse():
        raise execguard.ExecGuardUnavailable("no")

    monkeypatch.setattr(execguard, "install", refuse)
    with pytest.raises(execguard.ExecGuardUnavailable):
        execguard.lock_down(required=True)


def test_a_dev_box_says_so_and_continues(monkeypatch, capsys):
    """`required=False` is the box and the laptop. A hard refusal there is how
    the call ends up commented out, so it logs instead -- and it does log,
    because an unguarded process nobody was told about is the other failure."""
    def refuse():
        raise execguard.ExecGuardUnavailable("no")

    monkeypatch.setattr(execguard, "install", refuse)
    execguard.lock_down(required=False)
    assert "not installed" in capsys.readouterr().err


def _main_block_calls(module):
    """The names called inside a module's `if __name__ == "__main__":` block."""
    path = REPO / (module.replace(".", "/") + ".py")
    tree = ast.parse(path.read_text())
    called = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        source = ast.unparse(node.test)
        if "__name__" not in source or "__main__" not in source:
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Call):
                called.append(ast.unparse(inner.func))
    return called


@pytest.mark.parametrize("module", sorted(
    {root for roots in render_image_manifest.ROLE_ROOTS.values() for root in roots}
))
def test_every_enclave_entry_point_locks_itself_down(module):
    """Read from the manifest's own root list rather than from a list here: a
    role that gains an entry point gains it in that file, and an entry point
    nobody guards is a process in a measured image that can still start a
    program.

    The call is asserted in the `__main__` block specifically. In `main()` it
    would be inherited by every test that imports `main`, and at package import
    it would land in pytest and in every operator tool."""
    assert "execguard.lock_down" in _main_block_calls(module), (
        f"{module} does not call execguard.lock_down() in its __main__ block")
