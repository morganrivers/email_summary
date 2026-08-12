"""Make process creation impossible for the rest of this process's life.

Every other control in this tree answers "what may this code reach". This one
answers "may an attacker who already has code execution here run a program",
and the answer has to be no rather than no-so-far. Nothing shipped starts a
program -- `tests/test_image_manifest.py` proves the absence of `subprocess`,
`os.exec*`, `os.fork` and `eval` across every file in every measured image --
but that is a statement about our source, and an attacker executing code in
this address space is not running our source. A shell in the web container is
the worst thing that can happen to this product, so it is refused by the
kernel rather than checked for by us.

What this installs, once, in the process that calls it:

  * `PR_SET_NO_NEW_PRIVS`, which is a precondition of the next line for an
    unprivileged process and is worth having on its own.
  * A seccomp filter, with `SECCOMP_FILTER_FLAG_TSYNC` so it lands on every
    thread rather than only the caller.

The filter kills the process on `execve`, `execveat`, `fork`, `vfork`,
`ptrace`, and any `clone` that is not creating a thread. `clone3` returns
ENOSYS, which is what glibc's thread creation probes for before falling back to
`clone`, so threads keep working and a caller that wanted a process does not
get one. `execveat` matters as much as `execve`: without it a payload writes
itself to a `memfd` and never touches a filesystem at all.

The action is `SECCOMP_RET_KILL_PROCESS` and not `SECCOMP_RET_ERRNO`, because
the process is presumed compromised by the time this fires. An errno is a
failure the attacker retries around; death is the end of the attempt, and the
container's `restart: always` is what brings the service back. It is also not
`SECCOMP_RET_TRAP`, which would let us alert from a `SIGSYS` handler: a handler
is Python the attacker is already running inside of, so they would simply
ignore the signal. Detection of the surviving case belongs to
`backend/procwatch.py`, which watches from a place the filter has already made
hard to reach.

This is prevention that cannot be raced, and it does not replace the compose
file's `read_only`, `cap_drop` and `noexec` mounts. Those cover the processes
this module never runs in -- the entrypoint shell, and supercronic and its
children in the mail role.

Called from each service's `if __name__ == "__main__":` block rather than from
`main()` or from package import. A test imports `main()` and would inherit a
filter that outlives the test; package import would put one in every operator
tool and in pytest itself. The `__main__` block is exactly "this process is a
service", which is exactly the subject.

At the repo root beside `runtime_guard.py` and for its reason: both packages
start processes that want this, and `cosigner/` deliberately imports nothing
from `backend/` but its alerts. So this module imports neither, and `lock_down`
takes "is a failure fatal" as an argument rather than reading `TEE_REQUIRED`
itself. The enclave's entry points pass `secrets.tee_required()`; the co-signer,
which runs on the box and never in a CVM, passes False.
"""

from __future__ import annotations

import ctypes
import os
import platform
import struct
import sys

AUDIT_ARCH_X86_64 = 0xC000003E

PR_SET_NO_NEW_PRIVS = 38
SYS_SECCOMP = 317
SECCOMP_SET_MODE_FILTER = 1
SECCOMP_FILTER_FLAG_TSYNC = 1

SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000

BPF_LD_W_ABS = 0x20
BPF_JMP_JEQ_K = 0x15
BPF_JMP_JSET_K = 0x45
BPF_RET_K = 0x06

SECCOMP_DATA_NR = 0
SECCOMP_DATA_ARCH = 4
SECCOMP_DATA_ARG0 = 16

CLONE_THREAD = 0x00010000
ENOSYS = 38

KILLED = {
    "execve": 59,
    "execveat": 322,
    "fork": 57,
    "vfork": 58,
    "ptrace": 101,
}

CLONE = 56
CLONE3 = 435

SUPPORTED_MACHINE = "x86_64"


class ExecGuardUnavailable(RuntimeError):
    """The kernel would not take the filter, so this process can still start
    another program. Raised rather than logged under TEE_REQUIRED: an enclave
    that cannot refuse a shell is not the thing that was attested."""


def _instruction(code, jt, jf, k):
    return struct.pack("HBBI", code, jt, jf, k)


def _program():
    """The filter, as `struct sock_filter[]`.

    Written out with literal jump distances rather than assembled from labels,
    because the program is fifteen instructions and an assembler would be more
    code than the thing it assembles. The distances are counted from the
    instruction after the jump, and `_ALLOW`, `_KILL` and `_ENOSYS` below name
    the three returns they land on.

    The architecture check is first and its false branch is the kill, not the
    allow. A filter written against the x86_64 syscall table says nothing about
    a process that switched to the 32-bit ABI, where 59 is `chown` rather than
    `execve` -- which is the standard way out of a seccomp policy, and the same
    reason `SystemCallArchitectures=native` is in the box's hardening drop-in.
    """
    allow, kill, enosys = 13, 14, 15
    return b"".join([
        _instruction(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARCH),
        _instruction(BPF_JMP_JEQ_K, 0, kill - 2, AUDIT_ARCH_X86_64),
        _instruction(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR),
        _instruction(BPF_JMP_JEQ_K, kill - 4, 0, KILLED["execve"]),
        _instruction(BPF_JMP_JEQ_K, kill - 5, 0, KILLED["execveat"]),
        _instruction(BPF_JMP_JEQ_K, kill - 6, 0, KILLED["fork"]),
        _instruction(BPF_JMP_JEQ_K, kill - 7, 0, KILLED["vfork"]),
        _instruction(BPF_JMP_JEQ_K, kill - 8, 0, KILLED["ptrace"]),
        _instruction(BPF_JMP_JEQ_K, enosys - 9, 0, CLONE3),
        _instruction(BPF_JMP_JEQ_K, 1, 0, CLONE),
        _instruction(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
        _instruction(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARG0),
        _instruction(BPF_JMP_JSET_K, allow - 13, kill - 13, CLONE_THREAD),
        _instruction(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
        _instruction(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        _instruction(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | ENOSYS),
    ])


def install():
    """Install the filter on every thread of this process. Not reversible, on
    purpose: an unprivileged process cannot drop a seccomp filter, so code
    running here later cannot undo it either."""
    if platform.machine() != SUPPORTED_MACHINE:
        raise ExecGuardUnavailable(
            f"the syscall numbers in this filter are {SUPPORTED_MACHINE} and "
            f"this is {platform.machine()}; a filter written against the wrong "
            "table would allow exactly what it claims to refuse"
        )
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise ExecGuardUnavailable(
            f"PR_SET_NO_NEW_PRIVS: {os.strerror(ctypes.get_errno())}")
    program = _program()
    instructions = ctypes.create_string_buffer(program, len(program))
    fprog = ctypes.create_string_buffer(
        struct.pack("HxxxxxxP", len(program) // 8,
                    ctypes.addressof(instructions)), 16)
    if libc.syscall(SYS_SECCOMP, SECCOMP_SET_MODE_FILTER,
                    SECCOMP_FILTER_FLAG_TSYNC, ctypes.byref(fprog)) != 0:
        raise ExecGuardUnavailable(
            f"seccomp(SET_MODE_FILTER): {os.strerror(ctypes.get_errno())}")


def lock_down(required):
    """Install the filter, raising if it cannot be installed and `required`.

    The enclave passes True and gets a refusal: `restart: always` turns that
    into a crash loop and a log line, which is the correct outcome for a
    container that would otherwise open mailboxes while still able to spawn a
    shell. A dev box passes False, because it may be a kernel without
    `SECCOMP_RET_KILL_PROCESS` or a runtime whose own filter blocks `seccomp`,
    and a hard refusal there is how the call ends up commented out."""
    try:
        install()
    except ExecGuardUnavailable as err:
        if required:
            raise
        sys.stderr.write(f"[execguard] not installed ({err}); "
                         "process creation is not blocked in this process\n")
        sys.stderr.flush()
        return
    sys.stderr.write("[execguard] process creation refused for this process\n")
    sys.stderr.flush()
