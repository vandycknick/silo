"""Bounded child-only syscall boundaries for stopped copy/restore acceptance.

Normal gates pause one real syscall thread while all other threads continue.
Negative gates inject one explicitly recorded errno at an owned copy/publication
boundary, never a success or replacement bytes. Linux x86_64 only. EXITKILL and
pidfd cleanup fence owned descendants. None of this simulates power loss.
"""
from __future__ import annotations
from collections import Counter, deque

import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import signal
import stat
import sys
import time

from .shutdown_trace import Registers, SyscallInfo


def main() -> None:
    request = json.loads(Path(sys.argv[1]).read_text())
    assert platform.system() == "Linux" and platform.machine() == "x86_64"
    target = Path(request["target"]).stat()
    identity = (target.st_dev, target.st_ino)
    evidence = Path(request["evidence"])
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]

    def ptrace(op: int, tid: int, address=0, data=0) -> int:
        result = libc.ptrace(op, tid, ctypes.c_void_p(address) if isinstance(address, int) else address, ctypes.c_void_p(data) if isinstance(data, int) else data)
        if result == -1:
            raise OSError(ctypes.get_errno(), f"ptrace {op} tid {tid}")
        return result

    root = os.fork()
    if root == 0:
        try:
            out = os.open(evidence / "boundary-command.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.dup2(out, 1)
            os.dup2(out, 2)
            os.close(out)
            if "stdin" in request:
                source = os.open(request["stdin"], os.O_RDONLY)
                os.dup2(source, 0)
                os.close(source)
            ptrace(0, 0)
            os.execv(request["command"][0], request["command"])
        except BaseException:
            os._exit(126)
    tracked = {root}
    configured = set()
    groups = {}
    stopped_status = {}
    awaiting_terminal = {}
    owners = {root: os.pidfd_open(root)}
    held = None
    matched = False
    root_result = None
    deadline = time.monotonic() + 240
    options = 1 | 2 | 4 | 8 | 16 | 64 | 0x00100000
    pending_injection = {}
    publication_seen = False
    # A fixed sleep at every empty WNOHANG poll adds a millisecond to nearly
    # every syscall stop, including boot-asset authentication before the copy.
    # Block SIGCHLD only in the controller, then wait for actual stop readiness.
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGCHLD})
    syscall_counts = Counter()
    recent = deque(maxlen=32)
    machines = Path(request["machines"])
    boundary = request["boundary"]
    candidates = {
        "source-sync": {74, 75},
        "source-read": {0, 5, 8, 17},
        "destination-copy": {1, 16, 18, 20},
        "destination-sync": {74, 75},
        "publication-rename": {316},
        "destination-directory-sync": {74, 316},
    }[boundary]

    def lifecycle(event: str, tid: int, **details) -> None:
        with (evidence / "boundary-lifecycle.jsonl").open("a") as output:
            output.write(json.dumps({"event": event, "tid": tid, "tgid": groups.get(tid), **details}) + "\n")

    def resume(op: int, tid: int, deliver: int = 0) -> None:
        assert tid in stopped_status, "resume without an observed ptrace stop"
        try:
            ptrace(op, tid, 0, deliver)
        except ProcessLookupError as error:
            # exit_group/SIGKILL can invalidate a previously reported stop.
            # ESRCH is not terminal proof: keep the TID tracked until waitpid
            # reports its real exit, and never manufacture an injected return.
            awaiting_terminal[tid] = {"status": stopped_status[tid], "operation": str(error)}
            lifecycle("lost-stop-awaiting-terminal", tid, **awaiting_terminal[tid])
        stopped_status.pop(tid)

    def cancelled(_signal, _frame) -> None:
        raise InterruptedError("owned stopped boundary controller cancelled")

    signal.signal(signal.SIGTERM, cancelled)
    try:
        while tracked:
            assert time.monotonic() < deadline, f"actual operation exceeded 240s: {tracked}; lost stops: {awaiting_terminal}"
            if held is not None and Path(request["release"]).is_file():
                resume(24 if held in pending_injection else 7, held)
                held = None
            tid, status = os.waitpid(-1, os.WNOHANG | 0x40000000)
            if tid == 0:
                signal.sigtimedwait({signal.SIGCHLD}, 0.05)
                continue
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                lifecycle("wait-terminal", tid, status=status, code=os.waitstatus_to_exitcode(status),
                          lost_stop=awaiting_terminal.get(tid), pending_injection=tid in pending_injection)
                assert tid not in pending_injection, f"terminal wait lost a required injected return for tid {tid}"
                awaiting_terminal.pop(tid, None)
                stopped_status.pop(tid, None)
                tracked.discard(tid)
                configured.discard(tid)
                groups.pop(tid, None)
                if tid == root:
                    root_result = os.waitstatus_to_exitcode(status)
                continue
            assert os.WIFSTOPPED(status), (tid, status)
            tracked.add(tid)
            stopped_status[tid] = status
            if tid not in groups:
                groups[tid] = int(next(line.split()[1] for line in Path(f"/proc/{tid}/status").read_text().splitlines() if line.startswith("Tgid:")))
            group = groups[tid]
            if group not in owners:
                owners[group] = os.pidfd_open(group)
            if tid not in configured:
                ptrace(0x4200, tid, 0, options)
                configured.add(tid)
            event = status >> 16
            stopped = os.WSTOPSIG(status)
            if event in (1, 2, 3):
                child = ctypes.c_ulong()
                ptrace(0x4201, tid, 0, ctypes.byref(child))
                tracked.add(child.value)
            if stopped == signal.SIGTRAP | 0x80:
                info = SyscallInfo()
                ptrace(0x420E, tid, ctypes.sizeof(info), ctypes.byref(info))
                if info.op == 2 and tid in pending_injection:
                    registers = Registers()
                    ptrace(12, tid, 0, ctypes.byref(registers))
                    assert ctypes.c_longlong(registers.rax).value == -errno.ENOSYS
                    injected = pending_injection[tid]
                    registers.rax = (-injected["errno"]) & 0xffffffffffffffff
                    ptrace(13, tid, 0, ctypes.byref(registers))
                    (evidence / "boundary-injected.json").write_text(json.dumps(injected) + "\n")
                    del pending_injection[tid]
                if info.op == 1 and not matched:
                    syscall = int(info.data[0])
                    syscall_counts[syscall] += 1
                    if syscall not in candidates:
                        resume(24, tid)
                        continue
                    fd = int(info.data[1])
                    try:
                        fd_path = Path(f"/proc/{tid}/fd/{fd}")
                        metadata = fd_path.stat()
                        actual_path = Path(os.readlink(fd_path))
                    except OSError:
                        metadata = None
                        actual_path = None
                    recent.append({"tid": tid, "syscall": syscall, "fd": fd, "path": str(actual_path) if actual_path is not None else None})
                    owned_copy = actual_path is not None and actual_path.parent.name.startswith(".copy-") and actual_path.name == "file-0" and actual_path.parent.parent.parent == machines
                    owned_stage = actual_path is not None and actual_path.name.startswith(".copy-") and actual_path.parent.parent == machines
                    owned_child = actual_path is not None and actual_path.parent == machines and actual_path != Path(request["target"]).parent
                    publication = syscall == 316 and owned_stage
                    if publication:
                        with Path(f"/proc/{tid}/mem").open("rb", buffering=0) as memory:
                            memory.seek(int(info.data[2]))
                            publication = memory.read(64).split(b"\0", 1)[0] == b"file-0"
                        publication_seen = publication_seen or publication
                    source = metadata is not None and (metadata.st_dev, metadata.st_ino) == identity
                    selected = ((boundary == "source-sync" and syscall in (74, 75) and source)
                                or (boundary == "source-read" and syscall in (0, 5, 8, 17) and source)
                                or (boundary == "destination-copy" and owned_copy and (syscall in (1, 18, 20) or (syscall == 16 and info.data[2] == 0x40049409)))
                                or (boundary == "destination-sync" and owned_copy and syscall in (74, 75))
                                or (boundary == "publication-rename" and publication)
                                or (boundary == "destination-directory-sync" and publication_seen and syscall == 74 and (owned_stage or owned_child) and metadata is not None and stat.S_ISDIR(metadata.st_mode)))
                    if selected:
                        assert metadata is not None
                        held = tid
                        matched = True
                        injected_errno = request.get("errno")
                        receipt = {"pid": group, "tid": tid, "fd": fd, "syscall": syscall, "device": metadata.st_dev, "inode": metadata.st_ino, "target": str(actual_path), "injectedReturn": injected_errno is not None}
                        receipt["source"] = {"path": request["target"], "device": identity[0], "inode": identity[1]}
                        if injected_errno is not None:
                            assert injected_errno in (errno.EIO, errno.ENOSPC, errno.EACCES)
                            registers = Registers()
                            ptrace(12, tid, 0, ctypes.byref(registers))
                            registers.orig_rax = 0xffffffffffffffff
                            ptrace(13, tid, 0, ctypes.byref(registers))
                            pending_injection[tid] = {**receipt, "errno": injected_errno, "kind": "injected syscall failure, not physical media/power-loss failure"}
                        (evidence / "boundary-held.json").write_text(json.dumps(receipt) + "\n")
                        continue
            deliver = stopped if stopped not in (signal.SIGTRAP, signal.SIGSTOP, signal.SIGTRAP | 0x80) else 0
            # After the required boundary/checked injected return, retain
            # lifecycle tracing and EXITKILL without stopping every syscall.
            resume(24 if event != 6 and (not matched or tid in pending_injection) else 7, tid, deliver)
        assert matched and not pending_injection and not awaiting_terminal, "missing real syscall boundary/checked injected return/terminal wait; inspect boundary-command.log and boundary-lifecycle.jsonl"
        (evidence / "boundary-result.json").write_text(json.dumps({"returncode": root_result}) + "\n")
    finally:
        for fd in owners.values():
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
        cleanup = time.monotonic() + 10
        while tracked and time.monotonic() < cleanup:
            try:
                tid, status = os.waitpid(-1, os.WNOHANG | 0x40000000)
            except ChildProcessError:
                break
            if tid == 0:
                time.sleep(0.005)
            elif os.WIFEXITED(status) or os.WIFSIGNALED(status):
                lifecycle("cleanup-wait-terminal", tid, status=status, code=os.waitstatus_to_exitcode(status),
                          lost_stop=awaiting_terminal.get(tid), pending_injection=tid in pending_injection)
                tracked.discard(tid)
            else:
                try:
                    ptrace(7, tid, 0, signal.SIGKILL)
                except OSError as error:
                    if error.errno != errno.ESRCH:
                        raise
        for fd in owners.values():
            os.close(fd)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        (evidence / "boundary-trace.json").write_text(json.dumps({
            "boundary": boundary, "matched": matched,
            "source": {"path": request["target"], "device": identity[0], "inode": identity[1]},
            "syscallEntries": dict(syscall_counts), "recentCandidates": list(recent),
            "awaitingTerminal": awaiting_terminal,
        }, indent=2) + "\n")
        assert not tracked, f"unreaped owned tracees: {tracked}"


if __name__ == "__main__":
    main()
