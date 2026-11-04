"""Child-only Linux x86_64 ptrace injection at the real retained-backing fsync.

Start the normal CLI under tracing, following its monitor forks/threads so Yama
needs no machine-wide relaxation. Detach the native worker at exec. Only the
monitor's post-worker-terminal fsync on the requested exact (device,inode) is
replaced with EIO. This is injected syscall EIO, NOT physical media failure.
No production grant, native fork, JSON substitution or new package is involved.
"""
from __future__ import annotations

import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import select
import signal
import sys
import time


class Registers(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in ("r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs")]


class SyscallInfo(ctypes.Structure):
    _fields_ = [("op", ctypes.c_ubyte), ("pad", ctypes.c_ubyte * 3), ("arch", ctypes.c_uint), ("ip", ctypes.c_ulonglong), ("sp", ctypes.c_ulonglong), ("data", ctypes.c_ulonglong * 8)]


def main() -> None:
    request = json.loads(Path(sys.argv[1]).read_text())
    assert platform.system() == "Linux" and platform.machine() == "x86_64", "ptrace syscall-injection qualification is Linux x86_64 only"
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
    def ptrace(op: int, tid: int, address=0, data=0) -> int:
        result = libc.ptrace(op, tid, ctypes.c_void_p(address) if isinstance(address, int) else address, ctypes.c_void_p(data) if isinstance(data, int) else data)
        if result == -1:
            raise OSError(ctypes.get_errno(), f"ptrace {op} tid {tid}")
        return result
    evidence = Path(request["evidence"])
    holder_path = Path(request["holder"])
    wanted = {(item["device"], item["inode"]): item["path"] for item in request["backings"]}
    assert 1 <= len(wanted) <= 16
    close_target_path = Path(request["closeTargets"])
    binding: dict | None = None
    close_targets: dict[int, dict] = {}
    # Reap daemon descendants on every failure, not only the launching CLI.
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "subreaper")
    output = os.open(evidence / "traced-start.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    root = os.fork()
    if root == 0:
        try:
            os.dup2(output, 1)
            os.dup2(output, 2)
            os.close(output)
            ptrace(0, 0)  # TRACEME; first exec traps before application code
            os.execv(request["silo"], [request["silo"], "start", request["name"]])
        except BaseException:
            os._exit(126)
    os.close(output)
    tracked = {root}
    owners: dict[int, int] = {root: os.pidfd_open(root)}
    tgids: dict[int, int] = {}
    configured: set[int] = set()
    stopped_tids: set[int] = set()
    awaiting_terminal: dict[int, dict] = {}
    pending: dict[int, dict] = {}
    pending_close: dict[int, dict] = {}
    observed: dict[int, dict] = {}
    deadline = time.monotonic() + 240
    options = 1 | 2 | 4 | 8 | 16 | 64 | 0x00100000  # SYSGOOD/FORK/VFORK/CLONE/EXEC/EXIT/EXITKILL
    def capture(tid: int) -> int:
        if tid in tgids:
            return tgids[tid]
        try:
            status = Path(f"/proc/{tid}/status").read_text().splitlines()
        except FileNotFoundError as error:
            raise ProcessLookupError(errno.ESRCH, f"stopped tracee status disappeared: tid {tid}") from error
        tgid = int(next(line.split()[1] for line in status if line.startswith("Tgid:")))
        if tgid not in owners:
            owners[tgid] = os.pidfd_open(tgid)
        tgids[tid] = tgid
        return tgid

    def lifecycle(event: str, tid: int, **details) -> None:
        with (evidence / "ptrace-lifecycle.jsonl").open("a") as output:
            output.write(json.dumps({"event": event, "tid": tid, "tgid": tgids.get(tid), **details}) + "\n")

    def retire(tid: int, proof: str, **details) -> None:
        # A lost stopped thread is not a completed syscall. Even an actual
        # terminal wait/exec-collapse cannot supply its missing checked return.
        lifecycle(proof, tid, pending_sync=tid in pending,
                  pending_close=tid in pending_close,
                  lost_stop=awaiting_terminal.get(tid), **details)
        assert tid not in pending and tid not in pending_close, f"{proof} lost a required retained-attachment syscall return for tid {tid}"
        tracked.discard(tid)
        stopped_tids.discard(tid)
        awaiting_terminal.pop(tid, None)
        tgids.pop(tid, None)
        configured.discard(tid)

    def lost_stop(tid: int, status: int, error: ProcessLookupError) -> None:
        assert tid in stopped_tids, "ESRCH without a preceding observed ptrace stop"
        # exit_group/SIGKILL can invalidate a reported syscall stop. ESRCH
        # cannot retire the thread: WNOHANG may still report no terminal event.
        awaiting_terminal[tid] = {"status": status, "operation": str(error)}
        lifecycle("lost-stop-awaiting-terminal", tid, **awaiting_terminal[tid])
        stopped_tids.discard(tid)
    def bind_retained_targets() -> None:
        nonlocal binding
        if binding is not None or not close_target_path.is_file():
            return
        encoded = close_target_path.read_bytes()
        assert len(encoded) <= 65536
        current = json.loads(encoded)
        holder = json.loads(holder_path.read_text())
        roles = {item["role"]: item["pid"] for item in holder["holders"]}
        assert (current["machineId"], current["runId"]) == (holder["machineId"], holder["runId"])
        assert current["monitorPid"] == roles["monitor"] and current["workerPid"] == roles["krun-worker"]
        assert 1 <= len(current["attachments"]) <= 16
        for item in current["attachments"]:
            fd = item["fd"]
            assert fd >= 3 and fd not in close_targets
            metadata = Path(f"/proc/{current['monitorPid']}/fd/{fd}").stat()
            assert (metadata.st_dev, metadata.st_ino) == (item["device"], item["inode"])
            info = Path(f"/proc/{current['monitorPid']}/fdinfo/{fd}").read_text()
            flags = int(next(line.split()[1] for line in info.splitlines() if line.startswith("flags:")), 8)
            assert flags & os.O_ACCMODE == (os.O_RDONLY if item["readOnly"] else os.O_RDWR)
            assert item["readOnly"] or item["format"] == "raw"
            close_targets[fd] = item
        writable = {(item["device"], item["inode"]) for item in close_targets.values() if not item["readOnly"]}
        assert writable == set(wanted), "ready writable Raw coverage differs from prelaunch sync/fault scope"
        binding = current
        (evidence / "retained-close-targets-accepted.json").write_text(json.dumps(current, indent=2) + "\n")

    def terminal_attachment(tid: int, fd: int, kind: str) -> dict:
        assert binding is not None
        target = close_targets[fd]
        metadata = Path(f"/proc/{tid}/fd/{fd}").stat()
        assert (metadata.st_dev, metadata.st_ino) == (target["device"], target["inode"])
        worker = binding["workerPid"]
        assert select.select([owners[worker]], [], [], 0)[0], "retained native worker identity is not terminal"
        try:
            worker_state = Path(f"/proc/{worker}/stat").read_text().rsplit(") ", 1)[1].split()[0]
        except FileNotFoundError:
            worker_state = "reaped"
        assert worker_state == "reaped", "retained attachment finalization preceded actual native worker reap"
        return {**target, "kind": kind, "tgid": binding["monitorPid"], "tid": tid,
                "workerPid": worker, "workerState": worker_state,
                "machineId": binding["machineId"], "runId": binding["runId"]}

    def handle_stop(tid: int, status: int) -> None:
        stopped = os.WSTOPSIG(status)
        event = status >> 16
        if event == 4:
            # A nonleader exec acquires its leader's TID; Linux guarantees all
            # sibling threads are dead at this event, even if their final wait
            # statuses have not been consumed (or the former TID vanishes).
            for sibling, group in list(tgids.items()):
                if group == tid and sibling != tid:
                    retire(sibling, "exec-retired-thread", exec_tid=tid)
            former = ctypes.c_ulong()
            ptrace(0x4201, tid, 0, ctypes.byref(former))
            if former.value != tid:
                retire(former.value, "exec-former-tid", exec_tid=tid)
            lifecycle("exec-event", tid, former_tid=former.value)
            configured.discard(tid)
            tgids.pop(tid, None)
        tgid = capture(tid)
        if tid not in configured:
            ptrace(0x4200, tid, 0, options)
            configured.add(tid)
        if event in (1, 2, 3):
            child = ctypes.c_ulong()
            ptrace(0x4201, tid, 0, ctypes.byref(child))
            tracked.add(child.value)
            lifecycle("child-event", tid, child_tid=child.value, ptrace_event=event)
            # Capture the child only after its own initial wait stop. Reading
            # /proc here races group exit before that child's stop is consumed.
        if event == 4:
            try:
                argv = Path(f"/proc/{tid}/cmdline").read_bytes().split(b"\0")
            except FileNotFoundError as error:
                raise ProcessLookupError(errno.ESRCH, f"exec tracee disappeared: tid {tid}") from error
            if argv and argv[0] == b"krun":
                # Native execution must not be syscall-traced or mutated.
                ptrace(17, tid)
                retire(tid, "worker-detached")
                return
        if event == 6:
            exit_status = ctypes.c_ulong()
            ptrace(0x4201, tid, 0, ctypes.byref(exit_status))
            lifecycle("exit-event-not-terminal", tid, status=exit_status.value)
        if stopped == signal.SIGTRAP | 0x80:
            info = SyscallInfo()
            ptrace(0x420E, tid, ctypes.sizeof(info), ctypes.byref(info))
            if info.op == 1 and info.data[0] in (74, 75):
                fd = int(info.data[1])
                if binding is not None and tgid == binding["monitorPid"] and fd in close_targets and "closeReturn" not in observed.get(fd, {}):
                    target = close_targets[fd]
                    assert not target["readOnly"], "unexpected sync of a close-only read-only attachment"
                    assert fd not in observed, "retained writable attachment synchronized more than once"
                    receipt = terminal_attachment(tid, fd, "observed unmodified retained fsync")
                    identity = (receipt["device"], receipt["inode"])
                    inject = request["injectEio"] and identity == next(iter(wanted))
                    receipt.update(injected=inject, syscall=int(info.data[0]))
                    pending[tid] = receipt
                    if inject:
                        receipt["kind"] = "injected syscall EIO, not media failure"
                        registers = Registers()
                        ptrace(12, tid, 0, ctypes.byref(registers))
                        registers.orig_rax = 0xffffffffffffffff  # skip exactly this syscall
                        ptrace(13, tid, 0, ctypes.byref(registers))
            elif info.op == 1 and info.data[0] == 3:
                fd = int(info.data[1])
                if binding is not None and tgid == binding["monitorPid"] and fd in close_targets and "closeReturn" not in observed.get(fd, {}):
                    target = close_targets[fd]
                    proof = terminal_attachment(tid, fd, "observed retained read-only close")
                    if not target["readOnly"]:
                        assert fd in observed and "return" in observed[fd], "writable attachment closed before its checked final sync"
                        receipt = observed[fd]
                    else:
                        assert fd not in observed, "retained read-only descriptor closed more than once"
                        receipt = proof
                        observed[fd] = receipt
                    assert "closeReturn" not in receipt
                    receipt["closeSyscall"] = 3
                    pending_close[tid] = receipt
            elif info.op == 2 and tid in pending:
                registers = Registers()
                ptrace(12, tid, 0, ctypes.byref(registers))
                actual = ctypes.c_longlong(registers.rax).value
                receipt = pending[tid]
                if receipt["injected"]:
                    assert actual == -errno.ENOSYS
                    registers.rax = (-errno.EIO) & 0xffffffffffffffff
                    ptrace(13, tid, 0, ctypes.byref(registers))
                    actual = -errno.EIO
                receipt["return"] = actual
                observed[receipt["fd"]] = receipt
                del pending[tid]
            elif info.op == 2 and tid in pending_close:
                registers = Registers()
                ptrace(12, tid, 0, ctypes.byref(registers))
                receipt = pending_close[tid]
                receipt["closeReturn"] = ctypes.c_longlong(registers.rax).value
                del pending_close[tid]
                (evidence / "retained-fsync-receipt.json").write_text(json.dumps({"attachments": list(observed.values())}, indent=2) + "\n")
        deliver = stopped if stopped not in (signal.SIGTRAP, signal.SIGSTOP, signal.SIGTRAP | 0x80) else 0
        ptrace(7 if event == 6 else 24, tid, 0, deliver)
        stopped_tids.discard(tid)

    def cancelled(_signal, _frame) -> None:
        raise InterruptedError("owned syscall controller cancelled")
    signal.signal(signal.SIGTERM, cancelled)
    try:
        while tracked:
            assert time.monotonic() < deadline, f"bounded child ptrace gate exceeded 240s; unresolved tids={sorted(tracked)}, lost stops={awaiting_terminal}"
            bind_retained_targets()
            tid, status = os.waitpid(-1, os.WNOHANG | 0x40000000)  # __WALL includes clone threads
            if tid == 0:
                time.sleep(0.0001)
                continue
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                retire(tid, "wait-terminal", status=status,
                       exited=os.WIFEXITED(status), code=os.waitstatus_to_exitcode(status))
                if tid == root:
                    code = os.waitstatus_to_exitcode(status)
                    (evidence / "traced-start-result.json").write_text(json.dumps({"returncode": code}))
                continue
            assert os.WIFSTOPPED(status), (tid, status)
            tracked.add(tid)
            stopped_tids.add(tid)
            try:
                handle_stop(tid, status)
            except ProcessLookupError as error:
                lost_stop(tid, status, error)
        assert not awaiting_terminal and not pending and not pending_close, "unresolved trace lifecycle or missing checked syscall returns"
        assert binding is not None and set(observed) == set(close_targets), "not every bound retained monitor attachment reached its post-reap checked close"
        assert all(item.get("closeReturn") == 0 for item in observed.values()), "not every exact retained attachment FD was explicitly closed successfully"
        assert all("return" in item for item in observed.values() if not item["readOnly"]), "missing writable Raw final sync"
    finally:
        for fd in owners.values():
            if not select.select([fd], [], [], 0)[0]:
                try:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        cleanup_deadline = time.monotonic() + 10
        while time.monotonic() < cleanup_deadline:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG | 0x40000000)
            except ChildProcessError:
                break
            if pid == 0:
                time.sleep(0.01)
                continue
            if os.WIFSTOPPED(status):
                try:
                    ptrace(7, pid, 0, signal.SIGKILL)
                except OSError as error:
                    if error.errno != errno.ESRCH:
                        raise
        remaining = [pid for pid, fd in owners.items() if not select.select([fd], [], [], 0)[0]]
        for fd in owners.values():
            os.close(fd)
        assert not remaining, f"owned traced processes exceeded cleanup deadline: {remaining}"


if __name__ == "__main__":
    main()
