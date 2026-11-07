"""Bounded child-only syscall boundaries for stopped copy/restore acceptance.

Normal gates pause one real syscall thread while all other threads continue.
Negative gates inject one explicitly recorded errno at an owned copy/publication
boundary, never a success or replacement bytes. Restore activation gates hold
one native thread after the monitor logged the real preceding event. The Thaw
reply gate identifies response bytes regardless of which native thread forwards
them; `observeNetEgress` records native NIC sends.
Linux x86_64 only. EXITKILL and pidfd cleanup fence owned descendants. A held
boundary owns one observed stop, not the TID's later exit stops; losing it never
discharges an injected return or proves terminal exit. None of this simulates
power loss.
"""
from __future__ import annotations
from collections import Counter, deque

import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import re
import signal
import sqlite3
import stat
import struct
import sys
import time

from .shutdown_trace import Registers, SyscallInfo


def protobuf_fields(data: bytes) -> dict[int, list[int | bytes]]:
    """Decode only protobuf wire values, without generated smoke dependencies."""
    offset = 0

    def varint() -> int:
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            if offset == len(data):
                raise ValueError("truncated protobuf varint")
            byte = data[offset]
            offset += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
        raise ValueError("oversized protobuf varint")

    fields = {}
    while offset < len(data):
        key = varint()
        field, wire = key >> 3, key & 7
        if not field:
            raise ValueError("zero protobuf field")
        if wire == 0:
            value = varint()
        elif wire in (1, 2, 5):
            length = varint() if wire == 2 else (8 if wire == 1 else 4)
            if length > len(data) - offset:
                raise ValueError("truncated protobuf field")
            value = data[offset:offset + length]
            offset += length
        else:
            raise ValueError("unsupported protobuf wire type")
        fields.setdefault(field, []).append(value)
    return fields


def thaw_reply(data: bytes, activation: str) -> dict | None:
    """Find a complete unary THAWED response in actual HTTP/2 DATA frames.

    Input begins at the first native write after THAW_SENDING, including the
    optional Unix mux CONNECT reply on a fresh guest channel. Reassemble short
    socket writes and DATA fragmentation; CONNECT/SETTINGS/HEADERS/WINDOW_UPDATE
    alone never prove thaw. common.proto defines THAWED=7 and activation_id=10.
    """
    streams: dict[int, bytes] = {}
    offset = 0
    if data.startswith(b"O"):
        connected = re.match(rb"OK [0-9]+\n", data)
        if connected is None:
            return None
        offset = connected.end()
    while len(data) - offset >= 9:
        length = int.from_bytes(data[offset:offset + 3], "big")
        kind, flags = data[offset + 3:offset + 5]
        stream = int.from_bytes(data[offset + 5:offset + 9], "big") & 0x7fffffff
        offset += 9
        if length > len(data) - offset:
            return None
        payload = data[offset:offset + length]
        offset += length
        if kind != 0 or not stream:
            continue
        if flags & 8:
            if not payload or payload[0] >= len(payload):
                return None
            payload = payload[1:len(payload) - payload[0]]
        message = streams.get(stream, b"") + payload
        streams[stream] = message
        if len(message) < 5 or message[0] != 0:
            continue
        size = int.from_bytes(message[1:5], "big")
        if len(message) != size + 5:
            continue
        try:
            response = protobuf_fields(message[5:])
            if set(response) != {1} or len(response[1]) != 1 or not isinstance(response[1][0], bytes):
                continue
            status = protobuf_fields(response[1][0])
            if status.get(1) != [7] or status.get(10) != [activation.encode()]:
                continue
            # A successful restore Thaw carries the original freeze reference
            # and the activated destination identity, not an empty status.
            reference = protobuf_fields(status[2][0])
            if not all(reference.get(field) for field in (1, 2, 3, 4)):
                continue
            machine, run = status[8][0].decode(), status[9][0].decode()
            if not machine or not run or status.get(6):
                continue
        except (ValueError, KeyError, TypeError, AttributeError, IndexError):
            continue
        return {"state": "thawed", "activation": activation, "machine": machine,
                "run": run, "stream": stream, "grpcMessageHex": message.hex()}
    return None


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
    # A creator's PTRACE_EVENT_{FORK,VFORK,CLONE} stop is not ordered against
    # its auto-attached child's own waits: the child can stop, run and be
    # reaped (or exec-collapsed, or detached) before that announcement is
    # dequeued. Count announcements against kernel-proven ends per TID; a
    # positive balance is an announced tracee still owing an end, in
    # whichever order the waits arrive.
    unaccounted = Counter({root: 1})
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
    copy_pending = {}
    copy_totals = {}
    observe_copies = request.get("observeCaptureCopies", False)
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
        "boot-kernel-copy": {1, 18, 20},
        "destination-copy": {1, 16, 18, 20},
        "destination-sync": {74, 75},
        "publication-rename": {316},
        "destination-directory-sync": {74, 316},
        "capture-disk-sync": {74, 75},
        "capture-execution-sync": {74, 75},
        "capture-ram-sync": {74, 75},
        "capture-dirty-harvest": {16},
        "capture-seal-publish": {265},
        "capture-seal-sync": {74, 75, 265},
        "capture-source-sync": {74, 75},
        "capture-disk-copy": {1, 16, 18, 20},
        "capture-pool-sync": {74, 75},
        "capture-pool-rename": {316},
        "capture-pool-directory-sync": {74, 75},
        "capture-catalog-commit": {74, 75},
        "capture-guest-transport": {265},
        # Restore activation holds require a real preceding monitor event;
        # the reply boundary additionally requires the actual THAWED payload.
        "restore-vcpu-run": {16},
        "restore-guest-transport": set(),
        "restore-transport-reply": {1, 20, 44, 46},
    }[boundary]
    if observe_copies:
        candidates = candidates | {1, 16, 18, 20}
    restore_boundary = boundary.startswith("restore-")
    after_log = request.get("afterLog")
    assert not restore_boundary or after_log is not None, "restore holds require an afterLog gate"
    after_log_seen = False
    reply_activation = None
    reply_bytes = {}
    reply_pending = {}
    # Every frame the native NIC hands to netd crosses one send-family syscall
    # on the virtio-net worker's datagram socket: the host side of the fence.
    observe_net = request.get("observeNetEgress", False)
    net_egress = []

    def save_copies() -> None:
        if observe_copies:
            (evidence / "capture-copy.json").write_text(
                json.dumps(list(copy_totals.values()), indent=2) + "\n")
        if observe_net:
            (evidence / "net-egress.json").write_text(json.dumps(net_egress, indent=2) + "\n")

    def logged_gate() -> bool:
        nonlocal after_log_seen
        nonlocal reply_activation
        if not after_log_seen:
            # Logs that existed before the operation (a source, an earlier
            # child) can never satisfy a gate for this traced restore.
            ignored = {Path(path) for path in after_log.get("ignore", [])}
            for path in sorted(Path(after_log["directory"]).glob(after_log["glob"])):
                if path in ignored:
                    continue
                try:
                    text = path.read_text(errors="replace")
                except FileNotFoundError:
                    continue
                if any(after_log["needle"] in line for line in text.splitlines()):
                    after_log_seen = True
                    if boundary == "restore-transport-reply":
                        line = next(line for line in text.splitlines() if after_log["needle"] in line)
                        activation = re.search(r"\bactivation=([0-9a-f-]{36})\b", line)
                        assert activation is not None, f"Thaw gate lacks activation identity: {line}"
                        reply_activation = activation.group(1)
                    lifecycle("after-log-observed", 0, path=str(path), needle=after_log["needle"])
                    break
        return after_log_seen

    def socket_fd(tid: int, fd: int) -> bool:
        try:
            return os.readlink(f"/proc/{tid}/fd/{fd}").startswith("socket:")
        except FileNotFoundError:
            tracee_status(tid)
            return False
        except OSError:
            return False

    def publication_capture() -> Path | None:
        excluded = set()
        if "excludeCapturesFile" in request:
            exclusion_file = Path(request["excludeCapturesFile"])
            assert exclusion_file.stat().st_size <= 4096, "bounded exact prior-capture list"
            excluded = set(json.loads(exclusion_file.read_bytes()))
        for seal_path in sorted((Path(request["target"]).parent / "captures").glob("*/vm.capture.json")):
            if seal_path.parent.name in excluded:
                continue
            seal = json.loads(seal_path.read_bytes())
            if seal["captureOutcome"] == "coherent":
                return seal_path.parent
        return None

    def lifecycle(event: str, tid: int, **details) -> None:
        with (evidence / "boundary-lifecycle.jsonl").open("a") as output:
            output.write(json.dumps({"event": event, "tid": tid, "tgid": groups.get(tid), **details}) + "\n")

    def retire(tid: int) -> None:
        """Account one kernel-proven end of a TID: terminal wait, exec collapse or detach."""
        tracked.discard(tid)
        configured.discard(tid)
        stopped_status.pop(tid, None)
        awaiting_terminal.pop(tid, None)
        groups.pop(tid, None)
        unaccounted[tid] -= 1

    def lost_stop(tid: int, error: ProcessLookupError) -> None:
        nonlocal held
        assert tid in stopped_status, "ESRCH without an observed ptrace stop"
        # Any ptrace request can lose a reported stop to exit_group/SIGKILL.
        # ESRCH is not terminal proof, even when WNOHANG still returns zero.
        # https://man7.org/linux/man-pages/man2/ptrace.2.html
        awaiting_terminal[tid] = {"status": stopped_status.pop(tid), "operation": str(error)}
        lifecycle("lost-stop-awaiting-terminal", tid, held_boundary=held == tid,
                  **awaiting_terminal[tid])
        if held == tid:
            held = None

    def resume(op: int, tid: int, deliver: int = 0) -> None:
        nonlocal held
        assert tid in stopped_status, "resume without an observed ptrace stop"
        try:
            ptrace(op, tid, 0, deliver)
        except ProcessLookupError as error:
            lost_stop(tid, error)
        else:
            status = stopped_status.pop(tid)
            if held == tid:
                lifecycle("held-stop-resumed", tid, status=status, operation=op)
                held = None

    def tracee_status(tid: int) -> str:
        try:
            return Path(f"/proc/{tid}/status").read_text()
        except FileNotFoundError as error:
            raise ProcessLookupError(errno.ESRCH, f"stopped tracee status disappeared: tid {tid}") from error

    def thread_name(tid: int) -> str:
        try:
            return Path(f"/proc/{tid}/comm").read_text().strip()
        except FileNotFoundError as error:
            raise ProcessLookupError(errno.ESRCH, f"stopped thread name disappeared: tid {tid}") from error

    def tracee_name(tid: int, address: int) -> bytes:
        try:
            with Path(f"/proc/{tid}/mem").open("rb", buffering=0) as memory:
                memory.seek(address)
                return memory.read(64).split(b"\0", 1)[0]
        except FileNotFoundError as error:
            raise ProcessLookupError(errno.ESRCH, f"stopped tracee memory disappeared: tid {tid}") from error

    def send_bytes(tid: int, syscall: int, arguments) -> bytes:
        """Read the stopped syscall's real buffers; never modify guest bytes."""
        with Path(f"/proc/{tid}/mem").open("rb", buffering=0) as memory:
            def load(address: int, size: int) -> bytes:
                assert 0 <= size <= 1024 * 1024, "oversized reply trace buffer"
                memory.seek(address)
                data = memory.read(size)
                assert len(data) == size, "short stopped syscall buffer"
                return data

            address, length = int(arguments[2]), int(arguments[3])
            if syscall in (1, 44):
                return load(address, length)
            if syscall == 46:
                header = load(address, 56)  # Linux x86_64 msghdr
                address, length = struct.unpack_from("=QQ", header, 16)
            assert length <= 1024, "oversized reply iovec"
            vectors = load(address, length * 16)
            return b"".join(load(base, size) for base, size in struct.iter_unpack("=QQ", vectors))

    def handle_stop(tid: int, status: int) -> None:
        nonlocal held, matched, publication_seen
        event = status >> 16
        stopped = os.WSTOPSIG(status)
        if event == 4:
            former = ctypes.c_ulong()
            ptrace(0x4201, tid, 0, ctypes.byref(former))
            # A nonleader exec changes its TID to the leader's. This kernel
            # event, not ESRCH, proves the old TIDs cannot report more returns.
            siblings = {sibling for sibling, group in groups.items() if group == tid and sibling != tid}
            if former.value != tid:
                siblings.add(former.value)
            for sibling in siblings:
                lifecycle("exec-retired-thread", sibling, exec_tid=tid,
                          lost_stop=awaiting_terminal.get(sibling), pending_injection=sibling in pending_injection)
                retire(sibling)
            lost_injections = siblings.intersection(pending_injection)
            assert not lost_injections, f"exec lost required injected returns for tids {lost_injections}"
            assert held not in siblings, f"exec lost the held boundary for tid {held}"
            assert tid not in pending_injection, f"exec replaced a required injected return for tid {tid}"
            awaiting_terminal.pop(tid, None)
            groups.pop(tid, None)
            configured.discard(tid)
            lifecycle("exec-event", tid, former_tid=former.value)
        if tid not in groups:
            groups[tid] = int(next(line.split()[1] for line in tracee_status(tid).splitlines() if line.startswith("Tgid:")))
        group = groups[tid]
        if group not in owners:
            owners[group] = os.pidfd_open(group)
        if tid not in configured:
            ptrace(0x4200, tid, 0, options)
            configured.add(tid)
        if restore_boundary and event == 0 and stopped == signal.SIGSTOP:
            detach = evidence / "restore-manager-detach.json"
            if detach.is_file():
                selected = json.loads(detach.read_text())["pid"]
                manager = json.loads((evidence / "restore-manager-process.json").read_text())["pid"]
                assert selected == manager, "only the restore driver-owned manager may detach"
                if group == selected:
                    # A normal delivery stop starts the group stop; subsequent
                    # SIGSTOP group-stops detach its other threads as well.
                    # Keep the pidfd owner for cleanup, but retire ptrace state
                    # only after a successful DETACH. The driver owns waitpid.
                    assert tid != held and tid not in pending_injection
                    ptrace(17, tid, 0, signal.SIGSTOP)  # PTRACE_DETACH
                    lifecycle("restore-manager-detached", tid, group=group, status=status)
                    retire(tid)
                    return
        if event in (1, 2, 3):
            child = ctypes.c_ulong()
            ptrace(0x4201, tid, 0, ctypes.byref(child))
            # The child may already have been reaped: never re-own its TID.
            unaccounted[child.value] += 1
            lifecycle("child-event", tid, child_tid=child.value, ptrace_event=event,
                      ended_before_announcement=unaccounted[child.value] == 0)
        if stopped == signal.SIGTRAP | 0x80:
            info = SyscallInfo()
            ptrace(0x420E, tid, ctypes.sizeof(info), ctypes.byref(info))
            injected_result = None
            if info.op == 2 and tid in pending_injection:
                registers = Registers()
                ptrace(12, tid, 0, ctypes.byref(registers))
                injected = pending_injection[tid]
                if injected.get("afterEffect"):
                    actual = ctypes.c_longlong(registers.rax).value
                    assert actual == 0, "post-effect dirty fault requires an actual successful GET_DIRTY_LOG"
                    with Path(f"/proc/{tid}/mem").open("rb", buffering=0) as memory:
                        memory.seek(injected["argument"])
                        header = memory.read(16)
                        assert len(header) == 16
                        slot, padding, bitmap_address = struct.unpack("=IIQ", header)
                        assert padding == 0 and bitmap_address != 0
                        memory.seek(bitmap_address)
                        prefix = memory.read(8)
                        assert len(prefix) == 8
                    injected.update(realReturn=actual, slot=slot, dirtyBitmapPrefixHex=prefix.hex())
                else:
                    assert ctypes.c_longlong(registers.rax).value == -errno.ENOSYS
                registers.rax = (-injected["errno"]) & 0xffffffffffffffff
                ptrace(13, tid, 0, ctypes.byref(registers))
                injected_result = -injected["errno"]
                (evidence / "boundary-injected.json").write_text(json.dumps(injected) + "\n")
                del pending_injection[tid]
                if injected.get("afterEffect"):
                    held, matched = tid, True
                    record = evidence / "boundary-held.json.tmp"
                    record.write_text(json.dumps(injected) + "\n")
                    record.replace(evidence / "boundary-held.json")
                    return
            if info.op == 2 and tid in copy_pending:
                key, observation = copy_pending.pop(tid)
                result = (injected_result if injected_result is not None
                          else ctypes.c_longlong(info.data[0]).value)
                total = copy_totals.setdefault(key, {
                    **observation, "calls": 0, "successfulCalls": 0,
                    "returnedBytes": 0, "errors": {},
                })
                total["calls"] += 1
                if result >= 0:
                    total["successfulCalls"] += 1
                    if observation["syscall"] != 16:
                        total["returnedBytes"] += result
                else:
                    code = str(-result)
                    total["errors"][code] = total["errors"].get(code, 0) + 1
            if info.op == 2 and tid in reply_pending:
                key, payload = reply_pending.pop(tid)
                returned = ctypes.c_longlong(info.data[0]).value
                if returned > 0:
                    reply_bytes[key] = reply_bytes.get(key, b"") + payload[:returned]
                    assert len(reply_bytes[key]) <= 1024 * 1024, "Thaw reply trace exceeded bound"
            if (info.op == 1 and observe_net and int(info.data[0]) in (1, 20, 44, 46, 307)
                    and thread_name(tid).startswith("virtio-net")
                    and socket_fd(tid, int(info.data[1]))):
                observation = {"monotonicNs": time.monotonic_ns(), "realtimeNs": time.time_ns(),
                               "pid": group, "tid": tid, "syscall": int(info.data[0]),
                               "fd": int(info.data[1]), "argument": int(info.data[2])}
                net_egress.append(observation)
                with (evidence / "net-egress.jsonl").open("a") as output:
                    output.write(json.dumps(observation) + "\n")
            if (info.op == 1 and not matched
                    and ("arm" not in request or Path(request["arm"]).is_file())):
                syscall = int(info.data[0])
                syscall_counts[syscall] += 1
                if (boundary == "capture-dirty-harvest" and syscall == 16
                        and int(info.data[2]) == 0x4010AE42 and not pending_injection):
                    # GET_DIRTY_LOG actually harvests and reprotects. Observe
                    # its success at EXIT before substituting only -EIO; leave
                    # the kernel-returned bitmap and every real effect intact.
                    fd = int(info.data[1])
                    owner = os.readlink(f"/proc/{tid}/fd/{fd}")
                    assert "kvm-vm" in owner and thread_name(group) == "krun"
                    assert request.get("errno") in (None, errno.EIO)
                    pending_injection[tid] = {
                        "pid": group, "tid": tid, "fd": fd, "syscall": syscall,
                        "ioctl": int(info.data[2]), "argument": int(info.data[3]),
                        "target": owner, "errno": errno.EIO, "afterEffect": True,
                        "injectedReturn": True, "kind": "post-effect GET_DIRTY_LOG error, never injected success"}
                if (boundary == "capture-guest-transport" and publication_seen
                        and thread_name(tid) == "vsock muxer"):
                    directory = publication_capture()
                    if directory is not None:
                        assert request.get("errno") is None, "transport gate never injects a result"
                        receipt = {"pid": group, "tid": tid, "syscall": syscall,
                                   "thread": "vsock muxer", "injectedReturn": False,
                                   "captureDirectory": str(directory)}
                        held, matched = tid, True
                        save_copies()
                        held_record = evidence / "boundary-held.json.tmp"
                        held_record.write_text(json.dumps(receipt) + "\n")
                        held_record.replace(evidence / "boundary-held.json")
                        return
                if restore_boundary:
                    reply = None
                    if boundary == "restore-vcpu-run":
                        # KVM_RUN = _IO(0xAE, 0x80): the vCPU's next guest entry.
                        selected = (syscall == 16 and int(info.data[2]) == 0xAE80
                                    and thread_name(tid).startswith("fc_vcpu") and logged_gate())
                    elif boundary == "restore-guest-transport":
                        selected = thread_name(tid) == "vsock muxer" and logged_gate()
                    else:
                        # Guest TX is forwarded by the virtio event owner, or
                        # by the muxer when draining pending_tx. Match bytes,
                        # not the writer's thread name or the first socket send.
                        selected = False
                        if (syscall in candidates and thread_name(group) == "krun"
                                and logged_gate() and socket_fd(tid, int(info.data[1]))):
                            key = (group, os.readlink(f"/proc/{tid}/fd/{int(info.data[1])}"))
                            payload = send_bytes(tid, syscall, info.data)
                            reply = thaw_reply(reply_bytes.get(key, b"") + payload, reply_activation)
                            selected = reply is not None
                            if not selected:
                                reply_pending[tid] = (key, payload)
                    if not selected:
                        resume(24, tid)
                        return
                    assert request.get("errno") is None, "restore activation holds never inject a result"
                    receipt = {"pid": group, "tid": tid, "syscall": syscall, "thread": thread_name(tid),
                               "arguments": [int(value) for value in info.data[1:4]],
                               "injectedReturn": False, "afterLog": after_log["needle"],
                               "monotonicNs": time.monotonic_ns(), "realtimeNs": time.time_ns()}
                    if reply is not None:
                        receipt["thawReply"] = reply
                    held, matched = tid, True
                    save_copies()
                    held_record = evidence / "boundary-held.json.tmp"
                    held_record.write_text(json.dumps(receipt) + "\n")
                    held_record.replace(evidence / "boundary-held.json")
                    return
                if syscall not in candidates:
                    resume(24, tid)
                    return
                fd = int(info.data[1])
                try:
                    fd_path = Path(f"/proc/{tid}/fd/{fd}")
                    metadata = fd_path.stat()
                    actual_path = Path(os.readlink(fd_path))
                except ProcessLookupError:
                    raise
                except OSError:
                    # Invalid or concurrently closed FDs are not candidates,
                    # but a disappeared tracee is a lost stop, not a nonmatch.
                    tracee_status(tid)
                    metadata = None
                    actual_path = None
                recent.append({"tid": tid, "syscall": syscall, "fd": fd, "path": str(actual_path) if actual_path is not None else None})
                owned_copy = actual_path is not None and actual_path.parent.name.startswith(".copy-") and actual_path.name == "file-0" and actual_path.parent.parent.parent == machines
                owned_stage = actual_path is not None and actual_path.name.startswith(".copy-") and actual_path.parent.parent == machines
                owned_child = actual_path is not None and actual_path.parent == machines and actual_path != Path(request["target"]).parent
                publication = syscall == 316 and owned_stage
                if publication:
                    publication = tracee_name(tid, int(info.data[2])) == b"file-0"
                    publication_seen = publication_seen or publication
                capture_directory = (
                    actual_path is not None
                    and actual_path.parent.name == "captures"
                    and actual_path.parent.parent.parent == machines
                )
                capture_file = (
                    actual_path is not None
                    and actual_path.parent.parent.name == "captures"
                    and actual_path.parent.parent.parent.parent == machines
                )
                capture_disk = (
                    actual_path is not None and actual_path.parent.name == "disks"
                    and actual_path.parent.parent.parent.name == "captures"
                    and actual_path.parent.parent.parent.parent.parent == machines
                )
                seal_publish = False
                if syscall == 265 and capture_directory:  # linkat: no-replace seal publication
                    seal_publish = tracee_name(tid, int(info.data[2])) == b".vm.capture.json.tmp"
                    publication_seen = publication_seen or seal_publish
                source = metadata is not None and (metadata.st_dev, metadata.st_ino) == identity
                copy_call = capture_disk and (
                    syscall in (1, 18, 20) or (syscall == 16 and info.data[2] == 0x40049409))
                if observe_copies and copy_call:
                    observation = {"path": str(actual_path), "syscall": syscall,
                                   "ioctl": int(info.data[2]) if syscall == 16 else None}
                    copy_pending[tid] = ((str(actual_path), syscall), observation)
                pool = machines.parent / "images"
                pool_content = (actual_path is not None and actual_path.name == "content"
                                and actual_path.parent.parent == pool / "tmp")
                pool_stage = actual_path is not None and actual_path.parent == pool / "tmp"
                pool_destination = (actual_path is not None and actual_path.name == "sha256"
                                    and actual_path.parent in (pool / "streams", pool / "objects"))
                pool_boundary = (
                    (boundary == "capture-pool-sync" and pool_content and syscall in (74, 75))
                    or (boundary == "capture-pool-rename" and pool_stage and syscall == 316
                        and tracee_name(tid, int(info.data[2])) == b"content")
                    or (boundary == "capture-pool-directory-sync" and pool_destination
                        and syscall in (74, 75)))
                publication_directory = publication_capture() if pool_boundary else None
                catalog_commit = False
                if (boundary == "capture-catalog-commit" and syscall in (74, 75)
                        and actual_path == machines.parent / "state.db-wal"):
                    publication_directory = publication_capture()
                    if publication_directory is not None:
                        capture_id = publication_directory.name
                        with sqlite3.connect(
                                f"file:{machines.parent / 'state.db'}?mode=ro", uri=True,
                                timeout=1) as connection:
                            row = connection.execute(
                                "SELECT json_extract(record_json,'$.candidate') "
                                "FROM storage_operation WHERE operation_id=? AND kind='capture'",
                                (capture_id,)).fetchone()
                            published = connection.execute(
                                "SELECT 1 FROM snapshot_capture_provenance WHERE capture_id=?",
                                (capture_id,)).fetchone()
                        catalog_commit = row is not None and row[0] is not None and published is None
                selected = ((boundary == "source-sync" and syscall in (74, 75) and source)
                            or (boundary == "source-read" and syscall in (0, 5, 8, 17) and source)
                            or (boundary == "boot-kernel-copy" and syscall in (1, 18, 20)
                                and actual_path is not None and actual_path.parent.parent == machines
                                and actual_path.name.startswith(".kernel-") and actual_path.name.endswith(".tmp"))
                            or (boundary == "destination-copy" and owned_copy and (syscall in (1, 18, 20) or (syscall == 16 and info.data[2] == 0x40049409)))
                            or (boundary == "destination-sync" and owned_copy and syscall in (74, 75))
                            or (boundary == "publication-rename" and publication)
                            or (boundary == "destination-directory-sync" and publication_seen and syscall == 74 and (owned_stage or owned_child) and metadata is not None and stat.S_ISDIR(metadata.st_mode))
                            or (boundary == "capture-disk-sync" and capture_disk and syscall in (74, 75))
                            or (boundary == "capture-execution-sync" and capture_file and actual_path.name == "execution.state" and syscall in (74, 75))
                            or (boundary == "capture-ram-sync" and capture_file and actual_path.name == "memory.ram" and syscall in (74, 75))
                            or (boundary == "capture-seal-publish" and seal_publish)
                            or (boundary == "capture-seal-sync" and publication_seen and capture_directory and syscall in (74, 75))
                            or (boundary == "capture-source-sync" and capture_file and actual_path.name == ".vm.capture-source.json.tmp" and syscall in (74, 75))
                            or (boundary == "capture-disk-copy" and copy_call
                                and actual_path.name == request.get("captureDiskName", actual_path.name))
                            or (pool_boundary and publication_directory is not None)
                            or catalog_commit)
                if selected:
                    assert metadata is not None
                    injected_errno = request.get("errno")
                    receipt = {"pid": group, "tid": tid, "fd": fd, "syscall": syscall, "device": metadata.st_dev, "inode": metadata.st_ino, "target": str(actual_path), "injectedReturn": injected_errno is not None}
                    if publication_directory is not None:
                        receipt["captureDirectory"] = str(publication_directory)
                    receipt["source"] = {"path": request["target"], "device": identity[0], "inode": identity[1]}
                    if injected_errno is not None:
                        assert injected_errno in (errno.EIO, errno.ENOSPC, errno.EACCES)
                        registers = Registers()
                        ptrace(12, tid, 0, ctypes.byref(registers))
                        registers.orig_rax = 0xffffffffffffffff
                        # Record the obligation before mutating registers: a
                        # lost SETREGS stop must not erase an unchecked return.
                        pending_injection[tid] = {**receipt, "errno": injected_errno, "kind": "injected syscall failure, not physical media/power-loss failure"}
                        ptrace(13, tid, 0, ctypes.byref(registers))
                    held = tid
                    matched = True
                    save_copies()
                    held_record = evidence / "boundary-held.json.tmp"
                    held_record.write_text(json.dumps(receipt) + "\n")
                    held_record.replace(evidence / "boundary-held.json")
                    return
        deliver = stopped if stopped not in (signal.SIGTRAP, signal.SIGSTOP, signal.SIGTRAP | 0x80) else 0
        # After the required boundary/checked injected return, retain
        # lifecycle tracing and EXITKILL without stopping every syscall.
        resume(24 if event != 6 and (not matched or observe_net or tid in pending_injection) else 7, tid, deliver)

    def cancelled(_signal, _frame) -> None:
        raise InterruptedError("owned stopped boundary controller cancelled")

    signal.signal(signal.SIGTERM, cancelled)
    try:
        while True:
            assert time.monotonic() < deadline, f"actual operation exceeded 240s: {tracked}; announced: {dict(+unaccounted)}; lost stops: {awaiting_terminal}"
            if held is not None and Path(request["release"]).is_file():
                resume(24 if observe_net or held in pending_injection else 7, held)
            try:
                tid, status = os.waitpid(-1, os.WNOHANG | 0x40000000)
            except ChildProcessError:
                # A lost GETEVENTMSG may hide an auto-attached child until
                # its own wait stop. Drain all real waits, not just known TIDs.
                assert not tracked and not +unaccounted, f"missing terminal wait for tracees: {tracked}; announced: {dict(+unaccounted)}; lost stops: {awaiting_terminal}"
                break
            if tid == 0:
                signal.sigtimedwait({signal.SIGCHLD}, 0.05)
                continue
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                lifecycle("wait-terminal", tid, status=status, code=os.waitstatus_to_exitcode(status),
                          lost_stop=awaiting_terminal.get(tid), pending_injection=tid in pending_injection)
                if held == tid:
                    held = None
                retire(tid)
                if tid == root:
                    root_result = os.waitstatus_to_exitcode(status)
                assert tid not in pending_injection, f"terminal wait lost a required injected return for tid {tid}"
                continue
            assert os.WIFSTOPPED(status), (tid, status)
            tracked.add(tid)
            if held == tid:
                # SIGKILL can replace the held syscall stop with TRACEEXIT
                # before the release file arrives. The new wait owns that
                # stop; only a later terminal wait proves the tracee exited.
                lifecycle("held-stop-superseded", tid,
                          held_status=stopped_status[tid], status=status,
                          pending_injection=tid in pending_injection)
                held = None
            stopped_status[tid] = status
            try:
                handle_stop(tid, status)
            except ProcessLookupError as error:
                lost_stop(tid, error)
        assert matched and not pending_injection and not awaiting_terminal, "missing real syscall boundary/checked injected return/terminal wait; inspect boundary-command.log and boundary-lifecycle.jsonl"
        (evidence / "boundary-result.json").write_text(json.dumps({"returncode": root_result}) + "\n")
    finally:
        for fd in owners.values():
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
        cleanup = time.monotonic() + 10
        while time.monotonic() < cleanup:
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
                unaccounted[tid] -= 1
            else:
                tracked.add(tid)
                try:
                    ptrace(7, tid, 0, signal.SIGKILL)
                except OSError as error:
                    if error.errno != errno.ESRCH:
                        raise
        for fd in owners.values():
            os.close(fd)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        save_copies()
        (evidence / "boundary-trace.json").write_text(json.dumps({
            "boundary": boundary, "matched": matched,
            "source": {"path": request["target"], "device": identity[0], "inode": identity[1]},
            "syscallEntries": dict(syscall_counts), "recentCandidates": list(recent),
            "awaitingTerminal": awaiting_terminal,
        }, indent=2) + "\n")
        assert not tracked and not +unaccounted, f"unreaped owned tracees: {tracked}; announced: {dict(+unaccounted)}"


if __name__ == "__main__":
    main()
