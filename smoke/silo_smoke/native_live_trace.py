"""Hold one real native RAM-output syscall thread, without substituting a return.

Only the dedicated VM's main TID is traced; its API caller thread keeps running.
WSTOPPED-only waitid consumes ptrace stops, never process exits. Popen remains the
sole process reaper. The held descriptor/inode proves native accepted ownership
before the caller times out. Detach/terminal cleanup precedes every owner stop.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import signal
import threading
import time

from .shutdown_trace import SyscallInfo


def _record_restore_wait(value: os.waitid_result | None, tracked: set[int],
                         stopped: dict[int, int]) -> int | None:
    if value is None:
        return None
    # Linux can report a ptrace stop even to a WEXITED-only wait.
    # si_code, not the requested mask, determines whether an owner exited.
    if value.si_code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED):
        tracked.discard(value.si_pid)
        stopped.pop(value.si_pid, None)
        return None
    if value.si_code not in (os.CLD_STOPPED, os.CLD_TRAPPED):
        raise RuntimeError(f"unexpected owned restore wait event: {value}")
    stopped[value.si_pid] = value.si_status
    return value.si_status


class NativeIoHold:
    def __init__(self, pid: int, target: Path, *, expected_kill=False):
        self.pid = pid
        self.target = str(target.resolve())
        self.expected_kill = expected_kill
        self.ready = threading.Event()
        self.held = threading.Event()
        self.release = threading.Event()
        self.failure = None
        self.record = None
        self.thread = threading.Thread(target=self._trace, name="native-api-real-io-boundary")

    def __enter__(self):
        self.thread.start()
        if not self.ready.wait(5):
            self.release.set()
            self.thread.join(35)
            raise TimeoutError("native I/O tracer admission bound")
        if self.failure is not None:
            self.thread.join(35)
            raise self.failure
        return self

    def __exit__(self, _kind, _value, _traceback):
        self.release.set()
        self.thread.join(35)
        if self.thread.is_alive():
            raise TimeoutError("native I/O tracer did not detach; owner remains retained")
        if self.failure is not None:
            raise self.failure

    def _trace(self):
        libc = ctypes.CDLL(None, use_errno=True)
        libc.ptrace.restype = ctypes.c_long
        libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
        end = time.monotonic() + 30
        deliver = 0
        attached = stopped = False

        def ptrace(operation, address=0, data=0):
            result = libc.ptrace(operation, self.pid,
                ctypes.c_void_p(address) if isinstance(address, int) else address,
                ctypes.c_void_p(data) if isinstance(data, int) else data)
            if result == -1:
                raise OSError(ctypes.get_errno(), f"ptrace {operation}, owned native TID {self.pid}")
            return result

        def wait_stop():
            while time.monotonic() < end:
                value = os.waitid(os.P_PID, self.pid, os.WSTOPPED | os.WNOHANG | 0x40000000)
                if value is not None:
                    return value.si_status
                time.sleep(.0001)
            raise TimeoutError("owned native syscall-stop bound")

        try:
            ptrace(0x4206, 0, 1 | 0x00100000)  # SEIZE, TRACESYSGOOD, EXITKILL.
            attached = True
            ptrace(0x4207)  # INTERRUPT only this TID, not the native caller thread.
            wait_stop()
            stopped = True
            self.ready.set()
            while not self.release.is_set() and time.monotonic() < end:
                ptrace(24, 0, deliver)  # SYSCALL, preserving real non-trap signals.
                deliver = 0
                stopped = False
                status = wait_stop()
                stopped = True
                if (status & 0xff) != (signal.SIGTRAP | 0x80):
                    deliver = status & 0xff
                    if deliver in (signal.SIGTRAP, signal.SIGSTOP):
                        deliver = 0
                    continue
                info = SyscallInfo()
                ptrace(0x420e, ctypes.sizeof(info), ctypes.byref(info))
                if info.op != 1 or int(info.data[0]) not in (18, 77, 296, 328):
                    continue
                fd = int(info.data[1])
                descriptor = Path(f"/proc/{self.pid}/fd/{fd}")
                try:
                    name = os.readlink(descriptor)
                    metadata = descriptor.stat()
                except FileNotFoundError:
                    continue
                if name != self.target:
                    continue
                self.record = {"pid":self.pid,"tid":self.pid,"fd":fd,"syscall":int(info.data[0]),
                    "device":metadata.st_dev,"inode":metadata.st_ino,"path":name,
                    "held_monotonic_ns":time.monotonic_ns(),"injected_return":False,
                    "scope":"actual accepted native output syscall; only event-loop TID held, API caller continues"}
                self.held.set()
                if not self.release.wait(max(0, end-time.monotonic())):
                    raise TimeoutError("actual accepted native I/O hold bound")
                break
            if not self.held.is_set() and not self.release.is_set():
                raise TimeoutError("native RAM output boundary was not observed")
        except BaseException as error:
            self.failure = error
        finally:
            self.ready.set()
            if attached:
                try:
                    if not stopped:
                        ptrace(0x4207)
                        wait_stop()
                    ptrace(17, 0, deliver)  # DETACH, completing the real syscall unchanged.
                    if self.record is not None:
                        self.record["detached_monotonic_ns"] = time.monotonic_ns()
                except ProcessLookupError as error:
                    ended = None
                    until = time.monotonic() + 1
                    while self.expected_kill and ended is None and time.monotonic() < until:
                        ended = os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                        if ended is None:
                            time.sleep(.001)
                    if ended is None or ended.si_code != os.CLD_KILLED or ended.si_status != signal.SIGKILL:
                        self.failure = error
                    elif self.record is not None:
                        self.record["actual_sigkill_observed_without_reaping"] = True
                except BaseException as error:
                    self.failure = error


def accepted_timeout(owner, directory: Path, *, kill=False) -> tuple[str, dict]:
    """Read only the real reply FIFO while tracing; never poll/reap ptrace stops."""
    import json
    import select

    command = f"capture {directory} timeout"
    started = time.monotonic_ns()
    record = {"command": command, "native_pid": owner.process.pid, "started_monotonic_ns": started}
    try:
        with NativeIoHold(owner.process.pid, directory / "memory.ram", expected_kill=kill) as held:
            owner.process.stdin.write((command + "\n").encode())
            owner.process.stdin.flush()
            until = time.monotonic() + 30
            response = None
            while time.monotonic() < until:
                ready, _, _ = select.select([owner.process.stdout], [], [], .01)
                if not ready:
                    continue
                data = os.read(owner.process.stdout.fileno(), 65536)
                if not data:
                    raise RuntimeError("native reply EOF is not positive timeout/cleanup evidence")
                owner.log.write(data)
                owner.log.flush()
                owner.control_buffer.extend(data)
                if len(owner.control_buffer) > 65536:
                    raise ValueError("native reply framing bound")
                while b"\n" in owner.control_buffer:
                    line, _, owner.control_buffer = owner.control_buffer.partition(b"\n")
                    line = line.decode("utf-8")
                    owner.replies.append(line)
                    if line.startswith(("OK capture", "ERROR capture")):
                        response = line
                if response is not None:
                    break
            if response is None:
                raise TimeoutError("actual accepted-command reply bound")
            if "CallerTimeout" not in response or not held.held.is_set() or held.record is None:
                raise ValueError(f"did not exercise accepted native I/O plus caller timeout: {response}")
            descriptor = Path(f"/proc/{owner.process.pid}/fd/{held.record['fd']}")
            metadata = descriptor.stat()
            if (metadata.st_dev, metadata.st_ino) != (held.record["device"], held.record["inode"]):
                raise ValueError("caller timeout discarded/reused accepted native output ownership")
            held.record.update(caller_timeout_observed_ns=time.monotonic_ns(),
                               descriptor_still_owned_after_timeout=True,
                               length_at_timeout=metadata.st_size)
            record["response"] = response
            record["native_io"] = held.record
            if kill:
                pidfd = os.pidfd_open(owner.process.pid)
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    held.record["sigkill_sent_ns"] = time.monotonic_ns()
                finally:
                    os.close(pidfd)
        return response, held.record
    except BaseException as error:
        record["error"] = str(error)
        raise
    finally:
        record["finished_monotonic_ns"] = time.monotonic_ns()
        with (owner.directory / "api-commands.jsonl").open("a") as output:
            output.write(json.dumps(record, sort_keys=True) + "\n")


class NativeRestoreHold:
    """Trace construction and hold the real vCPU-owner KVM_SET_REGS install."""
    def __init__(self, pid: int, *, mode="install"):
        self.pid = pid
        if mode not in ("install", "callback-max"):
            raise ValueError("closed native restore trace mode")
        self.mode = mode
        self.ready = threading.Event()
        self.release = threading.Event()
        self.failure = None
        self.record = None
        self.native_run_entries = 0
        self.thread = threading.Thread(target=self._trace, name="native-api-install-boundary")

    def __enter__(self):
        self.thread.start()
        if not self.ready.wait(5):
            self.release.set()
            self.thread.join(35)
            raise TimeoutError("native restore tracer admission bound")
        if self.failure is not None:
            self.thread.join(35)
            raise self.failure
        return self

    def __exit__(self, _kind, _value, _traceback):
        self.release.set()
        self.thread.join(35)
        if self.thread.is_alive():
            raise TimeoutError("native install tracer did not detach; owner retained")
        if self.failure is not None:
            raise self.failure

    def _trace(self):
        libc = ctypes.CDLL(None, use_errno=True)
        libc.ptrace.restype = ctypes.c_long
        libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
        tracked = {self.pid}
        stopped = {}
        held = None
        end = time.monotonic() + 30
        pending_writes = {}

        def ptrace(operation, tid, address=0, data=0):
            result = libc.ptrace(operation, tid,
                ctypes.c_void_p(address) if isinstance(address, int) else address,
                ctypes.c_void_p(data) if isinstance(data, int) else data)
            if result == -1:
                raise OSError(ctypes.get_errno(), f"ptrace {operation}, owned restore TID {tid}")
            return result

        def poll_stop(tid):
            flags = os.WSTOPPED | os.WNOHANG | 0x40000000
            if tid != self.pid:
                flags |= os.WEXITED
            value = os.waitid(os.P_PID, tid, flags)
            return _record_restore_wait(value, tracked, stopped)

        def resume(tid):
            status = stopped.pop(tid)
            deliver = status & 0xff
            if deliver in (signal.SIGTRAP, signal.SIGSTOP, signal.SIGTRAP | 0x80):
                deliver = 0
            ptrace(7 if held is not None else 24, tid, 0, deliver)

        def event(tid, status):
            nonlocal held
            if (status >> 8) == 3:  # PTRACE_EVENT_CLONE, real kernel-created owner.
                message = ctypes.c_ulong()
                ptrace(0x4201, tid, 0, ctypes.byref(message))
                tracked.add(message.value)
            if (status & 0xff) == (signal.SIGTRAP | 0x80):
                info = SyscallInfo()
                ptrace(0x420e, tid, ctypes.sizeof(info), ctypes.byref(info))
                if self.mode == "callback-max":
                    if info.op == 1 and int(info.data[0]) == 1 and int(info.data[3]) == 8:
                        name = Path(f"/proc/{tid}/comm").read_text().strip()
                        fd = int(info.data[1])
                        endpoint = os.readlink(f"/proc/{self.pid}/fd/{fd}")
                        if name == "api-prep-MAX" and "eventfd" in endpoint:
                            pending_writes[tid] = {"pid":self.pid,"tid":tid,"thread":name,"fd":fd,
                                "endpoint":endpoint,"operation":(1 << 64)-1,"injected_return":False}
                    elif info.op == 2 and tid in pending_writes:
                        value = pending_writes.pop(tid)
                        if int(info.data[0]) == 8:
                            value.update(queue_wake_bytes=8, enqueued_monotonic_ns=time.monotonic_ns(),
                                scope="actual MAX public request enqueued before eventfd wake; callback still undispatched")
                            self.record = value
                if info.op == 1 and int(info.data[0]) == 16:
                    request = int(info.data[2])
                    if request == 0xae80:
                        self.native_run_entries += 1
                    if self.mode == "install" and request == 0x4090ae82 and tid != self.pid and held is None:
                        name = Path(f"/proc/{tid}/comm").read_text().strip()
                        fd = int(info.data[1])
                        endpoint = os.readlink(f"/proc/{self.pid}/fd/{fd}")
                        if name.startswith("fc_vcpu") and "kvm-vcpu" in endpoint:
                            held = tid
                            self.record = {"pid":self.pid,"tid":tid,"thread":name,"fd":fd,
                                "endpoint":endpoint,"ioctl":request,"held_monotonic_ns":time.monotonic_ns(),
                                "injected_return":False,"native_run_entries":self.native_run_entries,
                                "scope":"actual accepted InstallExecution in native parked vCPU owner"}
                            return
            resume(tid)

        try:
            ptrace(0x4206, self.pid, 0, 1 | 8 | 0x00100000)
            ptrace(0x4207, self.pid)
            while poll_stop(self.pid) is None:
                if time.monotonic() >= end:
                    raise TimeoutError("initial restore ptrace stop")
                time.sleep(.0001)
            self.ready.set()
            resume(self.pid)
            while not self.release.is_set() and time.monotonic() < end:
                activity = False
                for tid in tuple(tracked):
                    if tid == held:
                        continue
                    status = poll_stop(tid)
                    if status is not None:
                        activity = True
                        event(tid, status)
                if not activity:
                    time.sleep(.0001)
            if self.record is None and not self.release.is_set():
                raise TimeoutError("required actual native restore boundary absent")
        except BaseException as error:
            self.failure = error
        finally:
            self.ready.set()
            # The Popen owner, not this tracer, reaps the VM process leader.
            for tid in tuple(tracked):
                try:
                    if tid not in stopped:
                        ptrace(0x4207, tid)
                        while poll_stop(tid) is None and tid in tracked and time.monotonic() < end:
                            time.sleep(.0001)
                    if tid in stopped:
                        ptrace(17, tid)
                        stopped.pop(tid, None)
                except ProcessLookupError:
                    pass
                except ChildProcessError:
                    pass
                except BaseException as error:
                    self.failure = error
            if self.record is not None:
                self.record["detached_monotonic_ns"] = time.monotonic_ns()
                self.record["native_run_entries"] = self.native_run_entries


def receive_restore_reply(owner, prefix: str, timeout: float = 30) -> str:
    """Bounded real FIFO framing with no process polling during ptrace stops."""
    import select

    until = time.monotonic() + timeout
    while time.monotonic() < until:
        for line in owner.replies:
            if line.startswith(prefix + " "):
                return line
        ready, _, _ = select.select([owner.process.stdout], [], [], .01)
        if not ready:
            continue
        data = os.read(owner.process.stdout.fileno(), 65536)
        if not data:
            raise RuntimeError(f"reply EOF before actual {prefix}; not cleanup/started evidence")
        owner.log.write(data)
        owner.log.flush()
        owner.control_buffer.extend(data)
        if len(owner.control_buffer) > 65536:
            raise ValueError("restore proof reply bound")
        while b"\n" in owner.control_buffer:
            line, _, owner.control_buffer = owner.control_buffer.partition(b"\n")
            owner.replies.append(line.decode("utf-8"))
    raise TimeoutError(f"bounded explicit restore reply: {prefix}")
