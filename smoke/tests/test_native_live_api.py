from __future__ import annotations

import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
import time

from silo_smoke import shutdown
from silo_smoke.native_live_api import cleanup_session, make_session_type
from silo_smoke.native_live_trace import _record_restore_wait


class ApiConstructorCleanupTests(unittest.TestCase):
    """Exercise Silo's owner wrapper over the actual frozen native close/create API.

    Only ordinary Python subprocesses are launched, never a native VM or a fake
    native API. SILO_NATIVE_ROOT selects the read-only production checkout.
    """

    @classmethod
    def setUpClass(cls) -> None:
        native_root = os.environ.get("SILO_NATIVE_ROOT")
        if native_root is None:
            raise unittest.SkipTest("set SILO_NATIVE_ROOT to the frozen native checkout")
        examples = Path(native_root).resolve(strict=True) / "src/libkrun/examples"
        sys.path.insert(0, str(examples))
        try:
            cls.session_type = make_session_type()
        finally:
            sys.path.remove(str(examples))

    def constructor_failure(self, directory: Path, *, running: bool = False,
                            bad_fd: bool = False, exit_status: int = 1):
        owners = []
        original = RuntimeError(f"native process exited before stop: {exit_status}")

        class FailingSession(self.session_type):
            def __init__(self, args, path):
                self.directory = path
                path.mkdir()
                args.sessions.append(self)
                # The unit under test owns actual children and descriptors, not
                # simulated Popen/cleanup methods or synthetic native responses.
                self.netd = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.launched_netd = self.netd
                with (path / "driver.stderr").open("wb") as error:
                    self.process = subprocess.Popen(
                        [sys.executable, "-c", "import time; time.sleep(30)" if running else
                         f"import sys; sys.stderr.write('original restore error\\n'); sys.exit({exit_status})"],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error)
                self.launched_process = self.process
                if not running:
                    self.process.wait(timeout=5)
                if bad_fd:
                    self.fds = [-1]
                raise original

        with self.assertRaises(RuntimeError) as raised:
            FailingSession.create(SimpleNamespace(sessions=owners), directory)
        self.assertIs(raised.exception, original)
        self.assertEqual(len(owners), 1)
        owner = owners[0]
        if not bad_fd:
            self.addCleanup(owner.close)
        self.assertIsNone(owner.process)
        self.assertIsNotNone(owner.launched_process.returncode)
        self.assertIsNotNone(owner.launched_netd.returncode)
        self.assertTrue(owner.launched_process.stdin.closed)
        self.assertTrue(owner.launched_process.stdout.closed)
        return owner, original

    def test_constructor_exit_retains_wait_status_without_native_stop(self) -> None:
        for status in (0, 1):
            with self.subTest(exit_status=status), tempfile.TemporaryDirectory() as temporary:
                owner, original = self.constructor_failure(Path(temporary) / "child", exit_status=status)
                report = cleanup_session(owner)
                self.assertEqual(report["construction_error"], str(original))
                self.assertEqual(report["process_pid"], owner.launched_process.pid)
                self.assertEqual(report["process_exit_status"], status)
                self.assertTrue(report["os_reaped"])
                self.assertTrue(report["terminal"])
                self.assertFalse(report["native_stop_acknowledged"])
                self.assertIsNone(report["native_failure_cleanup"])
                self.assertEqual(report["errors"], [])
                self.assertEqual(cleanup_session(owner), report)
                self.assertEqual((owner.directory / "driver.stderr").read_text(), "original restore error\n")

    def test_constructor_forced_reap_remains_a_cleanup_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            owner, original = self.constructor_failure(Path(temporary) / "child", running=True)
            report = cleanup_session(owner)
            self.assertEqual(report["construction_error"], str(original))
            self.assertEqual(report["process_exit_status"], -signal.SIGKILL)
            self.assertTrue(report["os_reaped"])
            self.assertFalse(report["native_stop_acknowledged"])
            self.assertIsNone(report["native_failure_cleanup"])
            self.assertEqual(report["errors"], [
                "native driver required forced process reap, no native stop acknowledgement"])
            self.assertEqual(cleanup_session(owner), report)

    def test_constructor_cleanup_exception_does_not_replace_original(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            owner, original = self.constructor_failure(Path(temporary) / "child", bad_fd=True)
            report = cleanup_session(owner)
            self.assertEqual(report["construction_error"], str(original))
            self.assertEqual(report["process_exit_status"], 1)
            self.assertTrue(report["os_reaped"])
            self.assertFalse(report["native_stop_acknowledged"])
            self.assertIsNone(report["native_failure_cleanup"])
            self.assertEqual(len(report["errors"]), 1)
            self.assertIn("Bad file descriptor", report["errors"][0])
            owner.fds = []
            self.assertEqual(owner.close(), [])
            self.assertEqual(cleanup_session(owner), report)


@unittest.skipUnless(sys.platform == "linux", "Linux ptrace wait semantics")
class RestoreTraceWaitTests(unittest.TestCase):
    def test_exited_mask_does_not_discard_a_live_ptrace_stopped_owner(self) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.ptrace.restype = ctypes.c_long
        libc.ptrace.argtypes = [
            ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"])
        attached = False
        try:
            self.assertEqual(libc.ptrace(0x4206, child.pid, None, None), 0,
                             ctypes.get_errno())
            attached = True
            self.assertEqual(libc.ptrace(0x4207, child.pid, None, None), 0,
                             ctypes.get_errno())
            value = None
            deadline = time.monotonic() + 5
            while value is None and time.monotonic() < deadline:
                value = os.waitid(
                    os.P_PID, child.pid, os.WEXITED | os.WNOHANG | 0x40000000)
                if value is None:
                    time.sleep(.001)
            self.assertIsNotNone(value)
            self.assertEqual(value.si_code, os.CLD_TRAPPED)
            tracked = {child.pid}
            stopped = {}
            self.assertEqual(_record_restore_wait(value, tracked, stopped),
                             value.si_status)
            self.assertEqual(tracked, {child.pid})
            self.assertEqual(stopped, {child.pid: value.si_status})
            self.assertEqual(libc.ptrace(17, child.pid, None, None), 0,
                             ctypes.get_errno())
            attached = False
            child.kill()
            exited = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT)
            self.assertEqual(exited.si_code, os.CLD_KILLED)
            self.assertEqual(exited.si_status, signal.SIGKILL)
            self.assertIsNone(_record_restore_wait(exited, tracked, stopped))
            self.assertEqual(tracked, set())
            self.assertEqual(stopped, {})
            self.assertEqual(child.wait(timeout=5), -signal.SIGKILL)
        finally:
            if attached:
                libc.ptrace(17, child.pid, None, None)
            if child.returncode is None:
                child.kill()
                child.wait(timeout=5)


@unittest.skipUnless(
    sys.platform == "linux" and platform.machine() == "x86_64",
    "Linux x86_64 ptrace syscall boundaries",
)
class StoppedTraceLifecycleTests(unittest.TestCase):
    def run_controller(self, directory: Path, operation: int, phase: str) -> tuple[subprocess.CompletedProcess[str], list[dict], dict]:
        target = directory / "source"
        target.write_bytes(b"real fsync boundary\n")
        release = directory / "release"
        if not phase.startswith("held"):
            release.touch()
        driver = directory / "driver.py"
        driver.write_text(textwrap.dedent("""\
            import errno
            import json
            import os
            from pathlib import Path
            import subprocess
            import sys
            import threading
            if sys.argv[3] == "exec" and len(sys.argv) == 4:
                thread = threading.Thread(
                    target=os.execv, args=(sys.executable, [sys.executable, *sys.argv, "continued"]))
                thread.start()
                thread.join()
                raise AssertionError("nonleader exec unexpectedly returned")
            subprocess.run([sys.executable, "-c", "import os; os._exit(0)"], check=False)
            fd = os.open(sys.argv[1], os.O_RDWR)
            result = 0
            try:
                os.fsync(fd)
            except OSError as error:
                assert error.errno == errno.EIO
                result = error.errno
            finally:
                os.close(fd)
            Path(sys.argv[2]).write_text(json.dumps({"errno": result}))
            """))
        request = directory / "request.json"
        request.write_text(json.dumps({
            "command": [sys.executable, str(driver), str(target), str(directory / "return.json"), phase],
            "target": str(target), "boundary": "source-sync",
            "machines": str(directory / "machines"), "evidence": str(directory),
            "release": str(release),
            **({"errno": errno.EIO} if phase not in ("startup", "exec", "held") else {}),
        }))
        # Schedule real SIGKILL at an observed stop, or after publishing the
        # held boundary and before release. Never replace ptrace, /proc, wait
        # results or return values; leave terminal waits to the controller.
        bootstrap = textwrap.dedent("""\
            import ctypes
            import errno
            import json
            import os
            from pathlib import Path
            import runpy
            import signal
            import sys
            import time
            request, operation, phase = sys.argv[1:]
            operation = int(operation)
            evidence = Path(request).parent
            libc = ctypes.CDLL(None, use_errno=True)
            libc.ptrace.restype = ctypes.c_long
            libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
            fired = False
            killed_held = False
            def schedule(frame, event, arg):
                global fired, killed_held
                if fired:
                    return None
                if not frame.f_code.co_filename.endswith("/silo_smoke/stopped_trace.py"):
                    return None
                if (phase.startswith("held") and not killed_held
                        and event == "return" and frame.f_code.co_name == "handle_stop"
                        and frame.f_locals["held"] == frame.f_locals["tid"]
                        and (evidence / "boundary-held.json").is_file()):
                    # SIGKILL supersedes a held syscall stop with TRACEEXIT.
                    # Keep release absent until that new stop is resumed.
                    killed_held = True
                    os.kill(frame.f_locals["tid"], signal.SIGKILL)
                    return None
                if event != "call" or frame.f_code.co_name != "ptrace":
                    return schedule
                if frame.f_locals["op"] != operation:
                    return None
                caller = frame.f_back
                main = caller
                while main is not None and main.f_code.co_name != "main":
                    main = main.f_back
                if main is None:
                    return None
                tid = frame.f_locals["tid"]
                if phase.startswith("held"):
                    if (not killed_held or tid != main.f_locals["root"]
                            or main.f_locals["stopped_status"][tid] >> 16 != 6):
                        return None
                    fired = True
                    (evidence / "release").touch()
                    (evidence / "race.json").write_text(json.dumps({"tid": tid, "operation": operation}))
                    return None
                if phase == "startup":
                    if tid == main.f_locals["root"]:
                        return None
                else:
                    info = caller.f_locals.get("info")
                    if info is None or info.op != (1 if phase == "entry" else 2):
                        return None
                fired = True
                os.kill(tid, signal.SIGKILL)
                deadline = time.monotonic() + 5
                while True:
                    assert time.monotonic() < deadline, "killed tracee did not become terminal"
                    value = os.waitid(os.P_PID, tid,
                                     os.WEXITED | os.WSTOPPED | os.WNOHANG | os.WNOWAIT | 0x40000000)
                    if value is None:
                        time.sleep(.001)
                        continue
                    if value.si_code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED):
                        break
                    # TRACEEXIT is an early stop, not death. Resume it and
                    # wait for the actual kernel terminal status without reap.
                    stopped_tid, status = os.waitpid(tid, 0x40000000)
                    assert stopped_tid == tid and os.WIFSTOPPED(status)
                    result = libc.ptrace(7, tid, None, None)
                    assert result == 0 or ctypes.get_errno() == errno.ESRCH
                (evidence / "race.json").write_text(json.dumps({"tid": tid, "operation": operation}))
                return None
            sys.argv = ["silo_smoke.stopped_trace", request]
            sys.settrace(schedule)
            runpy.run_module("silo_smoke.stopped_trace", run_name="__main__")
            """)
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        result = subprocess.run(
            [sys.executable, "-c", bootstrap, str(request), str(operation), phase],
            env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=25,
        )
        events = [json.loads(line) for line in (directory / "boundary-lifecycle.jsonl").read_text().splitlines()]
        race = json.loads((directory / "race.json").read_text()) if phase not in ("none", "exec") else {}
        return result, events, race

    def test_capture_execution_pwrite_is_held_before_any_output_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            machines = directory / "machines"
            source = machines / "source/root.raw"
            execution = machines / "source/captures/cut/execution.state"
            execution.parent.mkdir(parents=True)
            source.write_bytes(b"private source\n")
            execution.touch(mode=0o600)
            release = directory / "release"
            request = directory / "request.json"
            request.write_text(json.dumps({
                "command": [sys.executable, "-c",
                            "import os, sys; fd = os.open(sys.argv[1], os.O_RDWR); "
                            "os.pwrite(fd, b'execution bytes', 0); os.close(fd)", str(execution)],
                "target": str(source), "boundary": "capture-execution-write",
                "machines": str(machines), "evidence": str(directory), "release": str(release),
            }))
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
            controller = subprocess.Popen(
                [sys.executable, "-m", "silo_smoke.stopped_trace", str(request)],
                env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            try:
                def held() -> dict | None:
                    marker = directory / "boundary-held.json"
                    if marker.is_file():
                        return json.loads(marker.read_text())
                    self.assertIsNone(controller.poll(), "execution boundary controller exited")
                    return None

                receipt = shutdown.until(held, timeout=5, description="pwrite64 gate was not reached")
                self.assertEqual(receipt["syscall"], 18)
                self.assertEqual(receipt["target"], str(execution))
                self.assertFalse(receipt["injectedReturn"])
                self.assertEqual(execution.read_bytes(), b"")
                self.assertFalse((execution.parent / "vm.capture.json").exists())
            finally:
                release.touch()
                try:
                    output, _ = controller.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    controller.kill()
                    controller.communicate(timeout=5)
                    raise
            self.assertEqual(controller.returncode, 0, output)
            self.assertEqual(execution.read_bytes(), b"execution bytes")
            self.assertEqual(source.read_bytes(), b"private source\n")

    def test_disappearing_startup_stop_keeps_real_wait_and_later_boundary(self) -> None:
        for operation in (0x4200, 0x4201, 0x420E):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                result, events, race = self.run_controller(directory, operation, "startup")
                self.assertEqual(result.returncode, 0, result.stdout)
                lost = [event for event in events if event["event"] == "lost-stop-awaiting-terminal" and event["tid"] == race["tid"]]
                self.assertEqual(len(lost), 1, events)
                terminal = [event for event in events if event["event"] == "wait-terminal" and event["tid"] == race["tid"]]
                self.assertEqual(len(terminal), 1, events)
                self.assertEqual(terminal[0]["code"], -signal.SIGKILL)
                self.assertIsNotNone(terminal[0]["lost_stop"])
                self.assertFalse(terminal[0]["pending_injection"])
                self.assertEqual(json.loads((directory / "boundary-result.json").read_text()), {"returncode": 0})
                self.assertEqual(json.loads((directory / "return.json").read_text()), {"errno": 0})
                self.assertEqual(json.loads((directory / "boundary-held.json").read_text())["target"], str(directory / "source"))

    def test_lost_register_inspection_never_fabricates_injection_or_boundary(self) -> None:
        for phase, operation in (("entry", 12), ("entry", 13), ("exit", 12), ("exit", 13)):
            with self.subTest(phase=phase, operation=operation), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                result, events, race = self.run_controller(directory, operation, phase)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                terminal = [event for event in events if event["event"] == "wait-terminal" and event["tid"] == race["tid"]]
                self.assertEqual(len(terminal), 1, result.stdout)
                self.assertEqual(terminal[0]["code"], -signal.SIGKILL)
                self.assertIsNotNone(terminal[0]["lost_stop"])
                self.assertEqual(terminal[0]["pending_injection"], phase == "exit" or operation == 13)
                self.assertFalse((directory / "boundary-result.json").exists())
                self.assertFalse((directory / "boundary-injected.json").exists())
                self.assertEqual((directory / "boundary-held.json").exists(), phase == "exit")
                expected = "missing real syscall boundary" if phase == "entry" and operation == 12 else "terminal wait lost a required injected return"
                self.assertIn(expected, result.stdout)

    def test_killed_held_stop_is_superseded_before_late_release_and_terminal_wait(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            result, events, race = self.run_controller(directory, 7, "held")
            self.assertEqual(result.returncode, 0, result.stdout)
            superseded = [event for event in events if event["event"] == "held-stop-superseded"]
            self.assertEqual(len(superseded), 1, events)
            self.assertEqual(superseded[0]["tid"], race["tid"])
            self.assertEqual(os.WSTOPSIG(superseded[0]["held_status"]), signal.SIGTRAP | 0x80)
            self.assertEqual(superseded[0]["status"] >> 16, 6)
            self.assertFalse(superseded[0]["pending_injection"])
            terminal = [event for event in events if event["event"] == "wait-terminal" and event["tid"] == race["tid"]]
            self.assertEqual(len(terminal), 1, events)
            self.assertEqual(terminal[0]["code"], -signal.SIGKILL)
            self.assertFalse(terminal[0]["pending_injection"])
            self.assertLess(events.index(superseded[0]), events.index(terminal[0]))
            self.assertEqual(json.loads((directory / "boundary-result.json").read_text()),
                             {"returncode": -signal.SIGKILL})
            self.assertTrue((directory / "release").is_file())
            self.assertFalse((directory / "return.json").exists())
            self.assertFalse(any(event["event"] == "cleanup-wait-terminal" for event in events))

    def test_killed_held_stop_keeps_injected_return_obligation_until_terminal_wait(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            result, events, race = self.run_controller(directory, 7, "held-injected")
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("terminal wait lost a required injected return", result.stdout)
            self.assertNotIn("resume without an observed ptrace stop", result.stdout)
            superseded = [event for event in events if event["event"] == "held-stop-superseded"]
            self.assertEqual(len(superseded), 1, events)
            self.assertEqual(superseded[0]["tid"], race["tid"])
            self.assertTrue(superseded[0]["pending_injection"])
            terminal = [event for event in events if event["event"] == "wait-terminal" and event["tid"] == race["tid"]]
            self.assertEqual(len(terminal), 1, events)
            self.assertEqual(terminal[0]["code"], -signal.SIGKILL)
            self.assertTrue(terminal[0]["pending_injection"])
            self.assertLess(events.index(superseded[0]), events.index(terminal[0]))
            self.assertTrue((directory / "release").is_file())
            self.assertFalse((directory / "boundary-injected.json").exists())
            self.assertFalse((directory / "boundary-result.json").exists())

    def test_checked_injected_return_is_observed_by_real_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            result, events, _ = self.run_controller(directory, 0, "none")
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(json.loads((directory / "return.json").read_text()), {"errno": errno.EIO})
            self.assertEqual(json.loads((directory / "boundary-injected.json").read_text())["errno"], errno.EIO)
            self.assertFalse(any(event["pending_injection"] for event in events if event["event"] == "wait-terminal"))

    def test_nonleader_exec_accounts_for_collapsed_tid_before_real_root_wait(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            result, events, _ = self.run_controller(directory, -1, "exec")
            self.assertEqual(result.returncode, 0, result.stdout)
            retired = [event for event in events if event["event"] == "exec-retired-thread"]
            self.assertTrue(retired, events)
            self.assertTrue(all(event["tid"] != event["exec_tid"] for event in retired))
            self.assertFalse(any(event["pending_injection"] for event in retired))
            self.assertEqual(json.loads((directory / "boundary-result.json").read_text()), {"returncode": 0})
            self.assertEqual(json.loads((directory / "return.json").read_text()), {"errno": 0})



if __name__ == "__main__":
    unittest.main()
