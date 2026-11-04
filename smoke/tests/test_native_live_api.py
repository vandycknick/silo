from __future__ import annotations

import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
import time

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


if __name__ == "__main__":
    unittest.main()
