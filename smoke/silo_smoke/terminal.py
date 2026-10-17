"""PTY execution with terminal-mode observation and bounded waits."""

from __future__ import annotations

import errno
import fcntl
import os
import pty
import select
import shlex
import signal
import struct
import subprocess
import termios
import threading
import time
from typing import TYPE_CHECKING

from .errors import SmokeAssertion

if TYPE_CHECKING:
    from .workspace import Workspace


class PtyCommand:
    def __init__(self, ws: Workspace, argv: list[str], rows: int = 37, cols: int = 119, label: str = "pty") -> None:
        self.ws = ws
        self.argv = argv
        self.label = label
        self._output = bytearray()
        self._condition = threading.Condition()
        self._raw_mode_seen = False
        self._restored = False
        self._finished = False
        self._reader_error: OSError | None = None
        self._recorded = False
        master, slave = pty.openpty()
        self._master = master
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
            self._initial_lflag = termios.tcgetattr(master)[3]
            os.set_blocking(master, False)

            def child_setup() -> None:
                os.setsid()
                fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

            env = ws.env()
            env["TERM"] = "xterm"
            self.proc: subprocess.Popen[bytes] = subprocess.Popen(
                argv, env=env, stdin=slave, stdout=slave, stderr=slave,
                preexec_fn=child_setup, pass_fds=(slave,), start_new_session=False,
            )
        except BaseException:
            os.close(master)
            raise
        finally:
            os.close(slave)
        self._reader = threading.Thread(target=self._read, name=f"pty-{self.proc.pid}", daemon=True)
        self._reader.start()

    def _sample_mode(self) -> None:
        flags = termios.tcgetattr(self._master)[3]
        with self._condition:
            if not flags & termios.ECHO or not flags & termios.ICANON:
                self._raw_mode_seen = True

    def _read(self) -> None:
        try:
            while True:
                self._sample_mode()
                readable, _, _ = select.select([self._master], [], [], 0.01)
                if not readable:
                    continue
                try:
                    data = os.read(self._master, 8192)
                except BlockingIOError:
                    continue
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
                self._sample_mode()
                if not data:
                    break
                with self._condition:
                    self._output.extend(data)
                    self._condition.notify_all()
        except OSError as exc:
            self._reader_error = exc
        finally:
            with self._condition:
                self._finished = True
                self._condition.notify_all()

    @property
    def output(self) -> bytes:
        with self._condition:
            return bytes(self._output)

    @property
    def raw_mode_seen(self) -> bool:
        with self._condition:
            return self._raw_mode_seen

    @property
    def restored(self) -> bool:
        return self._restored

    def wait_for(self, needle: bytes, timeout: float = 30) -> bytes:
        deadline = time.monotonic() + timeout
        with self._condition:
            while needle not in self._output:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self._finished:
                    raise SmokeAssertion(f"PTY did not produce {needle!r}: {bytes(self._output)!r}")
                self._condition.wait(remaining)
            return bytes(self._output)

    def write(self, data: bytes) -> None:
        remaining = memoryview(data)
        while remaining:
            try:
                count = os.write(self._master, remaining)
            except BlockingIOError:
                select.select([], [self._master], [], 0.1)
                continue
            remaining = remaining[count:]

    def resize(self, rows: int, cols: int) -> None:
        fcntl.ioctl(self._master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        os.kill(self.proc.pid, signal.SIGWINCH)

    def signal(self, sig: int) -> None:
        os.kill(self.proc.pid, sig)

    def _record(self) -> None:
        if not self._recorded:
            self.ws.record(self.label, f"$ {shlex.join(self.argv)}\n{self.output.decode(errors='replace')}\n")
            self._recorded = True

    def wait(self, timeout: float = 60) -> int:
        deadline = time.monotonic() + timeout
        try:
            code = self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            self._record()
            raise SmokeAssertion(f"PTY process timed out after {timeout}s: {self.output!r}") from exc
        self._reader.join(max(0, deadline - time.monotonic()))
        self._record()
        if self._reader.is_alive():
            raise SmokeAssertion(f"PTY output did not close after process exit: {self.output!r}")
        if self._master >= 0:
            try:
                self._restored = termios.tcgetattr(self._master)[3] == self._initial_lflag
            finally:
                os.close(self._master)
                self._master = -1
        if self._reader_error is not None:
            raise SmokeAssertion(f"PTY reader failed: {self._reader_error}; output: {self.output!r}") from self._reader_error
        return code
