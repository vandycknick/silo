"""Run only inside a disposable private user/mount namespace.

Bind-mount exactly one disposable upper file from a bounded tmpfs. Database,
logs, immutable lower and evidence stay outside. The actual worker inherits the
mount namespace. No injected errno, user-home filling, root execution, or helper
VM is involved.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import stat
import sys
import time
from uuid import UUID

from silo_smoke import overlay, procs, shutdown


def main() -> None:
    request = json.loads(Path(sys.argv[1]).read_text())
    silo = request["silo"]
    name = request["name"]
    upper = Path(request["upper"])
    scratch = Path(request["scratch"])
    evidence = Path(request["evidence"])
    assert os.getuid() == 0 and os.readlink("/proc/self/ns/user") != request["outer_user_namespace"]
    assert Path("/proc/self/uid_map").read_text().split()[1] == request["outer_uid"]
    scratch.mkdir(mode=0o700)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "size=32m,mode=0700", "overlay-enospc", str(scratch)], check=True, timeout=15)
    initial = overlay.digest(upper)
    clean_checkpoint = evidence / "host-clean-upper-source.raw"
    subprocess.run(["cp", "--reflink=auto", "--sparse=always", str(upper), str(clean_checkpoint)], check=True, timeout=60)
    clean_checkpoint.chmod(0o400)
    assert overlay.digest(clean_checkpoint) == initial
    disposable = scratch / "upper.raw"
    subprocess.run(["cp", "--sparse=always", str(upper), str(disposable)], check=True, timeout=60)
    disposable.chmod(0o600)
    assert overlay.digest(disposable) == initial
    subprocess.run(["mount", "--bind", str(disposable), str(upper)], check=True, timeout=15)
    log_offsets = {path: path.stat().st_size for directory in request["log_directories"] for path in Path(directory).rglob("*.log")}
    def run(*args: str, expect: int | None = 0, timeout: float = 90) -> subprocess.CompletedProcess:
        with (evidence / "host-enospc-controller.log").open("a") as output:
            output.write(f"$ silo {args}\n")
        try:
            result = subprocess.run([silo, *args], text=True, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            # communicate() preserves partial bytes even in text mode. Retain
            # probe stage markers before cleanup, without retrying the command.
            def text(value: str | bytes | None) -> str:
                return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
            with (evidence / "host-enospc-controller.log").open("a") as output:
                output.write(f"timeout={timeout}\nstdout:\n{text(error.stdout)}\nstderr:\n{text(error.stderr)}\n")
            raise
        with (evidence / "host-enospc-controller.log").open("a") as output:
            output.write(f"exit={result.returncode}\n{result.stdout}{result.stderr}\n")
        if expect is not None:
            assert result.returncode == expect, result.stderr
        return result
    def exhaust(stage: str) -> None:
        with (scratch / "host-fill").open("wb", buffering=0) as fill:
            block = b"h" * 65536
            try:
                while True:
                    fill.write(block)
            except OSError as error:
                assert error.errno == 28
                receipt = {"stage": stage, "errno": error.errno, "filesystem_bytes": shutil.disk_usage(scratch).total, "free_bytes": shutil.disk_usage(scratch).free, "upper_only_writable_attachment": True}
                filename = "actual-host-enospc.json" if stage == "guest" else "replacement-host-enospc.json"
                (evidence / filename).write_text(json.dumps(receipt))
    original_lock_fd = None
    try:
        run("start", name)
        deadline = time.monotonic() + 90
        while True:
            running = json.loads(run("info", name, "--format", "json").stdout)
            if running["ready"]:
                break
            assert time.monotonic() < deadline, "guest never ready before host exhaustion"
            time.sleep(0.1)
        space = run("exec", name, "--user", "root", "--", "df", "-Pk", "/run/silo/rootfs/upperfs")
        assert int(space.stdout.splitlines()[-1].split()[-3]) * 1024 > 16 * 1024**2, "guest lacks ample free blocks"
        database = Path(os.environ["SILO_HOME"]) / "state.db"
        monitor = int(procs.query(database, "SELECT json_extract(state_json,'$.vmmonPid') FROM machine_state WHERE machine_id='" + request["machine_id"] + "'")[0][0])
        worker = overlay.worker_pid_of_monitor(monitor)
        # Prove the running worker inherited the binding, not merely that the
        # controller mounted a tmpfs. Capture before exhaustion/forced cleanup.
        metadata = disposable.stat()
        backing = {"device": metadata.st_dev, "inode": metadata.st_ino}
        worker_fds = []
        for descriptor in Path(f"/proc/{worker}/fd").iterdir():
            try:
                observed = descriptor.stat()
                if (observed.st_dev, observed.st_ino) == (metadata.st_dev, metadata.st_ino):
                    worker_fds.append({"fd": descriptor.name, "target": os.readlink(descriptor)})
            except FileNotFoundError:
                continue
        namespaces = {str(pid): os.readlink(f"/proc/{pid}/ns/mnt") for pid in (os.getpid(), monitor, worker)}
        (evidence / "host-enospc-backing.json").write_text(json.dumps({"backing": backing, "workerFds": worker_fds, "mountNamespaces": namespaces, "tmpdir": os.environ.get("TMPDIR"), "filesystems": {str(path): {"device": path.stat().st_dev, "freeBytes": shutil.disk_usage(path).free} for path in (Path("/tmp"), evidence, scratch)}}, indent=2) + "\n")
        (evidence / "host-enospc-worker-mountinfo.log").write_text(Path(f"/proc/{worker}/mountinfo").read_text())
        assert worker_fds, "worker has no descriptor for the actual bounded upper"
        assert len(set(namespaces.values())) == 1, "worker did not inherit private mount namespace"
        exhaust("guest")
        result = run("exec", name, "--user", "root", "--", overlay.PROBE, "fill", "host", expect=None, timeout=120)
        assert result.returncode == 0, "guest must report actual EIO/ENOSPC through probe"
        value = json.loads(result.stdout)
        assert value["errno"] in (5, 28)
        # Normal CLI/libvm handshake must carry the sticky guest writeback
        # failure; host ENOSPC is not the separate retained-fsync-EIO gate.
        run("stop", name, "--timeout", "75s", expect=None, timeout=120)
        deadline = time.monotonic() + 90
        exited = None
        while time.monotonic() < deadline:
            if Path(request["exit_path"]).is_file():
                exit_text = Path(request["exit_path"]).read_text()
                observed = json.loads(exit_text)
                if UUID(observed["runId"]) == UUID(running["run_id"]):
                    exited = observed
                    break
            time.sleep(0.05)
        assert exited is not None, "PID1 failure-drain path produced no current-run native terminal artifact"
        overlay.assert_unforced_native_exit(exited, machine_id=request["machine_id"], run_id=running["run_id"], monitor=monitor, worker=worker)
        procs.wait_gone(worker, timeout=20)
        procs.wait_gone(monitor, timeout=20)
        assert exited["outcome"] == "error" and exited["error"]
        assert exited["storageShutdown"]["guestProtocolCompleted"] is False
        assert exited["storageShutdown"]["hostFlushCompleted"] is False
        diagnostic = exited["backend"]["diagnostic"]["tail"]
        (evidence / "host-enospc-exit.json").write_text(exit_text)
        logs = "\n".join(path.read_bytes()[log_offsets.get(path, 0):].decode(errors="replace") for directory in request["log_directories"] for path in Path(directory).rglob("*.log"))
        (evidence / "host-enospc-worker.log").write_text(logs)
        assert "No space left on device" in diagnostic or "code: 28" in diagnostic or "os error 28" in diagnostic
        shutdown.assert_failed_completion(Path(request["exit_path"]).parent, running["run_id"])
        # Keep failed bytes as evidence outside the bounded filesystem.
        subprocess.run(["cp", "--sparse=always", str(disposable), str(evidence / "host-exhausted-upper.raw")], check=True, timeout=90)
        # Restore a pre-ENOSPC private copy before the independent growth gate;
        # an aborted guest filesystem must not mask host-copy ENOSPC admission.
        (scratch / "host-fill").unlink()
        subprocess.run(["cp", "--sparse=always", str(clean_checkpoint), str(disposable)], check=True, timeout=60)
        disposable.chmod(0o600)
        assert overlay.digest(disposable) == initial
        # Preserve the real production lock inode before the whole-parent bind
        # hides its pathname. The empty file is only a mount target, never a
        # copied/replacement lock and never used by the production operation.
        original_lock = upper.parent / "node-state.lock"
        original_lock_fd = os.open(original_lock, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        original_lock_stat = os.fstat(original_lock_fd)
        assert stat.S_ISREG(original_lock_stat.st_mode)
        (scratch / "node-state.lock").touch(mode=0o600, exist_ok=False)
        exhaust("replacement")
        # While stopped, expose only the bounded disposable upper directory for
        # replacement growth. DB/log/lower/evidence and original machine files
        # remain outside, hidden rather than copied onto the exhausted volume.
        assert upper.name == "upper.raw"
        database = Path(os.environ["SILO_HOME"]) / "state.db"
        sql = "SELECT json(record_json) FROM machine_storage WHERE machine_id='" + request["machine_id"] + "'"
        before_record = procs.query(database, sql)
        before_growth = overlay.digest(disposable)
        def inventory() -> list[dict]:
            types = {stat.S_IFREG: "file", stat.S_IFDIR: "directory", stat.S_IFLNK: "symlink", stat.S_IFIFO: "fifo", stat.S_IFSOCK: "socket", stat.S_IFBLK: "block", stat.S_IFCHR: "character"}
            result = []
            for path in sorted(scratch.iterdir()):
                metadata = path.lstat()
                result.append({"name": path.name, "device": metadata.st_dev, "inode": metadata.st_ino, "type": types.get(stat.S_IFMT(metadata.st_mode), "unknown"), "mode": oct(metadata.st_mode), "sizeBytes": metadata.st_size, "links": metadata.st_nlink, "uid": metadata.st_uid, "gid": metadata.st_gid, "symlinkTarget": os.readlink(path) if stat.S_ISLNK(metadata.st_mode) else None})
            return result
        before_inventory = inventory()
        before_names = set(scratch.iterdir())
        host_failure = json.loads((evidence / "replacement-host-enospc.json").read_text())
        assert host_failure["errno"] == 28 and shutil.disk_usage(scratch).free == 0
        subprocess.run(["mount", "--bind", str(scratch), str(upper.parent)], check=True, timeout=15)
        lock_bound = False
        try:
            visible_lock = upper.parent / "node-state.lock"
            # --bind of the directory does not clone nested mounts. Bind the
            # held original explicitly AFTER the directory is visible. Do not
            # canonicalize /proc/self/fd back to the now-hidden pathname.
            subprocess.run(["mount", "--no-canonicalize", "--bind", f"/proc/self/fd/{original_lock_fd}", str(visible_lock)], pass_fds=(original_lock_fd,), check=True, timeout=15)
            lock_bound = True
            visible_lock_stat = visible_lock.stat()
            lock_binding = {"sourceFd": original_lock_fd, "sourcePath": str(original_lock), "visiblePath": str(visible_lock), "original": {"device": original_lock_stat.st_dev, "inode": original_lock_stat.st_ino, "sizeBytes": original_lock_stat.st_size, "mode": oct(original_lock_stat.st_mode)}, "visible": {"device": visible_lock_stat.st_dev, "inode": visible_lock_stat.st_ino, "sizeBytes": visible_lock_stat.st_size, "mode": oct(visible_lock_stat.st_mode)}}
            (evidence / "replacement-lock-binding.json").write_text(json.dumps(lock_binding, indent=2) + "\n")
            assert (visible_lock_stat.st_dev, visible_lock_stat.st_ino) == (original_lock_stat.st_dev, original_lock_stat.st_ino), "visible production lock is not the retained original inode"
            refused = run("set", name, "disk=512mib", expect=None, timeout=90)
            after_inventory = inventory()
            (evidence / "replacement-refusal.json").write_text(json.dumps({"hostFailure": host_failure, "lockBinding": lock_binding, "scratch": str(scratch), "boundMachineDirectory": str(upper.parent), "beforeInventory": before_inventory, "afterInventory": after_inventory, "returncode": refused.returncode, "stdout": refused.stdout, "stderr": refused.stderr}, indent=2) + "\n")
            assert refused.returncode != 0
            assert procs.query(database, sql) == before_record, "partial replacement capacity/path published"
            assert overlay.digest(disposable) == before_growth
            assert set(scratch.iterdir()) == before_names, "failed replacement left a private generation"
        finally:
            try:
                if lock_bound:
                    subprocess.run(["umount", str(visible_lock)], check=True, timeout=15)
            finally:
                subprocess.run(["umount", str(upper.parent)], check=True, timeout=15)
    finally:
        try:
            run("stop", name, "--force", "--timeout", "10s", expect=None)
        finally:
            try:
                subprocess.run(["umount", str(upper)], check=True, timeout=15)
            finally:
                try:
                    subprocess.run(["umount", str(scratch)], check=True, timeout=15)
                finally:
                    if original_lock_fd is not None:
                        os.close(original_lock_fd)
    assert overlay.digest(upper) == initial


if __name__ == "__main__":
    main()
