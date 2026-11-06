#!/usr/bin/env python3
"""Explicit Silo-engine/public-native-API proofs, never automatic Cargo VM tests.

Run one bounded cohort per fresh invocation. See --help for exact input roles.
Frozen native Python modules are reused only for guest transport, authentication,
sharing measurements and independent validation; native diagnostic operations are
never sent to the VM. Failures and their payloads are retained. Successful bulk
payload removal is Main-owned, after all process owners are reaped.

Cleanup reports distinguish OS wait/reap evidence from explicit native stop ACKs
and RESTORE_FAILURE terminal-cleanup responses. Reaping a failed constructor
does not make the cohort pass or prove terminal native cleanup. Original errors,
exit status and cumulative cleanup failures survive the frozen owner's close().

Host-only ownership regression (no VM/staging or native source edits):
  PYTHONPATH=smoke SILO_NATIVE_ROOT=/path/to/libkrun \\
    uv run --project smoke python -m unittest discover \\
    -s smoke/tests -p test_native_live_api.py -v
"""
from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time

MIB = 1024 * 1024
CAPTURE_OUTPUTS = ("memory.ram", "memory-layout.json", "execution.state", "devices.state")


def require(condition: bool, explanation: str) -> None:
    if not condition:
        raise ValueError(explanation)


def make_session_type():
    from native_device_controller import digest, save
    from native_generation_controller import GenerationSession
    from native_ram_image import authenticate_image, write_authentication

    class ApiSession(GenerationSession):
        @classmethod
        def create(cls, *args, **kwargs):
            session = cls.__new__(cls)
            session.native_reaped = False
            session.os_reaped = False
            session.process_pid = None
            session.process_exit_status = None
            session.cleanup_failures = []
            session.native_failure_cleanup = None
            session.construction_error = None
            try:
                session.__init__(*args, **kwargs)
            except BaseException as error:
                session.construction_error = str(error)
                try:
                    session.close()
                except BaseException as cleanup_error:
                    session.cleanup_failures.append(str(cleanup_error))
                raise
            return session

        def __init__(self, args, directory, disks, echo, restore=None, generic=False, partial=False):
            self.restore_directory = restore
            self.restore_failure_evidence = None
            GenerationSession.__init__(self, args, directory, disks, echo,
                                       restore=restore, generic=generic, partial=partial)

        def record_process_exit(self, process):
            failures = []
            if process is not None:
                self.process_pid = process.pid
                if process.returncode is not None:
                    self.process_exit_status = process.wait(timeout=0)
                    self.os_reaped = True
                    for stream in (process.stdin, process.stdout):
                        if stream is not None and not stream.closed:
                            try:
                                stream.close()
                            except OSError as error:
                                failures.append(str(error))
                                self.cleanup_failures.append(str(error))
            return failures

        def stop(self):
            process = getattr(self, "process", None)
            try:
                return GenerationSession.stop(self)
            finally:
                self.record_process_exit(process)

        def close(self):
            # The frozen owner clears its process handle after wait(), including
            # constructor failures. Retain OS evidence without inventing a stop ACK.
            process = getattr(self, "process", None)
            failures = []
            try:
                failures.extend(GenerationSession.close(self))
            finally:
                failures.extend(self.record_process_exit(process))
            return failures

        def until(self, predicate, label, timeout=30):
            if label == "native driver readiness" and self.prepared and self.args.case == "restore-failures":
                self.restore_failure_evidence = self.restore_failure()
                return
            return GenerationSession.until(self, predicate, label, timeout=timeout)

        def restore_failure(self):
            from silo_smoke.native_live_trace import NativeRestoreHold, receive_restore_reply
            from native_memory_sharing import readonly_owners
            proof = json.loads((self.binding / "api-proof-launch.json").read_bytes())["proof"]
            waiting = json.loads(receive_restore_reply(self, "RESTORE_CONSTRUCTION_WAITING").split(" ", 1)[1])
            require(waiting["proof"] == proof, "exact fresh-process restore proof admission")
            evidence = {"proof": proof, "pid": self.process.pid, "construction_waiting": waiting}
            if proof == "install-timeout":
                with NativeRestoreHold(self.process.pid) as held:
                    self.process.stdin.write(b"build\n"); self.process.stdin.flush()
                    failed = json.loads(receive_restore_reply(self, "RESTORE_FAILURE_PENDING").split(" ", 1)[1])
                    require(failed["native_install_stage_failure"] and failed["owner_retained"] and held.record is not None,
                            "restore timeout must follow accepted native InstallExecution with full failure ownership")
                    pending = json.loads(receive_restore_reply(self, "RESTORE_CLEANUP_PENDING").split(" ", 1)[1])
                    require(pending["first_cleanup_returned_owner"] and pending["owner_retained"],
                            "nonterminal cleanup discarded accepted native restore owners")
                    info = (self.restore_directory / "memory.ram").stat()
                    retained = readonly_owners(self.process.pid, info.st_dev, info.st_ino)
                    require(retained and lease_conflicts(self), "failed restore lost its backing/closure lease while install was in flight")
                    evidence.update(failure=failed, first_cleanup=pending, readonly_backing_owners=retained,
                                    actual_install_hold=held.record)
                require(held.native_run_entries == 0, "failed parked construction entered KVM_RUN")
                self.process.stdin.write(b"cleanup\n"); self.process.stdin.flush()
            elif proof == "prepared-callback-failure":
                with NativeRestoreHold(self.process.pid, mode="callback-max") as queued:
                    self.process.stdin.write(b"build\n"); self.process.stdin.flush()
                    evidence["prepared_callback"] = receive_restore_reply(self, "PREPARED_CALLBACK_ENTERED")
                    until = time.monotonic() + 5
                    while queued.record is None and time.monotonic() < until:
                        time.sleep(.001)
                    require(queued.record is not None and queued.record["queue_wake_bytes"] == 8
                            and queued.native_run_entries == 0 and lease_conflicts(self),
                            "MAX public operation was not really enqueued before callback failure/cleanup")
                    evidence["public_max_enqueued_before_callback_return"] = queued.record
                self.process.stdin.write(b"callback-fail\n"); self.process.stdin.flush()
            else:
                raise ValueError("unknown explicit restore failure case")
            terminal = json.loads(receive_restore_reply(self, "RESTORE_FAILURE").split(" ", 1)[1])
            require(terminal["terminal"] and terminal["owner_retained"], "failed native owner did not prove actual terminal cleanup")
            self.native_failure_cleanup = terminal
            if proof == "prepared-callback-failure":
                maximum = json.loads(receive_restore_reply(self, "PREPARED_PUBLIC_MAX_RESULT").split(" ", 1)[1])
                require(maximum["operation"] == (1 << 64)-1 and "CallerTimeout" not in maximum["outcome"]
                        and "Deadline" not in maximum["outcome"], "MAX public request was not serviced before cleanup")
                evidence["public_max_result"] = maximum
            require(not any(line.startswith("READY whole-machine-production") for line in self.replies),
                    "failed restore manufactured a dispatch/started readiness fact")
            status = self.process.wait(timeout=10)
            require(status == 1 and not lease_conflicts(self), "failed-owner process was not actually reaped before lease release")
            self.record_process_exit(self.process)
            evidence.update(terminal_cleanup=terminal, process_exit_status=status,
                            no_backend_started=True, native_failed_owner_cleanup=True)
            return evidence

        def guest(self, advance=False):
            value = GenerationSession.guest(self, advance=advance)
            self.last_generation_guest = value
            return value

        def command(self, command, error=False, timeout=30):
            record = {"command": command, "native_pid": self.process.pid,
                      "started_monotonic_ns": time.monotonic_ns()}
            try:
                record["response"] = self._command(command, error=error, timeout=timeout)
                return record["response"]
            except BaseException as failure:
                record["error"] = str(failure)
                raise
            finally:
                record["finished_monotonic_ns"] = time.monotonic_ns()
                with (self.directory / "api-commands.jsonl").open("a") as output:
                    output.write(json.dumps(record, sort_keys=True) + "\n")

        def value(self, command: str, prefix: str) -> dict:
            start = len(self.replies)
            self.command(command)
            values = [json.loads(line[len(prefix) + 1:]) for line in self.replies[start:]
                      if line.startswith(prefix + " ")]
            require(len(values) == 1, f"one exact {prefix} record required")
            return values[0]

        def live(self) -> dict:
            value = self.value("status", "LIVE")
            with (self.directory / "api-native-observations.jsonl").open("a") as output:
                output.write(json.dumps(value, sort_keys=True) + "\n")
            return value

        def capture_status(self) -> dict:
            return self.value("capture-status", "CAPTURE_STATUS")

        def capture(self, directory: Path, mode: str, *, accept=False, seal=True) -> dict:
            require(seal or not accept, "native acceptance requires the authenticated controller seal first")
            self.command(f"capture {directory} {mode}")
            record = json.loads((directory / "api-capture.json").read_bytes())
            require(record["schema"] == 1 and record["writers_closed"] is True,
                    "completed receipt must close every native RAM writer")
            require(self.capture_status()["stage"] == "CandidateComplete", "exact candidate status")
            assert_writers_closed(self.process.pid, directory)
            # Cheap completion identity; a later seal refuses outputs touched after the receipt.
            record["completed_output_identity"] = output_identities(directory)
            binding = directory / "binding"
            binding.mkdir(mode=0o700)
            for name in ("silo-producer", "profile", "topology", "ram-layout", "source-run", "capture"):
                (binding / name).write_bytes(bytes(record["binding"][name.replace("-", "_")]))
            if seal:
                self.seal(directory, record)
            if accept:
                first = self.value("accept", "ACCEPTED")
                require(self.capture_status()["stage"] == "Accepted", "accepted status after exact read-only accept")
                second = self.value("accept", "ACCEPTED")
                require(first == second, "duplicate exact acceptance advanced the ledger twice")
                record["accepted_generation"] = first["memory_generation"]
                self.command("release-capture")
                require(self.value("baseline", "BASELINE")["memory_generation"] == first["memory_generation"],
                        "result release dropped the coordinator's accepted baseline")
            return record

        def seal(self, directory: Path, record: dict, *, after: str = "native candidate completion") -> None:
            assert_writers_closed(self.process.pid, directory)
            require(output_identities(directory) == record["completed_output_identity"],
                    "captured outputs changed between native completion and controller seal")
            authentication = authenticate_image(directory / "memory.ram", directory / "memory-layout.json",
                                                  bytes(record["binding"]["ram_layout"]))
            save(directory / "memory-authentication.json", authentication)
            write_authentication(directory / "memory-authentication.bin", authentication)
            sealed = {}
            for name in CAPTURE_OUTPUTS:
                path = directory / name
                path.chmod(0o400)
                with path.open("rb") as source:
                    os.fsync(source.fileno())
                sealed[name] = {"sha256": digest(path), "length": path.stat().st_size,
                                "device": path.stat().st_dev, "inode": path.stat().st_ino}
            save(directory / "api-controller-seal.json", {
                "scope": "standalone exact read-only controller seal, not Phase14 publication",
                "native_writers_closed_before_chmod": True, "sealed_after": after, "objects": sealed})

        def resolve(self, *, accept=False) -> None:
            self.command("accept" if accept else "abandon")
            self.command("release-capture")

        def clock_resume(self) -> dict:
            from native_generation_controller import validate_ack
            before = self.last_generation_guest
            previous = self.native()
            self.command("resume")
            until = time.monotonic() + 6
            while True:
                native = self.native()
                guest = self.guest()
                if (native["outcome"] == "acknowledged" and guest.get("ack_accessor_returned") == "1"
                        and int(guest["ack_sequence"]) == native["sequence"]):
                    break
                require(time.monotonic() < until, "ordinary resident resume did not complete its real ClockOnly ACK")
                self.pump(.005)
            require(native["flags"] == 3 and native["id"] == previous["id"]
                    and native["sequence"] == previous["sequence"] + 1,
                    "ordinary source resume replaced its completed identity or failed to publish next ClockOnly")
            validate_ack(native, guest, int(before["reseed_count"]), clock=True)
            return {"native": native, "guest": guest, "api": "ordinary Control::resume / native ClockOnly"}

    return ApiSession


def output_identities(directory: Path) -> dict:
    identities = {}
    for name in CAPTURE_OUTPUTS:
        info = (directory / name).stat()
        identities[name] = {"device": info.st_dev, "inode": info.st_ino, "length": info.st_size,
                            "mode": info.st_mode, "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}
    return identities


def assert_writers_closed(pid: int, directory: Path) -> None:
    identities = {(path.stat().st_dev, path.stat().st_ino)
                  for path in directory.iterdir() if path.is_file() and path.name in CAPTURE_OUTPUTS}
    for entry in Path(f"/proc/{pid}/fd").iterdir():
        try:
            info = entry.stat()
            fields = dict(line.split(":", 1) for line in
                          Path(f"/proc/{pid}/fdinfo/{entry.name}").read_text().splitlines() if ":" in line)
        except FileNotFoundError:
            continue
        if (info.st_dev, info.st_ino) in identities:
            require(int(fields["flags"].strip(), 8) & os.O_ACCMODE == os.O_RDONLY,
                    "native completion retains writable output descriptor")


def lease_conflicts(session) -> bool:
    path = session.directory / "api.lease"
    with path.open("r+b") as lease:
        try:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(lease, fcntl.LOCK_UN)
        return False


def cleanup_session(owner) -> dict:
    errors = list(getattr(owner, "cleanup_failures", []))
    process = getattr(owner, "process", None)
    if process is not None and process.poll() is None:
        try:
            owner.stop()
        except BaseException as error:
            errors.append(str(error))
    try:
        errors.extend(owner.close())
    except BaseException as error:
        errors.append(str(error))
    errors.extend(getattr(owner, "cleanup_failures", []))
    return {
        "directory": str(owner.directory),
        "native_stop_acknowledged": owner.native_reaped,
        "native_failure_cleanup": owner.native_failure_cleanup,
        "os_reaped": owner.os_reaped,
        "process_pid": owner.process_pid,
        "process_exit_status": owner.process_exit_status,
        "construction_error": owner.construction_error,
        "terminal": owner.native_reaped or owner.os_reaped,
        "errors": list(dict.fromkeys(errors)),
    }


def make_disks(args, label: str, cut: Path | None = None) -> list[Path]:
    result = []
    for index in range(2):
        path = args.evidence / f"{label}-disk{index}.raw"
        if cut:
            subprocess.run(["cp", "--reflink=auto", "--sparse=always", str(cut / f"disk{index}.raw"), str(path)],
                           check=True, timeout=30, capture_output=True)
            path.chmod(0o600)
        else:
            with path.open("xb") as output:
                output.truncate(128 * MIB)
            subprocess.run(["mkfs.ext4", "-F", "-q", str(path)], check=True, timeout=30, capture_output=True)
        result.append(path)
    return result


def source(args, echo):
    owner = args.session_type.create(args, args.evidence / "source", make_disks(args, "source"), echo)
    owner.start_mux()
    owner.progress()
    owner.profile()
    owner.guest()
    require(lease_conflicts(owner), "source closure lease must stay locked while native owners live")
    return owner


def prepared(child, cut: Path) -> dict:
    value = child.live()
    require(value["state"].startswith("RestorePrepared") and value["backing"] == "RestoredPrivate"
            and value["tracking"] == "Some(Capture)" and value["coverage_valid"]
            and value["native_commands_reconciled"] and not value["activation_released"]
            and not value["activation_failed"], "actual parked/fenced/private/tracked native restore required")
    facts = value["restore_installation"]
    require(facts is not None and facts["tracking_before_install"] and facts["complete"]
            and facts["dirty_pages"] > 0, "native install effects must follow tracking and enter dirty coverage")
    info = (cut / "memory.ram").stat()
    require(value["file_backings"] and all(pair == [info.st_dev, info.st_ino] for pair in value["file_backings"]),
            "every child region must use the exact inherited immutable inode")
    fenced = {entry["configured_id"]: entry["activation_fenced"] for entry in value["providers"]
              if entry["activation_fenced"] is not None}
    require(fenced.get("net0") is True and fenced.get("vsock") is True,
            "actual destination network and non-control mux gates must remain closed")
    token = os.urandom(16).hex()
    child.device_counter_reply = None
    os.write(child.console, b"C" + token.encode() + b"\n")
    child.pump(.2)
    require(not child.device_counter_reply or child.device_counter_reply.get("request_token") != token,
            "parked restore executed a newly nonce-correlated guest command")
    require(lease_conflicts(child), "prepared child lost closure lease")
    return value


def release_child(child, *, before_reseeds: int | None = None) -> dict:
    if before_reseeds is None:
        # The captured coherent driver evidence is a caller input, not a native receipt.
        before_reseeds = child.args.saved_reseeds
    child.command("generation-fresh")
    child.expected_generation = child.native()
    child.command("release")
    native, guest = child.acknowledged(before_reseeds, clock=False)
    after_ack = child.live()
    require(not after_ack["activation_released"] and all(
        entry["activation_fenced"] is True for entry in after_ack["providers"]
        if entry["activation_fenced"] is not None), "generation ACK released endpoints")
    os.write(child.console, b"M\n")
    child.start_mux()  # Actual authorized 1027 control service, not an agent Activate ACK.
    other = child.connect_mux(port=1028)
    until = time.monotonic() + 2
    rejected = bytearray()
    chunk = None
    while time.monotonic() < until:
        try:
            chunk = other.recv(4096)
            rejected.extend(chunk)
            if not chunk or b"ERR" in rejected:
                break
        except BlockingIOError:
            child.pump(.005)
    require(not rejected.startswith(b"OK"), "non-control mux service opened while fenced")
    require(b"ERR" in rejected or chunk == b"", "non-control mux refusal must be actually observed")
    before = child.observe_device_counters()
    child.pump(.2)
    after = child.observe_device_counters()
    require(after["net_rx"] == before["net_rx"], "managed ingress delivered guest packets before explicit release")
    child.command("activate")  # Low-level explicit provider release only, NOT product activation.
    released = child.live()
    require(released["activation_released"] and not released["activation_failed"] and all(
        entry["activation_fenced"] is False for entry in released["providers"]
        if entry["activation_fenced"] is not None), "real provider release acknowledgements missing")
    child.progress(before)
    return {"generation_native": native, "generation_guest": guest, "after_ack": after_ack,
            "fenced_mux_refusal_hex": bytes(rejected).hex(), "fenced_network_before": before,
            "fenced_network_after": after, "released": released,
            "scope": "authorized native control service and separate provider fence release; no guest Activate/thaw/public Running"}


def comparison(session, root: Path, label: str, *, accept=True, first_mode="incremental", accept_incremental=False) -> dict:
    from native_device_controller import digest
    left, right = root / f"{label}-{first_mode}", root / f"{label}-full"
    first = session.capture(left, first_mode)
    refusal = session.command("resume", error=True)
    require("Busy" in refusal, "unresolved candidate must refuse source resume with typed Busy")
    session.resolve()
    full = session.capture(right, "full")
    require(digest(left / "memory.ram") == digest(right / "memory.ram"),
            "complete resolved incremental/wrong-baseline output differs from independent full capture at the same stopped cut")
    accepted_incremental = None
    if accept and accept_incremental:
        session.resolve()
        accepted_path = root / f"{label}-accepted-incremental"
        accepted_incremental = session.capture(accepted_path, "incremental")
        require(accepted_incremental["mode"] == "Incremental" and
                digest(accepted_path / "memory.ram") == digest(right / "memory.ram"),
                "actually accepted incremental replacement differs from independent full oracle")
        session.resolve(accept=True)
    else:
        session.resolve(accept=accept)
    return {"resolved": first, "full": full, "accepted_incremental":accepted_incremental,
            "busy_refusal": refusal, "identical_complete_ram": True, "left": str(left), "right": str(right)}


def identity_continuity(child, source_boot: bytes, source_work: dict, source_registers: dict,
                        source_clocks: list[dict]) -> dict:
    from native_device_controller import COUNTERS
    from native_device_execution import ClockCorrelation
    child.profile()
    require(child.observations["boot-identity"] == source_boot, "restored guest rebooted")
    work = child.progress(source_work)
    child.until(lambda: len(child.clock_brackets) >= 2 and child.registers and
                child.registers[-1]["sequence"] > source_registers["sequence"],
                "fresh two-CPU register and clock continuation")
    registers = child.registers[-1]
    require(registers["pid"] == source_registers["pid"] and
        all(new["progress"] > old["progress"] and not new["failed"]
            for new, old in zip(registers["cpus"], source_registers["cpus"])),
        "original live GPR/SIMD/x87 process or per-CPU control flow did not continue")
    require(all(work[key] > source_work[key] for key in COUNTERS), "device continuation counter regressed")
    preparation = child.live()["time_preparation"]
    require(preparation is not None, "actual native controller/time release preparation missing")
    plans = sorted(preparation["plans"], key=lambda plan: plan["id"])
    require([plan["id"] for plan in plans] == [0, 1], "exact native release-plan CPU coverage")
    correction = (plans[1]["offset"] - plans[0]["offset"]) & ((1 << 64) - 1)
    for bracket in child.clock_brackets[-4:]:
        adjusted = (bracket["tsc_ap"] - correction) & ((1 << 64) - 1)
        require(bracket["tsc_before"] <= adjusted <= bracket["tsc_after"] and
                bracket["mono_before"] <= bracket["mono_ap"] <= bracket["mono_after"],
                "contemporary AP clock sample escaped the actual primary bracket")
    relation = ClockCorrelation(source_clocks)
    relation.observe(child.clock_brackets[-4:])
    return {"source_boot_hex": source_boot.hex(), "child_boot_hex": child.observations["boot-identity"].hex(),
            "source_work": source_work, "child_work": work, "source_registers": source_registers,
            "child_registers": registers, "clock_brackets": child.clock_brackets[-4:],
            "native_release_preparation": preparation, "clock_relation": relation.record(),
            "scope": "real guest register/boot/device and contemporary clock continuation; exact saved LAPIC/deadline/PIC/IOAPIC records retained in api-capture.json"}


def measure(session, cut: Path, info, label: str) -> dict:
    from native_memory_sharing import bounded_text, parse_smaps, readonly_owners, SMAPS_BOUND
    from native_ram_image import validate_layout
    raw = bounded_text(Path(f"/proc/{session.process.pid}/smaps"), SMAPS_BOUND)
    (session.directory / f"api-{label}.smaps").write_text(raw)
    mappings = [value for value in parse_smaps(raw) if value["inode"] == info.st_ino
                and value["name"].removesuffix(" (deleted)") == str((cut / "memory.ram").resolve())]
    require(mappings and all(value["permissions"] == "rw-p" for value in mappings), "actual same-inode MAP_PRIVATE RAM VMAs required")
    layout = validate_layout((cut / "memory-layout.json").read_bytes())
    spans = sorted((value["offset"], value["offset"] + value["end"] - value["start"]) for value in mappings)
    offset = 0
    for start, end in spans:
        require(start == offset and end > start, "RAM private VMA packed offsets must cover without aliases/holes")
        offset = end
    require(offset == layout["packedLength"], "RAM mapping length differs from exact layout")
    keys = ("Rss", "Pss", "Shared_Clean", "Shared_Dirty", "Private_Dirty", "Private_Clean", "Anonymous")
    totals = {key: sum(value["metrics"][key] for value in mappings) for key in keys}
    owners = readonly_owners(session.process.pid, info.st_dev, info.st_ino)
    require(owners, "child must retain read-only backing ownership beyond result release")
    return {"native_pid":session.process.pid,"backing":[info.st_dev,info.st_ino],"mappings":mappings,
            "totals_bytes":totals,"readonly_owners":owners,
            "selection":"exact kernel path+inode+packed offsets, cross-checked with domain dev/inode; Btrfs smaps superblock device recorded, not confused with stat subvolume device"}


def api_cohort(args, echo) -> dict:
    from native_device_controller import digest
    from native_memory_sharing import observe, check_saved_first_page
    parent = source(args, echo)
    initial_generation = parent.guest()
    args.saved_reseeds = int(initial_generation["reseed_count"])
    initial = observe(parent, "A", None)
    work = parent.progress()
    registers = parent.registers[-1]
    parent.until(lambda: len(parent.clock_brackets) >= 2, "original separated two-CPU clock brackets")
    source_clocks = parent.clock_brackets[-4:].copy()
    boot = parent.observations["boot-identity"]
    parent.command("pause")
    cut = args.evidence / "accepted-source"
    captured = parent.capture(cut, "full", accept=True)
    parent.command("preserve")
    source_continuation = parent.clock_resume()
    parent.progress(work)
    parent.command("pause")
    children = []
    records = []
    info = (cut / "memory.ram").stat()
    original_hash = digest(cut / "memory.ram")
    for index in range(2):
        child = args.session_type.create(args, args.evidence / f"child-{index}", make_disks(args, f"child-{index}", cut), echo, restore=cut)
        children.append(child)
        prepared_state = prepared(child, cut)
        released = release_child(child)
        continuity = identity_continuity(child, boot, work, registers, source_clocks)
        clean = observe(child, "A", None, initial)
        child.command("pause")
        records.append({"prepared":prepared_state,"release":released,"continuity":continuity,"clean":clean})
    require(len({child.process.pid for child in children}) == 2 and all(child.process.pid != parent.process.pid for child in children), "two independent fresh child processes required")
    require(records[0]["release"]["generation_native"]["id"] != records[1]["release"]["generation_native"]["id"],
            "independent restored children reused a generation identity")
    clean_measurements = [measure(child, cut, info, "clean") for child in children]
    require(all(value["totals_bytes"]["Shared_Clean"] >= 48 * MIB for value in clean_measurements),
            "two children lack measured shared clean resident pages (RSS sums are not evidence)")
    require(sum(value["totals_bytes"]["Pss"] for value in clean_measurements) <
            sum(value["totals_bytes"]["Rss"] for value in clean_measurements) - 32*MIB,
            "RAM PSS does not show actual physical sharing")
    for index, child in enumerate(children):
        child.clock_resume()
        records[index]["dirty"] = observe(child, "IJ"[index], index, initial)
        child.command("pause")
        for sibling_index, sibling in enumerate(children):
            sibling.clock_resume()
            expected = records[sibling_index].get("dirty", records[sibling_index]["clean"])
            observe(sibling, "E", expected["write_slot"], initial, expected)
            sibling.command("pause")
    dirty_measurements = [measure(child, cut, info, "dirty") for child in children]
    require(all(after["totals_bytes"]["Private_Dirty"] >= before["totals_bytes"]["Private_Dirty"] + 8*MIB
                for before, after in zip(clean_measurements, dirty_measurements)), "private write divergence not physically measured")
    require(records[0]["dirty"]["checksum"] != records[1]["dirty"]["checksum"], "independent children did not diverge privately")
    require(digest(cut / "memory.ram") == original_hash, "private child writes modified immutable source RAM")
    recapture = comparison(children[0], args.evidence, "child-inherited-baseline")
    require(recapture["resolved"]["mode"] == "Incremental" and
            recapture["resolved"]["stats"]["live_bytes_read"] < recapture["resolved"]["stats"]["logical_bytes"],
            "child recapture scanned unchanged RAM or lost inherited baseline")
    parent.stop()
    parent.close()
    require(not lease_conflicts(parent), "source lease retained after native exit/reap")
    ram_fd = os.open(cut / "memory.ram", os.O_RDONLY | os.O_CLOEXEC)
    try:
        cut.joinpath("memory.ram").unlink()
        require(os.fstat(ram_fd).st_nlink == 0, "original baseline inode still linked")
        for index, child in enumerate(children):
            child.clock_resume()
            observe(child, "E", index, initial, records[index]["dirty"])
            child.progress()
            child.command("pause")
        after_unlink = [measure(child, cut, info, "source-exit-unlinked") for child in children]
        # Independently inspect the retained original backing after both COW writers.
        layout = json.loads((cut / "memory-layout.json").read_bytes())
        check_saved_first_page(ram_fd, layout, initial["first_gpa"], None)
    finally:
        os.close(ram_fd)
    return {"capture":captured,"source_clock_only":source_continuation,"children":records,
            "sharing_clean":clean_measurements,"sharing_private":dirty_measurements,
            "source_exit_unlink_survival":after_unlink,"child_recapture":recapture,
            "baseline_original_hash":original_hash,"original_ram_unlinked_after_source_reap":True}


def verify_saved_buffer(directory: Path, observation: dict) -> dict:
    from native_ram_image import validate_layout
    layout = validate_layout((directory / "memory-layout.json").read_bytes())
    checked = {}
    with (directory / "memory.ram").open("rb") as ram:
        for kind in ("host", "cpu"):
            gpa = observation[f"{kind}_gpa"]
            for region in layout["regions"]:
                offset = gpa - region["guestPhysicalAddress"]
                if 0 <= offset and offset + 4096 <= region["length"]:
                    ram.seek(region["streamOffset"] + offset)
                    data = ram.read(4096)
                    require(data == bytes([observation[f"{kind}_byte"]]) * 4096,
                        "resolved saved RAM differs from nonce-correlated pinned guest page")
                    checked[kind] = {"gpa": gpa, "bytes": 4096, "sha256": hashlib.sha256(data).hexdigest()}
                    break
            else:
                raise ValueError("actual pinned guest GPA outside native canonical layout")
    return checked


def incremental_cohort(args, echo) -> dict:
    from native_memory_controller import observe_buffer
    parent = source(args, echo)
    observed = observe_buffer(parent)
    parent.command("pause")
    initial = parent.capture(args.evidence / "baseline", "full", accept=True)
    initial["pinned_pages"] = verify_saved_buffer(args.evidence / "baseline", observed)
    zero_dirty = comparison(parent, args.evidence, "no-writes-after-accept")
    require(zero_dirty["resolved"]["mode"] == "Incremental" and
            zero_dirty["resolved"]["stats"]["live_bytes_read"] == 0 and
            zero_dirty["resolved"]["stats"]["overlay_bytes_written"] == 0,
            "accepted stopped VM performed an unchanged-RAM live scan")
    comparisons = []
    for index in range(2):
        parent.clock_resume()
        previous = observed
        observed = observe_buffer(parent, cpu_write=True)
        require(observed["cpu_gpa"] == previous["cpu_gpa"] and observed["cpu_byte"] != previous["cpu_byte"],
                "same actual pinned CPU page must be redirtied across accepted generations")
        parent.progress()
        parent.command("pause")
        comparisons.append(comparison(parent, args.evidence, f"redirty-{index}", accept_incremental=True))
        comparisons[-1]["pinned_pages"] = verify_saved_buffer(Path(comparisons[-1]["left"]), observed)
    parent.clock_resume()
    observed = observe_buffer(parent, cpu_zero=True)
    require(observed["cpu_byte"] == 0, "real guest nonzero-to-zero write missing")
    parent.command("pause")
    zeros = comparison(parent, args.evidence, "changed-to-zero")
    zeros["pinned_pages"] = verify_saved_buffer(Path(zeros["left"]), observed)
    require(zeros["resolved"]["stats"]["explicit_zero_bytes_written"] >= 4096,
            "zero transition was omitted rather than overlaid into the complete resolved image")
    wrong = comparison(parent, args.evidence, "wrong-old-baseline", first_mode="wrong")
    require(wrong["resolved"]["mode"] == "Full" and "BaselineToken" in wrong["resolved"]["full_reason"],
            "stale baseline token must produce real full fallback")
    parent.clock_resume()
    abandoned_observation = observe_buffer(parent, cpu_write=True)
    parent.command("pause")
    abandoned = parent.capture(args.evidence / "abandoned", "incremental")
    abandoned["pinned_pages"] = verify_saved_buffer(args.evidence / "abandoned", abandoned_observation)
    parent.resolve()
    parent.clock_resume()
    retained_observation = observe_buffer(parent, cpu_write=True)
    parent.command("pause")
    retained = comparison(parent, args.evidence, "abandon-retains-dirty-union")
    retained["pinned_pages"] = verify_saved_buffer(Path(retained["left"]), retained_observation)
    return {"baseline":initial,"zero_dirty":zero_dirty,"same_page_generations":comparisons,"changed_to_zero":zeros,
            "wrong_baseline":wrong,"abandoned":abandoned,"retained_union":retained,
            "host_write_scope":"real console/net/vsock provider DMA participates in every running interval; no diagnostic arbitrary-GPA host writer"}


def partial_cohort(args, echo) -> dict:
    parent = source(args, echo)
    before = int(parent.guest()["reseed_count"])
    parent.request()
    parent.phase(1)
    first_staged = parent.native()
    require(first_staged["outcome"] == "pending" and first_staged["processed_id"] == first_staged["id"]
        and first_staged["processed_sequence"] != first_staged["sequence"],
        "diagnostic gate must follow real ID/high writes and precede the low commit")
    parent.guest(advance=True)
    prior, prior_guest = parent.acknowledged(before, clock=False)
    original = parent.request()
    pending_guest = parent.phase(1)
    staged = parent.native()
    require(staged["outcome"] == "pending" and staged["processed_id"] == staged["id"]
        and staged["processed_sequence"] == prior["sequence"] and staged["clock_latch"] > 0,
        "second real request lacks deterministic partial ID/high/old-low/latch state")
    parent.command("pause")
    paused = parent.native()
    cut = args.evidence / "partial-word-source"
    captured = parent.capture(cut, "full")
    require(parent.native() == paused, "capture modified staged words or clock latch")
    parent.resolve()
    parent.expected_generation = original
    parent.command("generation-resume")
    parent.guest(advance=True)
    retained, retained_guest = parent.acknowledged(int(prior_guest["reseed_count"]), clock=False)
    child = args.session_type.create(args, args.evidence / "partial-word-child",
        make_disks(args, "partial-word-child", cut), echo, restore=cut)
    stopped = prepared(child, cut)
    inherited = child.native()
    for key in ("sequence", "id", "flags", "processed_sequence", "processed_id", "clock_latch", "config_generation"):
        require(inherited[key] == paused[key], f"partial-word restore changed exact {key}")
    require(inherited["outcome"] == "none" and inherited["committed_sequence"] == prior["sequence"],
        "restored staged equality/history manufactured a destination receipt")
    child.command("generation-fresh")
    destination = child.native()
    child.expected_generation = destination
    require(destination["sequence"] == original["sequence"] + 1 and destination["id"] != original["id"],
        "fresh destination did not supersede the interrupted request")
    child.command("release")
    child.guest(advance=True)  # Let the real interrupted publisher issue its stale low write.
    observations = []
    until = time.monotonic() + 2
    while time.monotonic() < until:
        child.guest()
        value = child.native()
        observations.append(value)
        if (value["outcome"] == "pending" and value["processed_sequence"] == original["sequence"]
                and value["processed_id"] == destination["id"]):
            break
        child.pump(.005)
    else:
        raise ValueError("did not observe rejected source low write followed by new destination staging")
    child.guest(advance=True)
    native, guest = child.acknowledged(int(pending_guest["reseed_count"]), clock=False)
    after = child.live()
    require(not after["activation_released"], "partial restore ACK released endpoints")
    child.command("activate")
    return {"first_staging": first_staged, "prior_receipt": prior, "capture": captured,
        "partial_before_capture": paused, "retained_source_receipt": retained,
        "retained_source_guest": retained_guest, "prepared": stopped, "inherited_exact_partial": inherited,
        "fresh_destination": destination, "actual_stale_low_then_staged_new_request": observations,
        "destination_receipt": native, "destination_guest": guest, "after_ack_still_fenced": after,
        "fixture": "separate native_generation_partial.patch/header; unchanged production ABI"}


def restore_failure_cohort(args, echo) -> dict:
    parent = source(args, echo)
    parent.command("pause")
    cut = args.evidence / "restore-failure-source"
    captured = parent.capture(cut, "full", accept=True)
    cases = []
    for proof in ("prepared-callback-failure", "install-timeout"):
        profile = cut / "binding" / "api-proof-launch.json"
        profile.write_text(json.dumps({"proof": proof}) + "\n")
        child = args.session_type.create(args, args.evidence / proof,
            make_disks(args, proof, cut), echo, restore=cut)
        require(child.restore_failure_evidence is not None, "explicit native failure path not exercised")
        cases.append(child.restore_failure_evidence)
        require(not child.close(), "failed restore child/provider cleanup did not reap")
    return {"capture": captured, "failures": cases,
        "scope": "actual pre-dispatch callback refusal and accepted native install deadline with retained-owner cleanup retry; separate from generation timeout"}


def restore_timeout_cohort(args, echo) -> dict:
    parent = source(args, echo)
    parent.command("pause")
    cut = args.evidence / "restore-timeout-source"
    captured = parent.capture(cut, "full")
    parent.resolve()
    child = args.session_type.create(args, args.evidence / "restore-timeout-child",
        make_disks(args, "restore-timeout-child", cut), echo, restore=cut)
    stopped = prepared(child, cut)
    child.command("generation-fresh")
    original = child.native()
    child.command("release")
    child.command("generation-wait", timeout=6)
    expired = child.native()
    require(expired["outcome"] == "deadline", "destination pending ACK did not expire")
    # This isolated negative stays fenced solely to observe the actual delayed
    # low write, then stops. It never advances toward product Running.
    child.pump(1.3)
    late = child.native()
    require(late["outcome"] == "deadline" and late["processed_sequence"] == original["sequence"]
        and late["processed_id"] == original["id"]
        and late["committed_sequence"] != original["sequence"],
        "late exact destination low write revived or failed to exercise expiry")
    refusal = child.command("activate", error=True)
    after = child.live()
    require(not after["activation_released"] and all(entry["activation_fenced"] is True
        for entry in after["providers"] if entry["activation_fenced"] is not None),
        "expired destination released native endpoints")
    child.stop()
    return {"capture": captured, "prepared": stopped, "request": original,
        "expired": expired, "actual_late_low_write": late,
        "provider_release_refusal": refusal, "failed_fenced": after}


def generation_cohort(args, echo) -> dict:
    from native_generation_controller import exercise, validate_pending
    if args.case in ("positive", "late", "absent"):
        parent = args.session_type.create(args, args.evidence / "source", make_disks(args, "source"), echo)
        return exercise(parent, args.case)
    parent = source(args, echo)
    before = int(parent.guest()["reseed_count"])
    parent.request()
    prior, guest = parent.acknowledged(before, clock=False)
    before = int(guest["reseed_count"])
    original = parent.request()
    parent.phase(1)
    wrong_sequence = parent.native()
    validate_pending(wrong_sequence, original, 1, prior)
    parent.command("pause")
    paused = parent.native()
    if args.case == "expiry":
        parent.pump(5.1)
        refusal = parent.command("generation-resume", error=True)
        expired = parent.native()
        require(expired["outcome"] == "deadline", "stopped pending request deadline was renewed")
        return {"pending":paused,"expired":expired,"release_refusal":refusal}
    cut = args.evidence / "pending-generation"
    # The native capture runs inside the immutable 5 s request window; the
    # multi-second host authentication/seal of its outputs does not need to.
    capture = parent.capture(cut, "full", seal=False)
    require(parent.native() == paused, "capture changed pending request/raw ACK/clock latch")
    parent.resolve()
    parent.expected_generation = original
    parent.command("generation-resume")
    parent.guest(advance=True); parent.phase(2)
    wrong_id = parent.native(); validate_pending(wrong_id,original,2,prior)
    parent.guest(advance=True); parent.phase(3)
    stale = parent.native(); validate_pending(stale,original,3,prior)
    parent.guest(advance=True)
    exact, guest = parent.acknowledged(before,clock=False)
    parent.seal(cut, capture, after="source exact generation ACK")
    saved_guest_reseeds = before + 1
    child = args.session_type.create(args,args.evidence/"pending-child",make_disks(args,"pending-child",cut),echo,restore=cut)
    prepared_state = prepared(child,cut)
    inherited = child.native()
    for key in ("sequence","id","flags","processed_sequence","processed_id","clock_latch","config_generation"):
        require(inherited[key] == paused[key], f"restored pending generation field changed: {key}")
    require(inherited["outcome"] == "none", "source host ticket was revived as destination authority")
    child.command("generation-fresh")
    destination = child.native(); child.expected_generation=destination
    require(destination["sequence"] == paused["sequence"]+1 and destination["id"] != paused["id"], "destination must supersede with fresh ID/next sequence")
    child.command("release")
    observations=[]
    until=time.monotonic()+4
    while time.monotonic()<until:
        child.guest(advance=True)
        observed=child.native(); observations.append(observed)
        if observed["outcome"] == "acknowledged": break
        child.pump(.01)
    native,guest=child.acknowledged(saved_guest_reseeds,clock=False)
    require(any(value["outcome"]=="pending" and (value["processed_id"] != destination["id"] or
                value["processed_sequence"] != destination["sequence"]) for value in observations),
            "actual stale/partial continuation writes were not rejected by destination request")
    require(not child.live()["activation_released"],"pending-state restore ACK implicitly released endpoints")
    child.command("activate")
    return {"capture":capture,"source_pending":paused,"wrong_sequence":wrong_sequence,"wrong_id":wrong_id,"stale":stale,
            "retained_source_exact":exact,"prepared_child":prepared_state,"inherited":inherited,"destination":destination,
            "continuation_writes":observations,"destination_native_ack":native,"destination_guest_ack":guest}


def failure_cohort(args, echo) -> dict:
    from silo_smoke.native_live_trace import accepted_timeout
    from native_device_controller import digest
    parent=source(args,echo)
    parent.command("pause")
    parent.capture(args.evidence/"failure-baseline","full",accept=True)
    failure_baseline = parent.value("baseline", "BASELINE")
    parent.clock_resume(); parent.progress(); parent.command("pause")
    # Accepted native command observation timeout is not cancellation. The short
    # deadline must actually return CallerTimeout; pre-admission Deadline is NOT a pass.
    start=len(parent.replies)
    timeout, native_io_hold = accepted_timeout(parent, args.evidence / "accepted-timeout")
    require("CallerTimeout" in timeout,"did not exercise accepted-command caller timeout; retain this failed sample")
    outputs=[json.loads(line.removeprefix("OUTPUTS ")) for line in parent.replies[start:] if line.startswith("OUTPUTS ")]
    require(len(outputs)==1,"accepted output identity record missing")
    settled=parent.capture_status()
    require(settled["stage"] in ("CandidateComplete","Failed"),"accepted timeout was neither retained nor terminally reconciled")
    require(lease_conflicts(parent),"caller timeout dropped native closure lease")
    if settled["stage"] == "CandidateComplete":
        assert_writers_closed(parent.process.pid,args.evidence/"accepted-timeout")
    parent.resolve()
    # Failed attempts retain their output files until explicit abandonment.
    assert_writers_closed(parent.process.pid,args.evidence/"accepted-timeout")
    # Actual bounded tmpfs ENOSPC, never /dev/full, injected errno or home filling.
    require(args.enospc_directory is not None,"failures cohort requires --enospc-directory in its private user/mount namespace")
    scratch=args.enospc_directory.resolve()
    require(scratch.is_dir() and not any(scratch.iterdir()),"ENOSPC mountpoint must be newly created and empty")
    subprocess.run(["mount","-t","tmpfs","-o","size=32m,mode=0700","silo-native-api-enospc",str(scratch)],check=True,timeout=15)
    try:
        require(shutil.disk_usage(scratch).total<=40*MIB,"ENOSPC filesystem is not bounded")
        with (scratch / "bounded-fill").open("xb") as filler:
            for _ in range(31):
                filler.write(bytes([0x5a]) * MIB)
            filler.flush()
            os.fsync(filler.fileno())
        no_space=parent.command(f"capture {args.evidence/'actual-enospc'} enospc:{scratch}",error=True)
        require("No space left on device" in no_space or "code: 28" in no_space or "os error 28" in no_space,"actual native RAM writer did not report ENOSPC")
        no_space_status=parent.capture_status()
        require(no_space_status["stage"]=="Failed","ENOSPC produced a coherent candidate")
        failed_payloads = {}
        for file in scratch.iterdir():
            if file.name == "bounded-fill":
                continue
            retained = args.evidence / ("failed-enospc-" + file.name)
            subprocess.run(["cp","--sparse=always",str(file),str(retained)],check=True,timeout=30)
            original_hash = digest(file)
            require(original_hash == digest(retained) and file.stat().st_size == retained.stat().st_size,
                    "failed ENOSPC payload was not retained byte-for-byte before unmount")
            failed_payloads[file.name] = {"path":str(retained),"sha256":original_hash,
                "length":retained.stat().st_size,"source_device":file.stat().st_dev,"source_inode":file.stat().st_ino}
        parent.resolve()
        assert_writers_closed(parent.process.pid,scratch)
        require(parent.value("baseline", "BASELINE") == failure_baseline,
                "failed/abandoned native attempts advanced the accepted baseline")
    finally:
        subprocess.run(["umount",str(scratch)],check=True,timeout=15)
    # A real controller seal/create-new failure cannot silently resolve a native candidate.
    seal=args.evidence/"seal-failure"
    candidate=parent.capture(seal,"incremental")
    before_mismatch = parent.value("baseline", "BASELINE")
    mismatch = parent.command(f"accept-wrong {args.evidence/'failure-baseline'/'memory.ram'}", error=True)
    require(parent.capture_status()["stage"] == "CandidateComplete" and
            parent.value("baseline", "BASELINE") == before_mismatch,
            "wrong-inode sealed acceptance advanced the ledger or destroyed the exact candidate")
    try:
        (seal/"api-controller-seal.json").open("x")
    except FileExistsError as error:
        seal_error={"errno":error.errno,"operation":"create_new controller seal manifest"}
    else:
        raise ValueError("controller seal failure not exercised")
    resume_refusal=parent.command("resume",error=True)
    require("Busy" in resume_refusal,"seal failure implicitly resolved/resumed a candidate")
    # Losing the controller-level acceptance response is separately labelled from
    # the native CallerTimeout above; no new API deadline is invented.
    parent.process.stdin.write(b"accept\n");parent.process.stdin.flush()
    accepted=parent.capture_status()
    require(accepted["stage"]=="Accepted","lost controller acceptance response was not recoverable by exact status")
    duplicate=parent.value("accept","ACCEPTED")
    parent.command("release-capture")
    # Kill while the real accepted RAM-output owner is still held in its syscall,
    # not after a conveniently settled idle VM. Only Popen reaps the process.
    pid=parent.process.pid
    death_directory=args.evidence/"worker-death-in-flight"
    death_reply, death_boundary=accepted_timeout(parent,death_directory,kill=True)
    status=parent.process.wait(timeout=10)
    parent.record_process_exit(parent.process)
    parent.process=None
    require(status==-signal.SIGKILL and not lease_conflicts(parent),"killed worker not actually reaped/lease released")
    require(not (death_directory/"api-capture.json").exists(),
            "worker death fabricated a completed/coherent output manifest")
    return {"accepted_timeout":timeout,"actual_native_io_hold":native_io_hold,
            "timeout_outputs":outputs,"settled_timeout":settled,
            "enospc":no_space,"enospc_status":no_space_status,"enospc_retained_payloads":failed_payloads,
            "failed_attempts_preserved_baseline":failure_baseline,"seal_failure":seal_error,
            "resume_after_seal_failure":resume_refusal,"accepted_status_after_controller_reply_loss":accepted,
            "duplicate_accept":duplicate,"wrong_inode_acceptance":mismatch,"prior_baseline":before_mismatch,
            "candidate":candidate,"worker_death":{"pid":pid,"wait_status":status,
            "actual_in_flight_boundary":death_boundary,"caller_reply_before_death":death_reply,
            "native_stop_acknowledged":False,"process_reaped":True,"positive_capture_or_started_fact":False}}


def capabilities_cohort(args, _echo) -> dict:
    from native_device_controller import digest
    require(args.monitor is not None, "capabilities case requires the actual staged --monitor")
    command = [str(args.monitor.resolve(strict=True)), "capabilities", "--backend", "krun", "--json"]
    started = time.monotonic_ns()
    result = subprocess.run(command, check=False, text=True, capture_output=True, timeout=30)
    (args.evidence / "staged-capabilities.stdout.json").write_text(result.stdout)
    (args.evidence / "staged-capabilities.stderr").write_text(result.stderr)
    require(result.returncode == 0 and result.stderr == "", "actual staged machine-less capability query failed")
    value = json.loads(result.stdout)
    require(value["schemaVersion"] == 1 and value["scope"] == "host" and value["backend"] == "krun",
        "actual host capability schema")
    for operation in ("pause", "capture", "restore", "fork", "incremental"):
        require(value["live"][operation]["native"] is True, "Main has not qualified/flipped the exercised native lane")
        expected = ({"status": "supported"} if operation == "pause" else
                    {"status": "unsupported", "reason": {
                        "code": "lane-not-qualified" if operation in ("capture", "restore") else "not-delivered",
                        "subject": None}})
        require(value["live"][operation]["availability"] == expected,
                "public capture stays unqualified until the combined live admission gates pass")
    return {"command": command, "elapsed_ns": time.monotonic_ns() - started,
        "exit_status": result.returncode, "monitor_sha256": digest(args.monitor),
        "actual_json": value, "guest_started": False}


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-root",type=Path,required=True,help="read-only native checkout containing frozen provider/validator sources")
    for name in ("entry","netd","guest-init","register-fixture","kernel","kernel-config","evidence"):
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--case",choices=("api","incremental","positive","faults","partial","restore-timeout","restore-failures","late","absent","expiry","failures","capabilities"),required=True)
    parser.add_argument("--enospc-directory",type=Path,help="new empty mountpoint, failures only; run via unshare --user --map-root-user --mount")
    parser.add_argument("--monitor", type=Path, help="staged silo-vmm; capabilities case only, run last AFTER Main's native evidence decision")
    args=parser.parse_args()
    require(os.uname().sysname == "Linux" and os.uname().machine == "x86_64"
            and os.sysconf("SC_PAGE_SIZE") == 4096, "explicit KVM x86_64/4KiB proof only; other lanes remain pending")
    args.native_root=args.native_root.resolve(strict=True)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    sys.path.insert(0,str(args.native_root/"src/libkrun/examples"))
    from native_device_controller import cpio,digest,save
    args.entry=args.entry.resolve(strict=True)
    os.environ["SILO_NATIVE_API_EXECUTABLE"]=str(args.entry)
    args.probe=Path(__file__).with_name("native_live_launch.py").resolve()
    args.session_type=make_session_type()
    args.sessions=[];args.execution_completeness=False;args.generation=True
    args.generation_proof_mode={"faults":1,"partial":4,"restore-timeout":2,"late":2,"absent":3,"expiry":1}.get(args.case,0)
    args.kernel_modules="CONFIG_MODULES=y" in args.kernel_config.read_text().splitlines()
    args.evidence=args.evidence.resolve();args.evidence.mkdir(mode=0o700)
    require(shutil.disk_usage(args.evidence).free>=16*1024*MIB,"bounded cohort requires 16GiB filesystem headroom")
    args.binding=args.evidence/"binding";args.binding.mkdir(mode=0o700)
    identities={name:digest(getattr(args,name)) for name in ("entry","probe","netd","guest_init","register_fixture","kernel","kernel_config")}
    identities["controller"]=digest(Path(__file__))
    identities["accepted_io_trace"] = digest(Path(__file__).with_name("native_live_trace.py"))
    partial_fixture=Path(__file__).resolve().parents[2]/"virt/vmm/examples/native_live_api"
    identities["partial_patch"]=digest(partial_fixture/"native_generation_partial.patch")
    identities["partial_header"]=digest(partial_fixture/"native_generation_partial.h")
    material=json.dumps(identities,sort_keys=True).encode()
    for name in ("silo-producer","profile","topology","ram-layout"):
        (args.binding/name).write_bytes(hashlib.sha256(name.encode()+material).digest())
    for name in ("source-run","capture"):(args.binding/name).write_bytes(os.urandom(16))
    args.initramfs=args.evidence/"initramfs.cpio"
    cpio(args.initramfs,[("init",args.guest_init.read_bytes(),0o100755),("register-fixture",args.register_fixture.read_bytes(),0o100755)])
    identities["initramfs"]=digest(args.initramfs)
    root=Path(__file__).resolve().parents[2]
    silo_sources=("Cargo.lock","virt/vmm/Cargo.toml","virt/vmm/src/krun/engine.rs","virt/vmm/src/krun/worker/fds.rs",
                  "virt/vmm/examples/native_live_api.rs","virt/vmm/examples/native_live_api/entry.rs",
                  "smoke/silo_smoke/native_live_trace.py","smoke/silo_smoke/shutdown_trace.py",
                  "resources/kernels/patches/live/0001-virtio-silo-vmgenid.patch")
    native_sources=("src/libkrun/src/api/live.rs","src/libkrun/src/api/live/restore.rs","src/libkrun/src/api/vmm_builder/restored.rs",
                    "src/libkrun/src/vmm/control.rs","src/libkrun/src/vmm/control/live.rs","src/libkrun/src/vmm/builder/restore.rs",
                    "src/libkrun/src/vmm/memory.rs","src/libkrun/src/vmm/memory/image.rs","src/devices/src/virtio/generation/mod.rs")
    revisions={}
    for name,checkout in (("silo",root),("native",args.native_root)):
        revisions[name]=subprocess.run(["git","rev-parse","HEAD"],cwd=checkout,check=True,text=True,capture_output=True,timeout=5).stdout.strip()
    save(args.evidence/"api-inputs.json",{"argv":sys.argv,"identities":identities,"revisions":revisions,
         "silo_source_sha256":{name:digest(root/name) for name in silo_sources},
         "native_source_sha256":{name:digest(args.native_root/name) for name in native_sources},
         "validation_source_sha256":{name:digest(args.native_root/"src/libkrun/examples"/name) for name in (
             "native_device_controller.py","native_generation_controller.py","native_memory_controller.py",
             "native_memory_sharing.py","native_ram_image.py","native_device_execution.py",
             "native_device_linux.c","native_generation_fault.patch","native_generation_fault.h")},
         "lane":"KVM x86_64","pending_lanes":["HVF arm64","KVM arm64"],
         "api":"Silo engine::{run_process,run_restore_process,Control} / public libkrun::live",
         "fd_roles":{"3":"bootstrap JSON FIFO","4":"reply FIFO","5":"parent-watchdog FIFO","6":"PTY console",
             "7":"new vsock mux","8":"closure lease","9..24":"Raw disks only","25":"readonly RAM","26":"readonly layout",
             "27":"readonly execution","28":"readonly devices","29":"managed unixgram","30":"console input","31":"console output"},
         "normal_worker_wire_delivered":False,"public_delivery":False,"qualification":False,
         "guest_lifecycle_freeze_activate_thaw":"not exercised; native cut/control-service/fence-release proof only"})
    echo=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);echo.bind(("127.0.0.1",0));echo.setblocking(False)
    report={"schema":1,"scope":"commit11 actual Silo engine/public native API","case":args.case,"status":"failed",
            "pending_lanes":["HVF arm64","KVM arm64"],"public_delivery":False,"all_reaped":False}
    def expired(_signum,_frame):raise TimeoutError("explicit 300-second API cohort bound")
    previous=signal.signal(signal.SIGALRM,expired);signal.alarm(300)
    failure=None
    try:
        cohort={"api":api_cohort,"incremental":incremental_cohort,"failures":failure_cohort,
            "partial":partial_cohort,"restore-timeout":restore_timeout_cohort,
            "restore-failures":restore_failure_cohort,
            "capabilities":capabilities_cohort}.get(args.case,generation_cohort)
        report["observations"]=cohort(args,echo)
        report["status"]="passed"
    except BaseException as error:
        failure=error;report["error"]=str(error)
    finally:
        cleanup=[cleanup_session(owner) for owner in args.sessions]
        report["cleanup"]=cleanup
        report["all_reaped"]=(args.case=="capabilities" and not cleanup) or (bool(cleanup) and all(value["terminal"] and not value["errors"] for value in cleanup))
        if not report["all_reaped"]:report["status"]="failed";report.setdefault("error","native/provider cleanup not proven")
        echo.close();signal.alarm(0);signal.signal(signal.SIGALRM,previous)
        save(args.evidence/"api-report.json",report)
        print(json.dumps(report,sort_keys=True))
    if failure is not None:raise failure
    require(report["status"]=="passed",report.get("error","cohort failed"))


if __name__=="__main__":main()
