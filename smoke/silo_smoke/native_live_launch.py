#!/usr/bin/env python3
"""Translate frozen provider-fixture inputs to the explicit Silo API entry.

This is not the normal worker wire. FD 0 remains the bounded standalone command
pipe, 4 duplicates stdout, 5 watches the command pipe's parent lifetime. All
nonstandard descriptors are validated together by production worker/fds.rs before
adoption. This process execs the VM entry, retaining one PID and one sole reaper.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("disk0", "disk1", "kernel", "initramfs", "binding"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("console-fd", "console-input-fd", "console-output-fd", "net-fd", "mux-fd", "echo-port"):
        parser.add_argument("--" + name, type=int, required=True)
    parser.add_argument("--restore", type=Path)
    parser.add_argument("--ram-image-fd", type=int)
    parser.add_argument("--ram-layout-fd", type=int)
    parser.add_argument("--generation", choices=("on",))
    parser.add_argument("--generation-proof-mode", type=int, choices=(1, 2, 3, 4), default=0)
    parser.add_argument("--silo-fixture", type=Path)
    args = parser.parse_args()
    entry = Path(os.environ["SILO_NATIVE_API_EXECUTABLE"]).resolve(strict=True)
    if bool(args.restore) != (args.ram_image_fd is not None and args.ram_layout_fd is not None):
        raise ValueError("complete descriptor-fed restore roles required")
    launch = {"kernel": str(args.kernel), "initramfs": str(args.initramfs),
              "binding": str(args.binding), "restore": str(args.restore) if args.restore else None,
              "echo_port": args.echo_port, "generation_proof_mode": args.generation_proof_mode}
    if args.silo_fixture is not None:
        with args.silo_fixture.open("rb") as fixture:
            fixture_bytes = fixture.read(4097)
        if len(fixture_bytes) > 4096:
            raise ValueError("bounded Silo fixture metadata")
        launch["silo_fixture"] = json.loads(fixture_bytes)
    profile = args.binding / "api-proof-launch.json"
    if profile.exists():
        if args.restore is None or not profile.is_file() or profile.stat().st_size > 4096:
            raise ValueError("bounded restore-only standalone proof profile")
        proof = json.loads(profile.read_bytes())
        if set(proof) != {"proof"} or proof["proof"] not in ("prepared-callback-failure", "install-timeout"):
            raise ValueError("unknown standalone restore proof profile")
        launch["proof"] = proof["proof"]
    payload = json.dumps(launch, separators=(",", ":")).encode()
    if len(payload) > 4096:
        raise ValueError("bounded bootstrap metadata exceeds atomic pipe write")
    config, writer = os.pipe2(os.O_CLOEXEC)
    if os.write(writer, payload) != len(payload):
        raise RuntimeError("short bootstrap metadata write")
    os.close(writer)
    lease = os.open(args.binding.parent / "api.lease", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    fcntl.flock(lease, fcntl.LOCK_SH | fcntl.LOCK_NB)
    roles = {3: config, 4: 1, 5: 0, 6: args.console_fd, 7: args.mux_fd, 8: lease,
             9: os.open(args.disk0, os.O_RDWR | os.O_CLOEXEC),
             10: os.open(args.disk1, os.O_RDWR | os.O_CLOEXEC),
             29: args.net_fd, 30: args.console_input_fd, 31: args.console_output_fd}
    if args.restore:
        roles.update({25: args.ram_image_fd, 26: args.ram_layout_fd,
                      27: os.open(args.restore / "execution.state", os.O_RDONLY | os.O_CLOEXEC),
                      28: os.open(args.restore / "devices.state", os.O_RDONLY | os.O_CLOEXEC)})
    # Move above the entire fixed table before dup2; inherited source numbers can
    # otherwise collide with a destination and silently exchange resource roles.
    temporary = {destination: fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, 64)
                 for destination, source in roles.items()}
    for destination, source in temporary.items():
        os.dup2(source, destination, inheritable=True)
    for raw in os.listdir("/proc/self/fd"):
        fd = int(raw)
        if fd >= 3 and fd not in roles:
            try:
                os.close(fd)
            except OSError:
                # os.listdir's own directory FD is already closed.
                if Path(f"/proc/self/fd/{fd}").exists():
                    raise
    os.execv(entry, [str(entry), *(["--restore"] if args.restore else [])])


if __name__ == "__main__":
    main()
