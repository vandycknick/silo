from __future__ import annotations

import hashlib

from silo_smoke.cli import Silo, Vm
from silo_smoke.workspace import Workspace


def test_cp_round_trip_and_directory_hint(silo: Silo, workspace: Workspace, vm: Vm) -> None:
    data = bytes(i % 251 for i in range(300 * 1024))
    digest = hashlib.sha256(data).hexdigest()
    source = workspace.root / "input.bin"
    source.write_bytes(data)
    for disposition in ("created", "replaced"):
        assert silo.json("cp", str(source), f"{vm.id}:/root/in.bin") == {
            "direction": "upload", "vm": vm.id, "path": "/root/in.bin",
            "bytes": 307200, "sha256": digest, "disposition": disposition,
        }
    target = workspace.root / "output.bin"
    downloaded = silo.run("cp", f"{vm.id}:/root/in.bin", str(target))
    assert downloaded.stdout == ""
    assert downloaded.stderr == f"copied 307200 bytes from {vm.id}:/root/in.bin (sha256 {digest})\n"
    assert target.read_bytes() == data
    directory = workspace.root / "directory"
    directory.mkdir()
    rejected = silo.run("cp", str(directory), f"{vm.id}:/root/dir", expect=1)
    assert rejected.returncode == 1
    assert f"{directory} is a directory; use: exec {vm.id} -- tar -xC DIR < bundle.tar" in rejected.stderr
