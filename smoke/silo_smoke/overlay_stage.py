"""Real CLI/KVM stage replacement while held guest boot assets are copied."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil

from . import overlay, procs, stopped
from .cli import Silo

def descriptors(pid: int) -> list[dict]:
    result = []
    directory = Path('/proc') / str(pid)
    for entry in (directory / 'fd').iterdir():
        try:
            metadata = entry.stat()
            info = (directory / 'fdinfo' / entry.name).read_text()
            target = os.readlink(entry)
        except FileNotFoundError:
            continue
        flags = int(next(line.split()[1] for line in info.splitlines() if line.startswith('flags:')), 8)
        result.append({'fd': int(entry.name), 'device': metadata.st_dev, 'inode': metadata.st_ino, 'links': metadata.st_nlink, 'length': metadata.st_size, 'flags': flags, 'target': target})
    return result


def replacement(silo: Silo, reference: str) -> None:
    root = silo.ws.root
    private = root / 'private-stage'
    successor = root / 'next-stage'
    retired = root / 'unlinked-stage'
    overlay.copy_runtime(silo.ws.config.runtime_dir, private)
    overlay.copy_runtime(private, successor)
    monitor_path = private / 'bin/silo-vmm'
    original = monitor_path.stat()
    original_identity = (original.st_dev, original.st_ino)
    successor_monitor = successor / 'bin/silo-vmm'
    installed = successor_monitor.stat()
    successor_identity = (installed.st_dev, installed.st_ino)
    assert successor_identity != original_identity
    monitor_digest = overlay.digest(monitor_path)
    assert overlay.digest(successor_monitor) == monitor_digest
    for path in ('assets/kernel-default', 'assets/initramfs'):
        assert overlay.digest(successor / path) == overlay.digest(private / path)
    environment = silo.ws.env(SILO_RUNTIME_DIR=str(private))
    name = 'overlay-stage-replacement'
    silo.run('create', reference, '--name', name, '--disk-size', '128mib', '--network', 'none', '--vsock', env=environment)
    silo.ws.register_machine(name)
    directory = overlay.machine_dir(silo, name)
    assert not (directory / 'kernel-qualified').exists(), 'fresh create must not have published a launch kernel'
    binding = stopped.record(silo, name)['boot']['binding']
    pool = silo.ws.silo_home / 'images/objects/sha256'
    files = {
        'kernel': pool / binding['kernel'].removeprefix('sha256:'),
        'base': pool / binding['baseInitramfs'].removeprefix('sha256:'),
    }
    identities = {kind: {'device': path.stat().st_dev, 'inode': path.stat().st_ino, 'length': path.stat().st_size, 'sha256': overlay.digest(path)} for kind, path in files.items()}
    command = ['/usr/bin/env', f'SILO_RUNTIME_DIR={private}', str(silo.ws.config.silo), 'start', name]
    with stopped.syscall_boundary(silo, command, files['kernel'], 'boot-kernel-copy') as receipt:
        pid = receipt['pid']
        observed = descriptors(pid)
        silo.ws.record('overlay-stage-interception', json.dumps({'receipt': receipt, 'descriptors': observed, 'sourceIdentities': identities}) + '\n')
        temporary = Path(receipt['target'])
        assert temporary.parent == directory and temporary.stat().st_size == 0
        assert temporary.name.startswith('.launch-') and temporary.name.endswith('.tmp')
        assert not (directory / 'kernel-qualified').exists()
        assert not (directory / 'initramfs').exists()
        assert not list(directory.glob('.initramfs.*.tmp'))
        assert procs.vmm_pid(silo.ws, name) is None
        assert all((fd['device'], fd['inode']) != original_identity for fd in observed), 'boot held a monitor FD'
        captured_fds = {}
        for kind, identity in identities.items():
            matches = [fd for fd in observed if (fd['device'], fd['inode']) == (identity['device'], identity['inode'])]
            assert matches, f'owned retained {kind} FD absent'
            for fd in matches:
                assert fd['fd'] >= 3 and fd['flags'] & os.O_ACCMODE == os.O_RDONLY and fd['flags'] & os.O_CLOEXEC
                assert overlay.digest(Path('/proc') / str(pid) / 'fd' / str(fd['fd'])) == identity['sha256']
            captured_fds[kind] = matches
        private.rename(retired)
        successor.rename(private)
        shutil.rmtree(retired)
        retained = {}
        for kind, matches in captured_fds.items():
            path = Path('/proc') / str(pid) / 'fd' / str(matches[0]['fd'])
            metadata = path.stat()
            assert (metadata.st_dev, metadata.st_ino) == (identities[kind]['device'], identities[kind]['inode'])
            assert metadata.st_nlink == 1
            assert overlay.digest(path) == identities[kind]['sha256']
            retained[kind] = {'fd': matches[0]['fd'], 'target': os.readlink(path), 'links': metadata.st_nlink, 'sha256': identities[kind]['sha256']}
        silo.ws.record('overlay-stage-retained-owned-assets', json.dumps(retained) + '\n')
        (silo.ws.evidence / 'boundary-release').touch()
        # The tracer waits for descendants, so inspect and stop the live VM before leaving.
        silo.wait_ready(name)
        assert overlay.digest(directory / 'kernel-qualified') == identities['kernel']['sha256']
        assert overlay.digest(directory / 'initramfs', identities['base']['length']) == identities['base']['sha256']
        actual = {}
        monitor = procs.vmm_pid(silo.ws, name)
        assert monitor is not None
        for kind, child_pid in [('monitor', monitor), ('worker', overlay.worker_pid(silo, name))]:
            executable = Path('/proc') / str(child_pid) / 'exe'
            metadata = executable.stat()
            assert (metadata.st_dev, metadata.st_ino) == successor_identity
            assert overlay.digest(executable) == monitor_digest
            actual[kind] = {'pid': child_pid, 'inode': metadata.st_ino, 'sha256': monitor_digest, 'target': os.readlink(executable)}
        overlay.evidence(silo, name)
        silo.ws.record('overlay-stage-successor-executables', json.dumps(actual) + '\n')
        silo.stop(name)
