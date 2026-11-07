"""Real CLI/KVM private-stage replacement while qualified source FDs are held."""
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
    fixture_root = os.environ.get('SILO_SMOKE_FAULT_MONITORS')
    assert fixture_root, 'build fresh COPY-only reordered fixture first'
    fixture = json.loads((Path(fixture_root) / 'reordered/fault-manifest.json').read_text())
    assert fixture['fault'] == 'reordered' and fixture['declaredNativeBaseline'] == overlay.APPROVED_NATIVE_REVISION
    assert fixture['validationUnchanged'] and fixture['uniqueAttachmentKeysUnchanged']
    assert overlay.digest(Path(fixture['binary'])) == fixture['binarySha256']
    shutil.copyfile(fixture['binary'], successor / 'bin/silo-vmm')
    (successor / 'bin/silo-vmm').chmod(0o700)
    files = {'kernel': private / 'assets/kernel-default', 'base': private / 'assets/initramfs', 'native': private / 'bin/silo-vmm'}
    assert fixture['binarySha256'] != overlay.digest(files['native'])
    for kind in ('kernel', 'base'):
        assert overlay.digest(successor / files[kind].relative_to(private)) == overlay.digest(files[kind])
    environment = silo.ws.env(SILO_RUNTIME_DIR=str(private))
    name = 'overlay-stage-replacement'
    silo.run('create', reference, '--name', name, '--root-profile', overlay.PROFILE, '--disk-size', '128mib', '--network', 'none', '--vsock', env=environment)
    silo.ws.register_machine(name)
    directory = overlay.machine_dir(silo, name)
    assert not (directory / 'kernel-qualified').exists(), 'fresh create must not have published a launch kernel'
    binding = stopped.record(silo, name)['boot']['binding']
    pool = silo.ws.silo_home / 'images/objects/sha256'
    files['kernel'] = pool / binding['kernel'].removeprefix('sha256:')
    files['base'] = pool / binding['baseInitramfs'].removeprefix('sha256:')
    identities = {kind: {'device': path.stat().st_dev, 'inode': path.stat().st_ino, 'length': path.stat().st_size, 'sha256': overlay.digest(path)} for kind, path in files.items()}
    command = ['/usr/bin/env', f'SILO_RUNTIME_DIR={private}', str(silo.ws.config.silo), 'start', name]
    with stopped.syscall_boundary(silo, command, files['native'], 'boot-kernel-copy') as receipt:
        pid = receipt['pid']
        observed = descriptors(pid)
        silo.ws.record('overlay-stage-interception', json.dumps({'receipt': receipt, 'descriptors': observed, 'sourceIdentities': identities}) + '\n')
        temporary = Path(receipt['target'])
        assert temporary.parent == directory and temporary.stat().st_size == 0
        assert not (directory / 'kernel-qualified').exists()
        assert not list(directory.glob('.initramfs.*.tmp'))
        assert procs.vmm_pid(silo.ws, name) is None
        captured_fds = {}
        for kind, identity in identities.items():
            matches = [fd for fd in observed if (fd['device'], fd['inode']) == (identity['device'], identity['inode'])]
            assert matches, f'qualified retained {kind} FD absent'
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
            assert metadata.st_nlink == (0 if kind == 'native' else 1)
            assert overlay.digest(path) == identities[kind]['sha256']
            retained[kind] = {'fd': matches[0]['fd'], 'target': os.readlink(path), 'links': metadata.st_nlink, 'sha256': identities[kind]['sha256']}
        silo.ws.record('overlay-stage-retained-qualified-assets', json.dumps(retained) + '\n')
        (silo.ws.evidence / 'boundary-release').touch()
        silo.wait_ready(name)
        actual = {}
        monitor = procs.vmm_pid(silo.ws, name)
        assert monitor is not None
        for kind, pid in [('monitor', monitor), ('worker', overlay.worker_pid(silo, name))]:
            executable = Path('/proc') / str(pid) / 'exe'
            metadata = executable.stat()
            digest = overlay.digest(executable)
            assert digest == identities['native']['sha256'] and metadata.st_nlink == 0
            assert (metadata.st_dev, metadata.st_ino) == (identities['native']['device'], identities['native']['inode'])
            actual[kind] = {'pid': pid, 'sha256': digest, 'target': os.readlink(executable), 'links': metadata.st_nlink, 'device': metadata.st_dev, 'inode': metadata.st_ino}
        assert overlay.digest(directory / 'kernel-qualified') == identities['kernel']['sha256']
        assert overlay.digest(directory / 'initramfs', identities['base']['length']) == identities['base']['sha256']
        overlay.evidence(silo, name)
        silo.ws.record('overlay-stage-bound-executables', json.dumps(actual) + '\n')
        silo.stop(name)
    before = {'runId': procs.run_id(silo.ws, name), 'monitorPid': procs.vmm_pid(silo.ws, name)}
    refusal = silo.run('start', name, env=environment, expect=None)
    assert refusal.returncode != 0
    assert 'unqualified linux-flat-overlay-v1 boot tuple' in refusal.stderr and 'native sha256:' + fixture['binarySha256'] in refusal.stderr
    assert silo.info(name)['state'] == 'stopped'
    assert before == {'runId': procs.run_id(silo.ws, name), 'monitorPid': procs.vmm_pid(silo.ws, name)}, 'unknown replacement bytes must not allocate a new run'
    silo.ws.record('overlay-stage-fresh-refusal', json.dumps(before) + '\n' + refusal.stderr)
