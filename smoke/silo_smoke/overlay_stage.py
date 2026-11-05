"""Real CLI/KVM private-stage replacement while qualified source FDs are held."""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import time
import shutil

from . import overlay, procs
from .cli import Silo

ADMITTED_NATIVE_SHA256 = '08798da88922cdb0e9c15a2831b81540c0ad2e79962f7c56542c33655a9d0bad'


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


def stop_owned_group(child: subprocess.Popen) -> None:
    assert child.poll() is None and os.getpgid(child.pid) == child.pid
    os.killpg(child.pid, signal.SIGSTOP)
    deadline = time.monotonic() + 3
    while child.poll() is None:
        states = []
        for task in (Path('/proc') / str(child.pid) / 'task').iterdir():
            try:
                states.append(next(line.split()[1] for line in (task / 'status').read_text().splitlines() if line.startswith('State:')))
            except FileNotFoundError:
                continue
        if states and all(state == 'T' for state in states):
            return
        assert time.monotonic() < deadline, f'owned CLI threads did not stop: {states}'
        # Condition wait after SIGSTOP, not a sleep used to select a race window.
        select.select([], [], [], 0.001)
    raise AssertionError('owned CLI exited before the interception boundary')


def replacement(silo: Silo, reference: str) -> None:
    root = silo.ws.root
    private = root / 'private-stage'
    successor = root / 'next-stage'
    retired = root / 'unlinked-stage'
    shutil.copytree(silo.ws.config.runtime_dir, private, symlinks=False)
    shutil.copytree(private, successor, symlinks=False)
    fixture_root = os.environ.get('SILO_SMOKE_FAULT_MONITORS')
    assert fixture_root, 'build fresh COPY-only reordered fixture first'
    fixture = json.loads((Path(fixture_root) / 'reordered/fault-manifest.json').read_text())
    assert fixture['fault'] == 'reordered' and fixture['declaredNativeBaseline'] == overlay.APPROVED_NATIVE_REVISION
    assert fixture['validationUnchanged'] and fixture['uniqueAttachmentKeysUnchanged']
    assert overlay.digest(Path(fixture['binary'])) == fixture['binarySha256']
    assert fixture['binarySha256'] != ADMITTED_NATIVE_SHA256
    shutil.copyfile(fixture['binary'], successor / 'bin/silo-vmm')
    (successor / 'bin/silo-vmm').chmod(0o700)
    files = {'kernel': private / 'assets/kernel-default', 'base': private / 'assets/initramfs', 'native': private / 'bin/silo-vmm'}
    identities = {kind: {'device': path.stat().st_dev, 'inode': path.stat().st_ino, 'length': path.stat().st_size, 'sha256': overlay.digest(path)} for kind, path in files.items()}
    assert identities['native']['sha256'] == ADMITTED_NATIVE_SHA256
    for kind in ('kernel', 'base'):
        assert overlay.digest(successor / files[kind].relative_to(private)) == identities[kind]['sha256']
    environment = silo.ws.env(SILO_RUNTIME_DIR=str(private))
    name = 'overlay-stage-replacement'
    silo.run('create', reference, '--name', name, '--root-profile', overlay.PROFILE, '--disk-size', '128mib', '--network', 'none', '--vsock', env=environment)
    silo.ws.register_machine(name)
    directory = overlay.machine_dir(silo, name)
    assert not (directory / 'kernel-qualified').exists(), 'fresh create must not have published a launch kernel'
    native = ctypes.CDLL(None, use_errno=True)
    native.inotify_init1.argtypes = [ctypes.c_int]
    native.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    notify = native.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    assert notify >= 0, os.strerror(ctypes.get_errno())
    child = None
    events = []
    output = silo.ws.evidence / 'stage-replacement-cli.stdout'
    error = silo.ws.evidence / 'stage-replacement-cli.stderr'
    try:
        watches = {}
        for kind, path in [*files.items(), ('machine', directory)]:
            wd = native.inotify_add_watch(notify, os.fsencode(path), 0x20 | 0x100)
            assert wd >= 0, os.strerror(ctypes.get_errno())
            watches[wd] = kind
        with output.open('wb') as stdout, error.open('wb') as stderr:
            child = silo.popen('start', name, env=environment, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
            deadline = time.monotonic() + 90
            captured = False
            while not captured:
                assert child.poll() is None, 'CLI exited before post-admission private output; inspect retained stdout/stderr'
                remaining = deadline - time.monotonic()
                assert remaining > 0, 'no post-admission .lower temporary IN_OPEN observed'
                ready, _, _ = select.select([notify], [], [], min(remaining, 1))
                if not ready:
                    continue
                data = os.read(notify, 65536)
                position = 0
                while position < len(data):
                    wd, mask, _, size = struct.unpack_from('iIII', data, position)
                    leaf = data[position + 16:position + 16 + size].split(b'\0', 1)[0].decode()
                    position += 16 + size
                    assert not mask & 0x4000, 'inotify queue overflow invalidates interception evidence'
                    events.append({'watch': watches.get(wd), 'mask': mask, 'name': leaf})
                    if watches.get(wd) != 'machine' or not mask & 0x20 or not (leaf.startswith('.lower-') and leaf.endswith('.tmp')):
                        continue
                    # publish_descriptor follows successful qualification and
                    # precedes BOTH checked boot-asset copies and native exec.
                    stop_owned_group(child)
                    observed = descriptors(child.pid)
                    silo.ws.record('overlay-stage-interception', json.dumps({'cliPid': child.pid, 'pgid': os.getpgid(child.pid), 'events': events, 'descriptors': observed, 'sourceIdentities': identities}) + '\n')
                    temporary = directory / leaf
                    assert temporary.exists(), 'missed private descriptor creation boundary (already renamed); do not weaken to hash-in-progress'
                    metadata = temporary.stat()
                    assert any((fd['device'], fd['inode']) == (metadata.st_dev, metadata.st_ino) for fd in observed), 'actual post-admission private output is not held by owned CLI'
                    assert not (directory / 'kernel-qualified').exists() and not list(directory.glob('.kernel-*.tmp')), 'interception missed the pre-kernel-copy boundary'
                    assert not list(directory.glob('.initramfs.*.tmp')), 'interception missed pre-base-copy boundary'
                    assert procs.vmm_pid(silo.ws, name) is None, 'monitor must not have executed yet'
                    captured_fds = {}
                    for kind, identity in identities.items():
                        matches = [fd for fd in observed if (fd['device'], fd['inode']) == (identity['device'], identity['inode'])]
                        assert matches, f'qualified retained {kind} FD absent; earlier capability query is not this boundary'
                        for fd in matches:
                            assert fd['fd'] >= 3 and fd['flags'] & os.O_ACCMODE == os.O_RDONLY and fd['flags'] & os.O_CLOEXEC
                            assert overlay.digest(Path('/proc') / str(child.pid) / 'fd' / str(fd['fd'])) == identity['sha256']
                        captured_fds[kind] = matches
                    private.rename(retired)
                    successor.rename(private)
                    shutil.rmtree(retired)
                    unlinked = {}
                    for kind, matches in captured_fds.items():
                        path = Path('/proc') / str(child.pid) / 'fd' / str(matches[0]['fd'])
                        metadata = path.stat()
                        assert metadata.st_nlink == 0 and (metadata.st_dev, metadata.st_ino) == (identities[kind]['device'], identities[kind]['inode'])
                        assert overlay.digest(path) == identities[kind]['sha256']
                        unlinked[kind] = {'fd': matches[0]['fd'], 'target': os.readlink(path), 'links': metadata.st_nlink, 'sha256': overlay.digest(path)}
                    silo.ws.record('overlay-stage-unlinked-qualified-assets', json.dumps(unlinked) + '\n')
                    os.killpg(child.pid, signal.SIGCONT)
                    captured = True
                    break
            child.communicate(timeout=120)
            assert child.returncode == 0, f'retained qualified launch failed: {error.read_text()}'
        silo.wait_ready(name)
        actual = {}
        monitor = procs.vmm_pid(silo.ws, name)
        assert monitor is not None
        for kind, pid in [('monitor', monitor), ('worker', overlay.worker_pid(silo, name))]:
            executable = Path('/proc') / str(pid) / 'exe'
            metadata = executable.stat()
            digest = overlay.digest(executable)
            assert digest == ADMITTED_NATIVE_SHA256 and metadata.st_nlink == 0
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
    finally:
        try:
            if child is not None and child.poll() is None:
                # This group belongs exclusively to this unreaped Popen child.
                os.killpg(child.pid, signal.SIGCONT)
                try:
                    child.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.communicate(timeout=10)
        finally:
            os.close(notify)
            silo.ws.record('overlay-stage-events', json.dumps(events) + '\n')
            for label, path in [('stdout', output), ('stderr', error)]:
                if path.exists():
                    silo.ws.record('overlay-stage-cli-' + label, path.read_text(errors='replace'))
