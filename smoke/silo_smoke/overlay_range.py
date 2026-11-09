"""Real bounded native DISCARD/WRITE_ZEROES evidence in a private mount namespace.

Only one 4MiB Data file enters ramfs (which has no intrinsic size limit). All
root storage, database, logs, copies and evidence remain outside that mount.
An unmodified production-path run and a separately labelled COPY-only opcode
observer are both required; neither an ioctl's name nor zeros prove its opcode.
"""
from __future__ import annotations

import ctypes
import errno
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from . import overlay
from .cli import Silo
from .config import SmokeConfig
from .overlay_candidate import Candidate
from .workspace import Workspace

SIZE = 4 * 1024**2


def worker_file(ws: Workspace, pid: int, path: Path) -> list[dict]:
    expected = path.stat()
    handles = []
    for fd in (Path('/proc') / str(pid) / 'fd').iterdir():
        try:
            actual = fd.stat()
            info = (fd.parent.parent / 'fdinfo' / fd.name).read_text()
        except FileNotFoundError:
            continue
        if (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino):
            flags = int(next(line.split()[1] for line in info.splitlines() if line.startswith('flags:')), 8)
            assert flags & os.O_ACCMODE == os.O_RDWR
            handles.append({'fd': int(fd.name), 'flags': flags, 'device': actual.st_dev, 'inode': actual.st_ino, 'length': actual.st_size})
    assert handles, 'actual worker must hold this exact raw Data inode writable'
    ws.record('overlay-range-worker-handles', json.dumps({'pid': pid, 'handles': handles}) + '\n')
    return handles


def main() -> None:
    request = json.loads(Path(sys.argv[1]).read_text())
    assert os.getuid() == 0 and os.readlink('/proc/self/ns/user') != request['outer_user_namespace']
    assert Path('/proc/self/uid_map').read_text().split()[1] == request['outer_uid']
    values = request['config']
    for key in ('bin_dir', 'runtime_dir', 'cache_dir'):
        values[key] = Path(values[key])
    ws = Workspace(SmokeConfig(**values), Path(request['registry_ca']))
    destination = Path(request['evidence'])
    destination.mkdir(parents=True, exist_ok=True)
    (destination / 'child-workspace.json').write_text(json.dumps({'root': str(ws.root), 'evidence': str(ws.evidence)}) + '\n')
    silo = Silo(ws)
    mountpoint = ws.root / 'bounded-data'
    mountpoint.mkdir(mode=0o700)
    backing = request['backing']
    assert backing in ('ramfs', 'tmpfs')
    options = 'mode=0700' if backing == 'ramfs' else 'size=8m,mode=0700'
    subprocess.run(['mount', '-t', backing, '-o', options, 'overlay-native-range', str(mountpoint)], check=True, timeout=15)
    data = mountpoint / 'data.raw'
    original = b'\xa5' * SIZE
    operation, region = request['operation'], request['region']
    assert operation in ('discard', 'zero', 'zero-unmap')
    offset, length = {'middle': (4096, 4096), 'tail': (SIZE - 4096, 4096), 'whole': (0, SIZE), 'middle-sector': (512, 512), 'tail-sector': (SIZE - 512, 512)}[region]
    expected = original[:offset] + bytes(length) + original[offset + length:]
    candidate = None
    failed = True
    production = None
    try:
        data.write_bytes(original)
        native = ctypes.CDLL(None, use_errno=True)
        native.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_longlong, ctypes.c_longlong]
        native.fallocate.restype = ctypes.c_int
        controls = []
        with data.open('r+b') as owned:
            for mode, name in ((3, 'PUNCH_HOLE|KEEP_SIZE'), (17, 'ZERO_RANGE|KEEP_SIZE')):
                owned.seek(0)
                owned.write(original)
                owned.flush()
                os.fsync(owned.fileno())
                ctypes.set_errno(0)
                result = native.fallocate(owned.fileno(), mode, 4096, 4096)
                actual_errno = ctypes.get_errno() if result != 0 else 0
                if backing == 'ramfs':
                    assert result == -1 and actual_errno == errno.EOPNOTSUPP, (name, result, actual_errno)
                elif mode == 3:
                    assert result == 0, (name, result, actual_errno)
                else:
                    assert actual_errno in (0, errno.EOPNOTSUPP), (name, result, actual_errno)
                after = data.read_bytes()
                control_expected = original[:4096] + bytes(4096) + original[8192:] if result == 0 else original
                assert after == control_expected and data.stat().st_size == SIZE
                controls.append({'mode': name, 'result': result, 'errno': actual_errno, 'ownedFd': owned.fileno(), 'device': data.stat().st_dev, 'inode': data.stat().st_ino})
        ws.record('overlay-range-real-host-controls', json.dumps(controls) + '\n')
        data.write_bytes(original)
        name = 'native-range-production'
        production = name
        overlay.create(silo, name, request['image'], '--disk', str(data), capacity='128mib')
        worker_file(ws, overlay.worker_pid(silo, name), data)
        result = silo.exec(name, overlay.PROBE, 'range-request', f'{operation}:{offset}:{length}', user='root')
        assert f'SILO_RANGE_RESULT operation={operation} offset={offset} length={length}' in result.stdout
        silo.stop(name)
        assert data.stat().st_size == SIZE and data.read_bytes() == expected
        silo.start(name)
        silo.wait_ready(name)
        device = silo.exec(name, 'sh', '-c', 'for p in /sys/block/*; do test ! -f "$p/serial" || test "$(cat "$p/serial")" != silo-data-0 || echo /dev/${p##*/}; done', user='root').stdout.strip()
        assert re.fullmatch(r'/dev/vd[a-z]+', device), device
        assert int(silo.exec(name, 'blockdev', '--getsize64', device, user='root').stdout) == SIZE
        for position in sorted({offset, offset + length - 512}):
            assert silo.exec(name, overlay.PROBE, 'read-file', device, str(position), user='root').stdout.strip() == '00' * 512
        silo.stop(name)
        assert data.stat().st_size == SIZE and data.read_bytes() == expected
        # A separately built observer monitor only observes real parsed
        # opcodes; the successful public production run above is not replaced.
        data.write_bytes(original)
        candidate = Candidate(silo, request['image'], fault='range-observer', data=data, range_request=f'{operation}:{offset}:{length}')
        candidate.start()
        text = candidate.wait()
        assert f'SILO_RANGE_RESULT operation={operation} offset={offset} length={length}' in text
        worker_file(ws, candidate.identities['workerPid'], data)
        candidate.close()
        diagnostic = candidate.native_diagnostic()
        responders = set(re.findall(r'SILO_SMOKE_GET_ID device=(\S+) sectors=8192 reply=silo-data-0', diagnostic))
        assert len(responders) == 1, diagnostic
        opcode = 'DISCARD' if operation == 'discard' else 'WRITE_ZEROES'
        expected_flags = 1 if operation == 'zero-unmap' else 0
        observed = [(actual_op, int(start), int(count), int(flags)) for device_id, actual_op, start, count, flags in re.findall(r'SILO_SMOKE_BLOCK_REQUEST device=(\S+) op=(\S+) offset=(\d+) length=(\d+) flags=(\d+)', diagnostic) if device_id in responders]
        assert observed, f'guest operation did not prove actual native {opcode}; ordinary-write kernel fallback is not opcode evidence: {diagnostic}'
        assert all(actual_op == opcode and flags == expected_flags for actual_op, _, _, flags in observed), observed
        requests = [(start, count) for _, start, count, _ in observed]
        covered = offset
        for start, count in sorted(requests):
            assert count > 0 and offset <= start <= covered and start + count <= offset + length, requests
            covered = max(covered, start + count)
        assert covered == offset + length, requests
        assert data.stat().st_size == SIZE and data.read_bytes() == expected
        assert list(mountpoint.iterdir()) == [data] and data.stat().st_size <= SIZE
        ws.record('overlay-range-complete', json.dumps({'backing': backing, 'operation': operation, 'offset': offset, 'length': length, 'logicalLength': SIZE, 'nativeOpcode': opcode, 'nativeFlags': expected_flags, 'observedNativeRequests': observed, 'nativeRequests': requests, 'nativeIdentity': candidate.identities, 'productionPath': 'unmodified staged CLI/libvm/monitor/worker; stop/reopen/capacity/guest read', 'observerPath': 'COPY-only actual parsed opcode/flags; never installed into the shared stage'}) + '\n')
        failed = False
    finally:
        try:
            if candidate is not None:
                candidate.close()
        finally:
            try:
                if production is not None:
                    silo.stop(production, force=True)
            finally:
                try:
                    subprocess.run(['umount', str(mountpoint)], check=True, timeout=15)
                finally:
                    shutil.copytree(ws.evidence, destination, dirs_exist_ok=True)
                    ws.cleanup(failed=failed)


if __name__ == '__main__':
    main()
