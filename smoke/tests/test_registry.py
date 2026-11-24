from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import sys

import pytest

from silo_smoke.cli import Silo
from silo_smoke.daemon import Daemon
from silo_smoke.registry import LoopbackRegistry


_CLIENT = r'''
import hashlib
import http.client
import json
from pathlib import Path
import ssl
import subprocess
import sys
from silo_smoke.registry import LoopbackRegistry

try:
    registry = LoopbackRegistry(Path(sys.argv[1]))
except subprocess.CalledProcessError as error:
    print(error.stderr.decode(errors="replace"), file=sys.stderr)
    raise
registry.start()
connection = http.client.HTTPSConnection(registry.host, registry.port,
    context=ssl.create_default_context(cafile=str(registry.ca_path)), timeout=10)
try:
    connection.connect()
    certificate = connection.sock.getpeercert()
    connection.request("GET", "/v2/")
    response = connection.getresponse()
    assert response.status == 200 and response.read() == b"{}"
    print(json.dumps({"ca": hashlib.sha256(registry.ca_path.read_bytes()).hexdigest(),
                      "serial": certificate["serialNumber"]}))
finally:
    connection.close()
    registry.stop()
'''


def test_concurrent_registries_share_ca_and_issue_distinct_valid_certificates(tmp_path: Path) -> None:
    cache = tmp_path / "shared-cache"
    smoke_root = Path(__file__).resolve().parents[1]

    def connect(_: int) -> dict[str, str]:
        result = subprocess.run([sys.executable, "-c", _CLIENT, str(cache)],
                                cwd=smoke_root, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    with ThreadPoolExecutor(max_workers=4) as workers:
        cold = list(workers.map(connect, range(4)))
        existing = list(workers.map(connect, range(4)))
    results = cold + existing
    assert len({result["ca"] for result in results}) == 1
    assert len({result["serial"] for result in results}) == len(results)


@pytest.mark.parametrize("daemon_mode", [False, pytest.param(True, marks=pytest.mark.daemon)], ids=["local", "daemon"])
def test_silo_pulls_with_workspace_registry_ca(
    silo: Silo, registry: LoopbackRegistry, basic_image: str, daemon: Daemon, daemon_mode: bool,
) -> None:
    if daemon_mode:
        daemon.start()
        daemon.wait_core()
    requests = registry.requests
    pulled = silo.json("image", "pull", basic_image)
    assert pulled["kind"] == "oci" and basic_image in pulled["info"]["names"]
    assert registry.requests > requests
