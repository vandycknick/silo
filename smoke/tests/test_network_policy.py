from __future__ import annotations

import json
import stat
import pytest

from silo_smoke import images
from silo_smoke.cli import Silo
from silo_smoke.config import SmokeConfig
from silo_smoke.errors import SmokeAssertion
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.workspace import Workspace


@pytest.fixture(scope="session")
def ca_trust_image(config: SmokeConfig, registry: LoopbackRegistry) -> str:
    return registry.publish(images.build(images.CA_TRUST, images.fetch_alpine(config.cache_dir)), "ca-trust")


def test_bearer_policy_machine_starts_ready(silo: Silo, workspace: Workspace, ca_trust_image: str) -> None:
    workspace.silo_home.mkdir(parents=True, exist_ok=True)
    secrets = workspace.silo_home / "secrets.json"
    secrets.write_text('{"bearer_token.api.token":{"type":"plain","value":"synthetic-silod-secret"}}')
    secrets.chmod(0o600)
    assert stat.S_IMODE(secrets.stat().st_mode) == 0o600
    policy = workspace.root / "policy.json"
    policy.write_text('{"version":1,"endpoints":[{"name":"api","kind":"https","family":"http","transport":"https-mitm","tls":"terminate","capabilities":["credential-injection"],"hosts":["example.com"]}],"credentials":[{"name":"api","kind":"bearer_token","endpoint":"api"}],"rules":[{"endpoints":["api"],"credential":"api","verdict":"allow"}]}')
    name = "policy-vm"
    silo.create(name, ca_trust_image, "--cpus", "1", "--memory", "512mb", "--vsock", "--network", "private", "--network-policy", str(policy))
    try:
        silo.run("start", name, "-v")
    except SmokeAssertion:
        for stream in ("network", "monitor", "serial"):
            silo.run("logs", name, "--stream", stream, expect=None, label=f"failed-start-{stream}")
        raise
    ready = silo.wait_ready(name)
    assert ready["state"] == "running"
    assert ready["ready"] is True
    assert silo.run("logs", name, "--stream", "network-audit").returncode == 0
    # Upstream availability is outside this qualification; the audit record proves the guest
    # trusted the injected CA (the request was decrypted) and the policy selected the credential.
    silo.exec(name, "wget", "-T", "15", "-O", "/dev/null", "https://example.com", expect=None)
    audit = silo.run("logs", name, "--stream", "network-audit")
    records = [json.loads(line) for line in audit.stdout.splitlines() if line.startswith("{")]
    http = [record for record in records if record.get("family") == "http"]
    assert len(http) == 1, records
    assert http[0]["http"]["request"]["host"] == "example.com"
    assert http[0]["policy"] == {"endpoint_kind": "https", "endpoint_name": "api"}
    assert http[0]["credential"]["status"] == "selected"
    assert http[0]["verdict"] == "allow"
    silo.stop(name)
    assert silo.show(name)["state"] == "stopped"
    silo.rm(name)
    assert silo.run("show", name, expect=1).returncode == 1
