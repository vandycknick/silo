from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
from uuid import UUID

import pytest

from silo_smoke import images
from silo_smoke.cli import Silo
from silo_smoke.config import SmokeConfig
from silo_smoke.errors import SmokeAssertion
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.workspace import Workspace


KEY = "openai_codex_oauth.personal.oauth"
EXPIRED_TOKEN = "expired-initial-payload"
REFRESHED_TOKEN = "synthetic-sec02-refreshed-access"


@pytest.fixture(scope="session")
def ca_trust_image(config: SmokeConfig, registry: LoopbackRegistry) -> str:
    return registry.publish(
        images.build(images.CA_TRUST, images.fetch_alpine(config.cache_dir)), "ca-trust",
    )


def _replace_record(store: Path, token: str, expiry: str) -> None:
    record = {
        KEY: {
            "type": "oauth", "access_token": token,
            "refresh_token": "", "expires_at": expiry,
        },
    }
    replacement = store.with_suffix(".replacement")
    replacement.write_text(json.dumps(record))
    replacement.chmod(0o600)
    replacement.replace(store)


@pytest.mark.live
def test_secret_provider_reloads_expired_payload(
    silo: Silo, workspace: Workspace, ca_trust_image: str,
) -> None:
    # The CLI installs this exact provider/store hook on the launched netd.
    store = workspace.silo_home / "secrets.json"
    _replace_record(store, EXPIRED_TOKEN, "2020-01-01T00:00:00Z")
    policy = workspace.root / "policy.json"
    policy.write_text(json.dumps({
        "version": 1,
        "endpoints": [{
            "name": "echo", "kind": "https", "family": "http",
            "transport": "https-mitm", "tls": "terminate",
            "capabilities": ["credential-injection"], "hosts": ["httpbingo.org"],
        }],
        "credentials": [{
            "name": "personal", "kind": "openai_codex_oauth", "endpoint": "echo",
        }],
        "rules": [{"endpoints": ["echo"], "credential": "personal", "verdict": "allow"}],
    }))
    name = "sec02-provider"
    silo.create(
        name, ca_trust_image, "--cpus", "1", "--memory", "512mb", "--vsock",
        "--network", "private", "--network-policy", str(policy),
    )
    provider = silo.popen("secret", "provide", "--store-file", str(store), stdin=subprocess.PIPE)
    try:
        silo.start(name)
        ready = silo.wait_ready(name)
        assert ready["state"] == "running"
        assert provider.poll() is None
        # netd still holds the expired launch payload when the host refresh wins.
        _replace_record(store, REFRESHED_TOKEN, "2099-01-01T00:00:00Z")
        before = store.read_bytes()
        for _ in range(2):
            try:
                output = silo.exec(name, "wget", "-qO-", "https://httpbingo.org/bearer", timeout=30)
            except SmokeAssertion:
                for stream in ("network", "network-audit"):
                    silo.run("logs", name, "--stream", stream, expect=None, label=f"failed-request-{stream}")
                raise
            echoed = json.loads(output.stdout)
            assert echoed["authenticated"] is True
            assert echoed["token"] == REFRESHED_TOKEN
            assert EXPIRED_TOKEN not in output.stdout
        assert store.read_bytes() == before

        # Exercise a fresh get in the separately spawned actual CLI provider.
        machine = UUID(ready["id"]).hex
        names = ["personal.oauth.access_token", "personal.oauth.expires_at"]
        grant = {
            "version": 2, "store": f"file:{store}", "machine": machine,
            "run": ready["run_id"], "issued_at": datetime.now(timezone.utc).isoformat(),
            "allowed": [
                {"slot": slot, "key": KEY, "field": field, "backing_scope": "Home"}
                for slot, field in zip(names, ["OAuthAccessToken", "OAuthExpiresAt"], strict=True)
            ],
        }
        request = json.dumps({
            "version": 2, "operation": "get",
            "grant": base64.b64encode(json.dumps(grant).encode()).decode(),
            "scope": {"machine": machine, "run": ready["run_id"]},
            "names": names, "reason": "expired",
        }).encode()
        frame = f"Content-Length: {len(request)}\r\n\r\n".encode() + request
        stdout, stderr = provider.communicate(frame, timeout=20)
        workspace.record("secret-provider", f"{stdout.decode()}\n[stderr]\n{stderr.decode()}")
        assert provider.returncode == 0
        header, body = stdout.split(b"\r\n\r\n", 1)
        assert header == f"Content-Length: {len(body)}".encode()
        response = json.loads(body)
        assert response["version"] == 2
        assert response["status"] == "ok"
        projected = {item["name"]: base64.b64decode(item["value"]).decode() for item in response["secrets"]}
        assert projected == {
            names[0]: REFRESHED_TOKEN, names[1]: "2099-01-01T00:00:00Z",
        }
        assert store.read_bytes() == before
        silo.stop(name)
        assert silo.show(name)["state"] == "stopped"
        silo.rm(name)
    finally:
        if provider.poll() is None:
            provider.terminate()
            try:
                provider.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                provider.kill()
                provider.communicate(timeout=10)
