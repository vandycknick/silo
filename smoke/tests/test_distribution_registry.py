from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, replace
import hashlib
import io
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tarfile

import pytest

from silo_smoke import images
from silo_smoke.config import SmokeConfig
from silo_smoke.distribution_registry import (
    DISTRIBUTION_MODULE, DISTRIBUTION_VERSION, EMPTY_JSON, OCI_EMPTY, OCI_INDEX, OCI_MANIFEST, DistributionClient,
    DistributionRegistry, DistributionRelease, digest_of, host_release, install_distribution, parse_gc_output,
    running_distribution,
)
from silo_smoke.errors import SmokeAssertion, SmokeEnvironmentError


# --- Pinned acquisition, exercised offline through real file:// archives ----------------------


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _member(name: str, data: bytes = b"", *, kind: bytes = tarfile.REGTYPE, target: str = "") -> tuple[tarfile.TarInfo, bytes | None]:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.mode = 0o755
    if kind == tarfile.REGTYPE:
        info.size = len(data)
        return info, data
    info.linkname = target
    return info, None


def _archive(path: Path, members: list[tuple[tarfile.TarInfo, bytes | None]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as bundle:
        for info, data in members:
            bundle.addfile(info, io.BytesIO(data) if data is not None else None)
    return path


def _release(archive: Path, binary: bytes) -> DistributionRelease:
    data = archive.read_bytes()
    return DistributionRelease(version="test", arch="amd64", url=archive.as_uri(), archive_sha256=_sha(data),
                               archive_size=len(data), binary_sha256=_sha(binary), binary_size=len(binary))


def _install_dir(cache: Path) -> Path:
    return cache / "distribution-registry/test/amd64"


BINARY = b"#!/bin/sh\necho pinned-registry\n"


def test_install_acquires_verifies_and_reuses_the_pinned_release(tmp_path: Path) -> None:
    source = _archive(tmp_path / "upstream/registry_test_linux_amd64.tar.gz",
                      [_member("LICENSE", b"license"), _member("registry", BINARY), _member("README.md", b"readme")])
    release = _release(source, BINARY)
    cache = tmp_path / "cache"

    installed = install_distribution(cache, release)
    assert installed.binary == _install_dir(cache) / "registry"
    assert installed.binary.read_bytes() == BINARY
    assert installed.binary.stat().st_mode & 0o777 == 0o755
    assert sorted(path.name for path in _install_dir(cache).iterdir()) == ["install.lock", "registry", source.name]
    assert not (_install_dir(cache) / "LICENSE").exists(), "only the pinned executable is extracted"

    # The upstream source disappears: a tampered binary is restored from the verified cached archive.
    source.unlink()
    installed.binary.write_bytes(b"#!/bin/sh\necho tampered\n")
    assert install_distribution(cache, release).binary.read_bytes() == BINARY

    # Both cached copies tampered and no source: a precise offline prerequisite, never a fallback.
    installed.binary.write_bytes(b"tampered")
    (_install_dir(cache) / source.name).write_bytes(b"tampered archive")
    with pytest.raises(SmokeEnvironmentError, match=r"Cannot download the pinned Distribution archive .*Place that exact archive"):
        install_distribution(cache, release)


@pytest.mark.parametrize("case", ["wrong-bytes", "oversized"])
def test_install_rejects_downloads_that_do_not_match_the_pin(tmp_path: Path, case: str) -> None:
    source = _archive(tmp_path / "upstream/registry_test_linux_amd64.tar.gz", [_member("registry", BINARY)])
    if case == "wrong-bytes":
        release = replace(_release(source, BINARY), archive_sha256=_sha(b"something else"))
        expected = "does not match its pin"
    else:
        release = replace(_release(source, BINARY), archive_size=source.stat().st_size - 1)
        expected = "exceeds its pinned size"
    cache = tmp_path / "cache"
    with pytest.raises(SmokeEnvironmentError, match=expected):
        install_distribution(cache, release)
    assert [path.name for path in _install_dir(cache).iterdir()] == ["install.lock"], "no partial archive or binary"


@pytest.mark.parametrize(("members", "expected"), [
    ([_member("../registry", BINARY)], "exactly one 'registry' member, found 0"),
    ([_member("./registry", BINARY)], "exactly one 'registry' member, found 0"),
    ([_member("registry", kind=tarfile.SYMTYPE, target="/bin/sh")], "not a regular"),
    ([_member("registry", kind=tarfile.LNKTYPE, target="LICENSE"), _member("LICENSE", BINARY)], "not a regular"),
    ([_member("registry", BINARY), _member("registry", BINARY)], "found 2"),
    ([_member("registry", BINARY + b"x")], "not a regular"),
    ([_member("registry", BINARY[:-1] + b"X")], "does not match its pin"),
], ids=["parent-traversal", "dot-prefix", "symlink", "hardlink", "duplicate", "wrong-size", "wrong-content"])
def test_extraction_rejects_unsafe_or_ambiguous_archives(tmp_path: Path, members: list[tuple[tarfile.TarInfo, bytes | None]], expected: str) -> None:
    source = _archive(tmp_path / "upstream/registry_test_linux_amd64.tar.gz", members)
    cache = tmp_path / "cache"
    with pytest.raises(SmokeEnvironmentError, match=expected):
        install_distribution(cache, _release(source, BINARY))
    assert sorted(path.name for path in _install_dir(cache).iterdir()) == ["install.lock", source.name]
    written = [path for path in tmp_path.rglob("*") if path.name == "registry" and path.is_file()]
    assert written == [], f"archive member names must never become output paths: {written}"


# --- Strict garbage-collect output parsing ----------------------------------------------------

A, B, C, D = ("sha256:" + character * 64 for character in "abcd")
GC_OUTPUT = f"""silo/vm
silo/vm: marking manifest {A} 
silo/vm: marking blob {B}
silo/vm: marking blob {A}
manifest eligible for deletion: {{silo/vm {C} [a b]}}

2 blobs marked, 2 blobs and 1 manifests eligible for deletion
blob eligible for deletion: {C}
blob eligible for deletion: {D}
silo/vm: layer link eligible for deletion: {D}
"""


def test_gc_output_parser_extracts_the_mark_and_sweep_sets() -> None:
    report = parse_gc_output(GC_OUTPUT, "", delete_untagged=True, dry_run=True)
    assert report.marked == {A, B}
    assert report.eligible_blobs == {C, D}
    assert report.eligible_manifests == {("silo/vm", C)}
    assert report.removed_layer_links == {("silo/vm", D)}


@pytest.mark.parametrize(("stdout", "delete_untagged", "expected"), [
    (GC_OUTPUT.replace("2 blobs marked", "3 blobs marked"), True, "disagrees"),
    (GC_OUTPUT + "something new happened\n", True, "Unrecognized"),
    (GC_OUTPUT, False, "without --delete-untagged"),
    ("silo/vm\n", False, "no summary"),
    (GC_OUTPUT + "\n0 blobs marked, 0 blobs and 0 manifests eligible for deletion\n", True, "Repeated"),
], ids=["count-mismatch", "unknown-line", "untagged-without-flag", "no-summary", "two-summaries"])
def test_gc_output_parser_rejects_drift(stdout: str, delete_untagged: bool, expected: str) -> None:
    with pytest.raises(SmokeAssertion, match=expected):
        parse_gc_output(stdout, "", delete_untagged=delete_untagged, dry_run=False)


# --- The real pinned Distribution server --------------------------------------------------------


@pytest.fixture
def distribution(config: SmokeConfig, tmp_path: Path, request: pytest.FixtureRequest) -> Iterator[DistributionRegistry]:
    instance = DistributionRegistry(install_distribution(config.cache_dir), config.cache_dir, tmp_path)
    failures = request.session.testsfailed
    try:
        instance.start()
        yield instance
    finally:
        # The call report is logged before fixture teardown, so a new failure is visible here.
        instance.close(retain=request.session.testsfailed > failures or config.keep)


@pytest.mark.linux_only
def test_pinned_release_executable_identity(config: SmokeConfig) -> None:
    installed = install_distribution(config.cache_dir)
    assert installed.release == host_release()
    assert _sha(installed.binary.read_bytes()) == installed.release.binary_sha256
    version = subprocess.run([str(installed.binary), "--version"], capture_output=True, text=True, timeout=30, check=True)
    assert version.stdout.split()[1:] == [DISTRIBUTION_MODULE, DISTRIBUTION_VERSION]


@pytest.mark.linux_only
def test_registry_serves_suite_ca_tls_restarts_on_its_port_and_stops_cleanly(distribution: DistributionRegistry) -> None:
    port = distribution.port
    assert port is not None and distribution.address == f"127.0.0.1:{port}"
    assert f"listening on 127.0.0.1:{port}, tls" in distribution.log_text()
    # The fixture client already verified the chain against the suite CA; a verifier
    # without that CA must refuse it, so trust really comes from the suite CA.
    trusted = ssl.create_default_context(cafile=str(distribution.ca_path))
    with socket.create_connection((distribution.host, port), timeout=5) as raw:
        with trusted.wrap_socket(raw, server_hostname=distribution.host) as tls:
            assert tls.version() in {"TLSv1.2", "TLSv1.3"}
    with pytest.raises(ssl.SSLCertVerificationError):
        with socket.create_connection((distribution.host, port), timeout=5) as raw:
            with ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).wrap_socket(raw, server_hostname=distribution.host):
                pass
    identity = json.loads((distribution.root / "identity.json").read_text())
    assert identity["version"] == DISTRIBUTION_VERSION and identity["address"] == distribution.address

    with pytest.raises(SmokeAssertion, match="Refusing garbage-collect while the registry serves"):
        distribution.garbage_collect(delete_untagged=False)
    with pytest.raises(SmokeAssertion, match="already running"):
        distribution.start()

    digest = distribution.client().push_blob("silo/lifecycle", b"persistent bytes")
    distribution.stop()
    assert not distribution.running
    with socket.socket() as probe:
        assert probe.connect_ex((distribution.host, port)) != 0, "the stopped registry must release its port"
    with pytest.raises(SmokeAssertion, match="not running"):
        distribution.stop()

    distribution.start()
    assert distribution.port == port, "references recorded before a restart must stay valid"
    assert distribution.client().blob("silo/lifecycle", digest) == b"persistent bytes"
    assert digest in distribution.stored_blob_digests()


@pytest.mark.linux_only
def test_close_stops_a_running_registry_and_removes_only_its_root(config: SmokeConfig, tmp_path: Path) -> None:
    sibling = tmp_path / "sibling"
    sibling.write_text("caller owned")
    with running_distribution(config.cache_dir, tmp_path) as registry:
        root, port = registry.root, registry.port
        assert root.parent == tmp_path and root.stat().st_mode & 0o777 == 0o700
    assert not root.exists()
    assert sibling.read_text() == "caller owned"
    with socket.socket() as probe:
        assert port is not None and probe.connect_ex(("127.0.0.1", port)) != 0


def _json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def _descriptor(media_type: str, data: bytes, **extra: object) -> dict[str, object]:
    return {"mediaType": media_type, "digest": digest_of(data), "size": len(data), **extra}


def _bytes(label: str, size: int) -> bytes:
    seed = hashlib.sha256(label.encode()).digest()
    return (seed * (size // len(seed) + 1))[:size]


@dataclass(frozen=True)
class VmArtifact:
    index_digest: str
    index: bytes
    manifests: dict[str, bytes]
    blobs: dict[str, bytes]

    @property
    def digests(self) -> frozenset[str]:
        return frozenset({self.index_digest, *self.manifests, *self.blobs})


def _push_vm_artifact(client: DistributionClient, repository: str, label: str, shared_chunk: bytes) -> VmArtifact:
    """Push a Silo-shaped ADR 0014 graph: blobs, child manifests by digest, then the index by digest."""
    config = _json({"schema": 1, "kind": "vm-artifact", "encoding": "silo-chunks-v1", "label": label})
    layers = [
        ("application/vnd.silo.vm.record.v1+json", _json({"schema": 1, "kind": "silo-chunk-map", "label": label})),
        ("application/vnd.silo.vm.record.v1+json", _json({"schema": 1, "kind": "stream-table", "label": label})),
        ("application/vnd.silo.vm.chunk.v1", _bytes(f"{label}-raw", 8192)),
        ("application/vnd.silo.vm.chunk.v1+zstd", b"\x28\xb5\x2f\xfd" + _bytes(f"{label}-zstd", 512)),
        ("application/vnd.silo.vm.chunk.v1", shared_chunk),
        ("application/vnd.silo.vm.execution.v1", _bytes(f"{label}-execution", 2048)),
        ("application/vnd.silo.vm.device-state.v1", _bytes(f"{label}-devices", 1024)),
    ]
    contents = {digest_of(data): data for data in (config, EMPTY_JSON, *(data for _, data in layers))}
    for digest, data in contents.items():
        assert client.push_blob(repository, data) == digest
    payloads = sorted((_descriptor(media_type, data) for media_type, data in layers), key=lambda item: str(item["digest"]))
    metadata = _json({"schemaVersion": 2, "mediaType": OCI_MANIFEST, "artifactType": "application/vnd.silo.vm.metadata.v1",
                      "config": _descriptor("application/vnd.silo.vm.config.v1+json", config),
                      "layers": [_descriptor(OCI_EMPTY, EMPTY_JSON)]})
    children = [_json({"schemaVersion": 2, "mediaType": OCI_MANIFEST, "artifactType": "application/vnd.silo.vm.payloads.v1",
                       "config": _descriptor(OCI_EMPTY, EMPTY_JSON), "layers": group})
                for group in (payloads[:4], payloads[4:])]
    manifests = {digest_of(body): body for body in (metadata, *children)}
    for digest, body in manifests.items():
        assert client.push_manifest(repository, digest, body, OCI_MANIFEST) == digest
    index = _json({"schemaVersion": 2, "mediaType": OCI_INDEX, "artifactType": "application/vnd.silo.vm.v1", "manifests": [
        _descriptor(OCI_MANIFEST, metadata, artifactType="application/vnd.silo.vm.metadata.v1",
                    platform={"os": "linux", "architecture": images.oci_arch()}),
        *(_descriptor(OCI_MANIFEST, child, artifactType="application/vnd.silo.vm.payloads.v1") for child in children)]})
    index_digest = client.push_manifest(repository, digest_of(index), index, OCI_INDEX)
    return VmArtifact(index_digest, index, manifests, contents)


def _assert_complete(client: DistributionClient, repository: str, artifact: VmArtifact) -> None:
    fetched = client.manifest(repository, artifact.index_digest)
    assert fetched is not None and fetched.body == artifact.index, "index bytes must be preserved exactly"
    assert fetched.media_type == OCI_INDEX
    for digest, body in artifact.manifests.items():
        child = client.manifest(repository, digest)
        assert child is not None and child.body == body
    for digest, data in artifact.blobs.items():
        assert client.blob(repository, digest) == data


@pytest.mark.linux_only
def test_silo_graph_survives_tag_deletion_replacement_and_offline_gc(distribution: DistributionRegistry) -> None:
    client = distribution.client()
    repository = "silo/vm"
    shared = _bytes("shared-chunk", 4096)
    kept = _push_vm_artifact(client, repository, "kept", shared)
    client.push_manifest(repository, "a", kept.index, OCI_INDEX)
    replaced = _push_vm_artifact(client, repository, "replaced", shared)
    client.push_manifest(repository, "b", replaced.index, OCI_INDEX)
    replacement = _push_vm_artifact(client, repository, "replacement", shared)
    client.push_manifest(repository, "b", replacement.index, OCI_INDEX)

    source_layer, source_config = _bytes("source-layer", 3000), _json({"rootfs": {"type": "layers", "diff_ids": []}})
    for data in (source_layer, source_config):
        client.push_blob("silo/source", data)
    source_manifest = _json({"schemaVersion": 2, "mediaType": OCI_MANIFEST,
                             "config": _descriptor("application/vnd.oci.image.config.v1+json", source_config),
                             "layers": [_descriptor("application/vnd.oci.image.layer.v1.tar", source_layer)]})
    source_digest = client.push_manifest("silo/source", "v1", source_manifest, OCI_MANIFEST)
    sentinel = client.push_blob(repository, _bytes("unreferenced-sentinel", 777))

    client.delete_manifest("silo/source", "v1")
    assert client.manifest("silo/source", source_digest) is not None, "deleting a tag keeps the manifest"
    client.delete_manifest("silo/source", source_digest)
    assert client.manifest("silo/source", source_digest) is None
    assert client.tags(repository) == ["a", "b"]
    tagged_b = client.manifest(repository, "b")
    assert tagged_b is not None and tagged_b.digest == replacement.index_digest

    survivors = kept.digests | replacement.digests
    removed = (replaced.digests - survivors) | {sentinel, source_digest, digest_of(source_layer), digest_of(source_config)}
    before = distribution.stored_blob_digests()
    assert survivors | removed <= before

    distribution.stop()
    preview = distribution.garbage_collect(delete_untagged=True, dry_run=True)
    assert distribution.stored_blob_digests() == before, "a dry run removes nothing"
    assert preview.marked == survivors
    assert preview.eligible_blobs == removed
    assert {digest for _, digest in preview.eligible_manifests} == {replaced.index_digest, *replaced.manifests}

    collected = distribution.garbage_collect(delete_untagged=True)
    assert (collected.marked, collected.eligible_blobs, collected.eligible_manifests) == (
        preview.marked, preview.eligible_blobs, preview.eligible_manifests)
    assert distribution.stored_blob_digests() == survivors, "sweep must physically remove exactly the unreachable blobs"

    distribution.start()
    client = distribution.client()
    _assert_complete(client, repository, kept)
    _assert_complete(client, repository, replacement)
    assert client.tags(repository) == ["a", "b"]
    for digest in (replaced.index_digest, *replaced.manifests):
        assert client.manifest(repository, digest) is None
    for digest in (replaced.digests - survivors) | {sentinel}:
        assert not client.blob_exists(repository, digest)
    assert client.manifest("silo/source", source_digest) is None
    for digest in (digest_of(source_layer), digest_of(source_config)):
        assert not client.blob_exists("silo/source", digest)
    assert client.blob(repository, digest_of(shared)) == shared, "a chunk shared with a collected artifact survives"


@pytest.mark.linux_only
def test_registry_rejects_graphs_with_json_only_or_missing_edges(distribution: DistributionRegistry) -> None:
    client = distribution.client()
    repository = "silo/edges"
    client.push_blob(repository, EMPTY_JSON)
    missing = _bytes("never-uploaded", 100)
    manifest = _json({"schemaVersion": 2, "mediaType": OCI_MANIFEST, "artifactType": "application/vnd.silo.vm.payloads.v1",
                      "config": _descriptor(OCI_EMPTY, EMPTY_JSON),
                      "layers": [_descriptor("application/vnd.silo.vm.chunk.v1", missing)]})
    response = client.request("PUT", f"/v2/{repository}/manifests/{digest_of(manifest)}", body=manifest,
                              headers={"Content-Type": OCI_MANIFEST})
    assert response.status == 400 and b"MANIFEST_BLOB_UNKNOWN" in response.body

    index = _json({"schemaVersion": 2, "mediaType": OCI_INDEX, "artifactType": "application/vnd.silo.vm.v1",
                   "manifests": [_descriptor(OCI_MANIFEST, manifest, artifactType="application/vnd.silo.vm.payloads.v1")]})
    response = client.request("PUT", f"/v2/{repository}/manifests/{digest_of(index)}", body=index,
                              headers={"Content-Type": OCI_INDEX})
    assert response.status == 400 and b"MANIFEST_BLOB_UNKNOWN" in response.body
    assert client.manifest(repository, digest_of(index)) is None


@pytest.mark.linux_only
def test_blob_upload_resumes_across_restart_and_rejects_bad_ranges(distribution: DistributionRegistry) -> None:
    client = distribution.client()
    repository = "silo/resume"
    data = _bytes("resumable-blob", 3 * 1024 * 1024 + 17)
    session = client.upload_chunk(client.start_upload(repository), data[:1024 * 1024])
    assert session.offset == 1024 * 1024

    distribution.restart()
    client = distribution.client()
    resumed = client.upload_status(session)
    assert resumed.offset == 1024 * 1024, "the session survives a restart with the instance's stable secret"

    skipped = client.request("PATCH", resumed.location, body=data[2 * 1024 * 1024:], headers={
        "Content-Type": "application/octet-stream", "Content-Length": str(len(data) - 2 * 1024 * 1024),
        "Content-Range": f"{2 * 1024 * 1024}-{len(data) - 1}"})
    assert skipped.status == 416, "a gap in the upload must be rejected, never zero-filled"

    resumed = client.upload_chunk(resumed, data[1024 * 1024:])
    wrong = client.request("PUT", f"{resumed.location}&digest={digest_of(b'not these bytes')}",
                           headers={"Content-Length": "0"})
    assert wrong.status == 400 and b"DIGEST_INVALID" in wrong.body
    assert not client.blob_exists(repository, digest_of(data))

    retry = client.upload_chunk(client.start_upload(repository), data)
    assert client.finish_upload(retry, digest_of(data)) == digest_of(data)
    assert client.blob(repository, digest_of(data)) == data
