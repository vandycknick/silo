"""Real CLI/Distribution gates for portable raw image artifacts.

All producer and consumer Homes are private. Registry oracles inspect actual OCI
edges and bytes; local catalog observations are independent read-only queries.
No hosted registry, fake server or guest-executing Cargo test is involved.
Snapshot push is not reachable from the CLI, so the only snapshot artifact here
is a real image artifact relabelled as snapshot content to prove refusal.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, replace
import json
from pathlib import Path

import pytest

from silo_smoke import cloud_disk, images, overlay, procs, shutdown, stopped
from silo_smoke.cli import TIMINGS_PROPERTY, Silo, release
from silo_smoke.config import SmokeConfig
from silo_smoke.daemon import Daemon
from silo_smoke.distribution_registry import (
    OCI_INDEX, OCI_MANIFEST, DistributionRegistry, digest_of, install_distribution,
)
from silo_smoke.workspace import Workspace
from silo_smoke.cloud_disk import Roots
from .test_cloud_disk import CONVERTED_PROCESS
from .test_stopped import stopped_silo

pytestmark = pytest.mark.linux_only

RAW_CHUNK = "application/vnd.silo.vm.chunk.v1"
ZSTD_CHUNK = RAW_CHUNK + "+zstd"
RECORD = "application/vnd.silo.vm.record.v2+json"
REPOSITORY = "portable/vm"


@pytest.fixture
def artifact_registry(config: SmokeConfig, request: pytest.FixtureRequest) -> Iterator[DistributionRegistry]:
    registry = DistributionRegistry(install_distribution(config.cache_dir), config.cache_dir)
    failures = request.session.testsfailed
    try:
        registry.start()
        yield registry
    finally:
        registry.close(retain=config.keep or request.session.testsfailed > failures)


@pytest.fixture(scope="session")
def artifact_runtime(config: SmokeConfig, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Share only read-only runtime bytes, never producer or consumer state."""
    runtime = tmp_path_factory.mktemp("artifact-runtime") / "runtime"
    overlay.copy_runtime(config.runtime_dir, runtime)
    # Successful boots must use the pinned closure received from the registry,
    # not these deliberately unusable packaged assets.
    cloud_disk.break_assets(runtime / "assets")
    for path in runtime.rglob("*"):
        path.chmod(path.stat().st_mode & ~0o222)
    runtime.chmod(runtime.stat().st_mode & ~0o222)
    return runtime


@pytest.fixture
def artifact_destination(config: SmokeConfig, artifact_registry: DistributionRegistry,
                         artifact_runtime: Path, request: pytest.FixtureRequest) -> Iterator[Silo]:
    workspace = Workspace(replace(config, runtime_dir=artifact_runtime), artifact_registry.ca_path)
    failures = request.session.testsfailed
    try:
        workspace.record("artifact-runtime", f"read-only broken-assets fixture: {artifact_runtime}\n")
        consumer = Silo(workspace)
        consumer.run("image", "list")
        assert consumer.ls() == []
        assert not list((workspace.silo_home / "images/streams/sha256").glob("*"))
        yield consumer
    finally:
        release(workspace, failed=request.session.testsfailed > failures,
                publish=lambda value: request.node.user_properties.append((TIMINGS_PROPERTY + "-artifact-destination", value)))


def _start_daemon(silo: Silo, enabled: bool) -> None:
    if enabled:
        daemon = Daemon(silo.ws)
        daemon.start()
        daemon.wait_core()
        assert daemon.control_sock.is_socket()


def _json(silo: Silo, *args: str) -> dict:
    return silo.json(*args, timeout=300)


def _publish_oci(registry: DistributionRegistry, image: images.OciImage) -> str:
    client = registry.client()
    repository = "source/container"
    assert client.push_blob(repository, image.config) == image.config_digest
    assert client.push_blob(repository, image.layer) == image.layer_digest
    assert client.push_manifest(repository, "original", image.manifest, OCI_MANIFEST) == image.manifest_digest
    return registry.reference(repository, "original")


@dataclass(frozen=True)
class Graph:
    index: str
    config: dict
    descriptors: dict[str, dict]
    reachable: frozenset[str]


def _graph(registry: DistributionRegistry, repository: str, index_digest: str) -> Graph:
    """Authenticate every real OCI graph edge, including custom payload bytes."""
    client = registry.client()
    index = client.manifest(repository, index_digest)
    assert index is not None and index.media_type == OCI_INDEX
    top = json.loads(index.body)
    assert top["artifactType"] == "application/vnd.silo.vm.v2"
    assert 2 <= len(top["manifests"]) <= 4097
    reachable = {index_digest}
    payloads: dict[str, dict] = {}
    config: dict | None = None
    for position, descriptor in enumerate(top["manifests"]):
        child = client.manifest(repository, descriptor["digest"])
        assert child is not None and child.media_type == OCI_MANIFEST
        assert len(child.body) == descriptor["size"] <= 4 * 1024**2
        reachable.add(child.digest)
        manifest = json.loads(child.body)
        expected_type = "metadata" if position == 0 else "payloads"
        assert manifest["artifactType"] == f"application/vnd.silo.vm.{expected_type}.v2"
        assert len(manifest["layers"]) <= 4096
        for blob in [manifest["config"], *manifest["layers"]]:
            content = client.blob(repository, blob["digest"])
            assert content is not None and len(content) == blob["size"]
            reachable.add(blob["digest"])
            if blob["mediaType"] == "application/vnd.silo.vm.config.v2+json":
                assert position == 0 and config is None
                config = json.loads(content)
            elif position > 0 and blob["mediaType"] != "application/vnd.oci.empty.v1+json":
                assert blob["digest"] not in payloads, "payload descriptors must be unique across children"
                payloads[blob["digest"]] = blob
    assert config is not None and config["encoding"] == "silo-chunks-v2"
    assert set(config) == {"schema", "kind", "encoding", "content", "root", "guestPlatform", "bootAbi", "memory",
                           "streams", "objects"}, sorted(config)
    assert any(item["mediaType"] == RECORD for item in payloads.values())
    assert any(item["mediaType"] in {RAW_CHUNK, ZSTD_CHUNK} for item in payloads.values())
    return Graph(index_digest, config, payloads, frozenset(reachable))


def _push(source: Silo, registry: DistributionRegistry, reference: str, encoding: str) -> Graph:
    source_id = cloud_disk.inspect(source, reference)["info"]["id"]
    report = _json(source, "image", "push", reference, registry.reference(REPOSITORY, encoding),
                   *(["--raw"] if encoding == "raw" else []))
    assert report["repository"] == f"{registry.address}/{REPOSITORY}"
    assert report["content"] == {"kind": "image", "id": source_id}
    assert report["tag"] == encoding
    graph = _graph(registry, REPOSITORY, report["indexDigest"])
    assert registry.client().manifest(REPOSITORY, encoding).digest == graph.index
    assert graph.config["content"]["kind"] == "image" and graph.config["content"]["id"] == source_id
    return graph


def _push_encodings(source: Silo, registry: DistributionRegistry, reference: str) -> tuple[Graph, Graph]:
    compressed, raw = (_push(source, registry, reference, encoding) for encoding in ("zstd", "raw"))
    assert compressed.index != raw.index, "compressible ext4/boot bytes must exercise distinct encodings"
    assert compressed.config["content"] == raw.config["content"], "encoding must not salt canonical identity"
    assert any(item["mediaType"] == ZSTD_CHUNK for item in compressed.descriptors.values())
    assert not any(item["mediaType"] == ZSTD_CHUNK for item in raw.descriptors.values())
    return compressed, raw


def _gc_source(registry: DistributionRegistry, source_digest: str, graphs: tuple[Graph, Graph], silo: Silo) -> None:
    client = registry.client()
    client.delete_manifest("source/container", source_digest)
    assert client.manifest("source/container", "original") is None
    assert client.manifest("source/container", source_digest) is None
    # A real unreferenced blob proves physical sweep actually took place.
    garbage = client.push_blob("source/container", b"phase18-unreachable-source-garbage")
    registry.stop()
    report = registry.garbage_collect(delete_untagged=True)
    silo.ws.record("artifact-registry-gc", report.stdout + "\n" + report.stderr)
    stored = registry.stored_blob_digests()
    assert garbage in report.eligible_blobs and garbage not in stored
    if all(source_digest not in graph.reachable for graph in graphs):
        assert source_digest not in stored
    for graph in graphs:
        assert graph.reachable <= report.marked
        assert graph.reachable <= stored
    registry.start()
    assert client.manifest("source/container", "original") is None
    assert client.manifest("source/container", source_digest) is None
    for graph in graphs:
        assert _graph(registry, REPOSITORY, graph.index) == graph


def _inspect(consumer: Silo, registry: DistributionRegistry, graph: Graph) -> None:
    reference = registry.reference(REPOSITORY, "zstd")
    before = (stopped.catalog(consumer), stopped.inventory(consumer.ws.silo_home), stopped.inventory(consumer.ws.run_root))
    inspected = _json(consumer, "image", "inspect-remote", reference)
    assert inspected["indexDigest"] == graph.index and inspected["root"] == "opaque-raw"
    assert inspected["content"] == {"kind": "image", "id": graph.config["content"]["id"]}
    assert inspected["memory"] is False
    assert before == (stopped.catalog(consumer), stopped.inventory(consumer.ws.silo_home), stopped.inventory(consumer.ws.run_root))
    assert consumer.ls() == [], "inspection must never create or boot imported code"


def _pull_both(consumer: Silo, registry: DistributionRegistry, graphs: tuple[Graph, Graph], expected: dict) -> str:
    references = []
    for encoding, graph in zip(("zstd", "raw"), graphs):
        reference = registry.reference(REPOSITORY, encoding)
        pulled = _json(consumer, "image", "pull", reference)
        assert pulled["kind"] == "stored", pulled
        info = pulled["info"]
        assert info["id"] == expected["id"] and info["recordDigest"] == expected["recordDigest"]
        assert info["record"] == expected["record"]
        assert reference in info["names"], info
        references.append(reference)
    # Each pulled reference names the one record both encodings carry.
    assert set(cloud_disk.inspect(consumer, expected["id"])["info"]["names"]) == set(references)
    return str(expected["id"])


def _chunk_only(consumer: Silo, stream_ids: list[str]) -> None:
    shutdown.storage_tool(consumer, "prune")
    for stream_id in stream_ids:
        flat = consumer.ws.silo_home / "images/streams/sha256" / stream_id.removeprefix("sha256:")
        assert not flat.exists(), "prune must exercise retained chunk-only reconstruction, not an existing flat copy"
        assert procs.query(consumer.ws.state_db(), f"SELECT flat_state FROM storage_stream WHERE stream_id='{stream_id}'") == [("absent",)]
        assert procs.query(consumer.ws.state_db(), f"SELECT root_digest FROM stream_representation WHERE stream_id='{stream_id}'")


def _payload_blobs(graph: Graph) -> frozenset[str]:
    """Bulk payloads that verifying the metadata graph never needs: chunks and the content record."""
    chunks = {digest for digest, item in graph.descriptors.items() if item["mediaType"] in {RAW_CHUNK, ZSTD_CHUNK}}
    assert chunks
    return frozenset({*chunks, graph.config["content"]["record"]["digest"]})


def _fetched(log: str, digests: frozenset[str]) -> list[str]:
    return sorted(digest for digest in digests if f"/blobs/{digest}" in log)


def _as_snapshot_artifact(registry: DistributionRegistry, graph: Graph, tag: str) -> str:
    """Relabel a real image artifact as snapshot content under a new tag.

    Only the config and the metadata manifest change. Every payload manifest
    and blob is the image's own, so the graph verifies and only the content
    kind differs; the record and chunks are never consistent with that kind.
    """
    client = registry.client()
    fetched_index = client.manifest(REPOSITORY, graph.index)
    assert fetched_index is not None
    index = json.loads(fetched_index.body)
    fetched_metadata = client.manifest(REPOSITORY, index["manifests"][0]["digest"])
    assert fetched_metadata is not None
    metadata = json.loads(fetched_metadata.body)
    config = {**graph.config, "content": {**graph.config["content"], "kind": "snapshot"}}
    config_bytes = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
    metadata["config"] = {**metadata["config"], "digest": client.push_blob(REPOSITORY, config_bytes),
                          "size": len(config_bytes)}
    metadata_bytes = json.dumps(metadata, separators=(",", ":")).encode()
    metadata_digest = client.push_manifest(REPOSITORY, digest_of(metadata_bytes), metadata_bytes, OCI_MANIFEST)
    index["manifests"][0] = {**index["manifests"][0], "digest": metadata_digest, "size": len(metadata_bytes)}
    index_bytes = json.dumps(index, separators=(",", ":")).encode()
    client.push_manifest(REPOSITORY, tag, index_bytes, OCI_INDEX)
    return registry.reference(REPOSITORY, tag)


@pytest.mark.parametrize("daemon_mode", [False, pytest.param(True, marks=pytest.mark.daemon)], ids=["local", "daemon"])
def test_raw_artifact_same_identity_and_offline_reconstruction(stopped_silo: Silo, artifact_destination: Silo,
                                                               artifact_registry: DistributionRegistry,
                                                               cloud_roots: Roots, daemon_mode: bool) -> None:
    source, consumer, registry = stopped_silo, artifact_destination, artifact_registry
    disk = cloud_disk.sparse_clone(cloud_roots.root, source.ws.root / "input.raw")
    expected_sha = overlay.digest(disk)
    _start_daemon(source, daemon_mode)
    imported = cloud_disk.import_disk(source, disk, root="whole-disk", name="raw-source")
    graphs = _push_encodings(source, registry, "raw-source")
    _start_daemon(consumer, daemon_mode)
    _inspect(consumer, registry, graphs[0])
    immutable = _pull_both(consumer, registry, graphs, imported)
    registry.stop()
    _chunk_only(consumer, [imported["record"]["root"]["stream"]["stream"]])
    consumer.create("raw-child", immutable, "--cpus", "1", "--memory", "512mib", "--network", "none", "--vsock")
    root = cloud_disk.root_disk(consumer, "raw-child")
    assert root.stat().st_size == disk.stat().st_size and overlay.digest(root) == expected_sha
    assert stopped.record(consumer, "raw-child")["boot"] == imported["record"]["boot"]
    cloud_disk.assert_pool_objects(consumer, imported["record"]["boot"]["binding"])
    # rm ID removes the record and both pulled names; the machine keeps its bytes.
    consumer.run("image", "rm", immutable)
    shutdown.storage_tool(consumer, "prune")
    assert procs.query(consumer.ws.state_db(), f"SELECT id FROM storage_image WHERE id='{imported['id']}'") == []
    cloud_disk.boot(consumer, "raw-child")
    cloud_disk.assert_root(cloud_disk.guest_probe(consumer, "raw-child"), partition=None)
    assert cloud_disk.guest_agent_sha256(consumer, "raw-child") == imported["record"]["boot"]["binding"]["agent"]
    stopped.stop(consumer, "raw-child")
    assert overlay.digest(disk) == expected_sha, "publication must never mutate imported source bytes"


@pytest.mark.parametrize("daemon_mode", [False, pytest.param(True, marks=pytest.mark.daemon)], ids=["local", "daemon"])
def test_converted_artifact_survives_source_oci_deletion_and_registry_gc(stopped_silo: Silo, artifact_destination: Silo,
                                                                      artifact_registry: DistributionRegistry,
                                                                      convert_image: tuple[str, images.OciImage], daemon_mode: bool) -> None:
    source, consumer, registry = stopped_silo, artifact_destination, artifact_registry
    _, image = convert_image
    reference = _publish_oci(registry, image)
    _start_daemon(source, daemon_mode)
    converted = _json(source, "image", "convert", reference, "--disk-format", "raw", "--name", "converted-source")
    assert converted["record"]["process"] == CONVERTED_PROCESS
    stream = converted["record"]["root"]["stream"]["stream"]
    converted_root = source.ws.silo_home / "images/streams/sha256" / stream.removeprefix("sha256:")
    expected_sha, expected_length = overlay.digest(converted_root), converted_root.stat().st_size
    graphs = _push_encodings(source, registry, "converted-source")
    _gc_source(registry, image.manifest_digest, graphs, source)
    source.run("image", "rm", converted["id"])
    shutdown.storage_tool(source, "remove-image", reference)
    shutdown.storage_tool(source, "prune")
    assert not converted_root.exists(), "the producer's decoded OCI cache must not rescue the consumer"
    _start_daemon(consumer, daemon_mode)
    immutable = _pull_both(consumer, registry, graphs, converted)
    registry.stop()
    _chunk_only(consumer, [stream])
    consumer.create("converted-child", immutable, "--cpus", "1", "--memory", "512mib", "--network", "none", "--vsock")
    root = cloud_disk.root_disk(consumer, "converted-child")
    assert (root.stat().st_size, overlay.digest(root)) == (expected_length, expected_sha)
    assert stopped.configuration(consumer, "converted-child")["process"] == CONVERTED_PROCESS
    assert stopped.record(consumer, "converted-child")["boot"] == converted["record"]["boot"]
    cloud_disk.assert_pool_objects(consumer, converted["record"]["boot"]["binding"])
    cloud_disk.boot(consumer, "converted-child")
    cloud_disk.assert_root(cloud_disk.guest_probe(consumer, "converted-child"), partition=None)
    assert cloud_disk.guest_agent_sha256(consumer, "converted-child") == converted["record"]["boot"]["binding"]["agent"]
    stopped.stop(consumer, "converted-child")


def test_image_pull_and_create_refuse_snapshot_artifact_before_payload_fetch(
    stopped_silo: Silo, artifact_destination: Silo,
    artifact_registry: DistributionRegistry, cloud_roots: Roots,
) -> None:
    source, consumer, registry = stopped_silo, artifact_destination, artifact_registry
    disk = cloud_disk.sparse_clone(cloud_roots.root, source.ws.root / "relabel.raw")
    cloud_disk.import_disk(source, disk, root="whole-disk", name="relabel-source")
    graph = _push(source, registry, "relabel-source", "raw")
    snapshot_reference = _as_snapshot_artifact(registry, graph, "as-snapshot")
    payloads = _payload_blobs(graph)
    inspected = _json(consumer, "image", "inspect-remote", snapshot_reference)
    assert inspected["content"] == {"kind": "snapshot", "id": graph.config["content"]["id"]}, inspected

    for args in (("image", "pull", snapshot_reference),
                 ("create", snapshot_reference, "--name", "never-created", "--network", "none")):
        before = registry.log_text()
        refused = cloud_disk.refuse_before_publication(consumer, *args)
        log = registry.log_text()[len(before):]
        assert "silo restore" in refused.stderr, refused.stderr
        assert "/manifests/as-snapshot" in log, "the refusal must come from the registry artifact"
        assert _fetched(log, payloads) == [], "a snapshot artifact was refused only after payload fetch"
    assert consumer.ls() == []

    # Positive control: the same oracle observes payload fetches of the real image.
    before = registry.log_text()
    pulled = _json(consumer, "image", "pull", registry.reference(REPOSITORY, "raw"))
    assert pulled["kind"] == "stored" and pulled["info"]["id"] == graph.config["content"]["id"]
    assert _fetched(registry.log_text()[len(before):], payloads) == sorted(payloads)


def test_restore_refuses_image_artifact_before_payload_fetch(
    stopped_silo: Silo, artifact_destination: Silo,
    artifact_registry: DistributionRegistry, cloud_roots: Roots,
) -> None:
    source, consumer, registry = stopped_silo, artifact_destination, artifact_registry
    disk = cloud_disk.sparse_clone(cloud_roots.root, source.ws.root / "restore-refused.raw")
    cloud_disk.import_disk(source, disk, root="whole-disk", name="restore-refused")
    graph = _push(source, registry, "restore-refused", "raw")
    reference = registry.reference(REPOSITORY, "raw")
    before = registry.log_text()
    refused = cloud_disk.refuse_before_publication(consumer, "restore", reference, "--name", "never-restored")
    log = registry.log_text()[len(before):]
    assert f"silo create {reference}" in refused.stderr, refused.stderr
    assert "/manifests/raw" in log, "the refusal must come from the registry artifact"
    assert _fetched(log, _payload_blobs(graph)) == [], "an image artifact was refused only after payload fetch"
    assert consumer.ls() == []


def test_failed_pull_reuses_verified_chunks_and_refetches_corrupt_cache(
    stopped_silo: Silo, artifact_destination: Silo,
    artifact_registry: DistributionRegistry, cloud_roots: Roots,
) -> None:
    source, consumer, registry = stopped_silo, artifact_destination, artifact_registry
    disk = cloud_disk.sparse_clone(cloud_roots.root, source.ws.root / "resume.raw")
    imported = cloud_disk.import_disk(source, disk, root="whole-disk", name="resume-source")
    graph = _push(source, registry, "resume-source", "raw")
    chunks = sorted(digest for digest, item in graph.descriptors.items() if item["mediaType"] == RAW_CHUNK)
    assert len(chunks) >= 3, "fixture needs distinct failed, corrupted and reusable chunks"
    corrupt, reusable, missing = chunks[0], chunks[1], chunks[-1]
    client = registry.client()
    missing_bytes = client.blob(REPOSITORY, missing)
    assert missing_bytes is not None
    client.delete_blob(REPOSITORY, missing)
    reference = registry.reference(REPOSITORY, "raw")
    failed = consumer.run("image", "pull", reference, expect=None, timeout=300)
    assert failed.returncode != 0
    assert procs.query(consumer.ws.state_db(), "SELECT id FROM storage_image") == []
    cache = consumer.ws.silo_home / "images/transport/sha256"
    for digest in (corrupt, reusable):
        assert overlay.digest(cache / digest.removeprefix("sha256:")) == digest.removeprefix("sha256:")
    damaged = cache / corrupt.removeprefix("sha256:")
    damaged.chmod(0o600)
    damaged.write_bytes(b"corrupt completed cache entry")
    assert client.push_blob(REPOSITORY, missing_bytes) == missing
    before = registry.log_text()
    acquired = _json(consumer, "image", "pull", reference)
    after = registry.log_text()
    assert acquired["info"]["id"] == imported["id"]
    # A valid completed chunk requires no network access on retry. A cache
    # pathname or prior completion bit cannot authorize the damaged chunk.
    assert after.count(f"/blobs/{reusable}") == before.count(f"/blobs/{reusable}")
    assert after.count(f"/blobs/{corrupt}") > before.count(f"/blobs/{corrupt}")
    assert overlay.digest(damaged) == corrupt.removeprefix("sha256:")
    registry.stop()
    consumer.create("resumed-child", reference, "--network", "none")
    root = cloud_disk.root_disk(consumer, "resumed-child")
    assert root.stat().st_size == disk.stat().st_size
    assert overlay.digest(root) == overlay.digest(disk)
