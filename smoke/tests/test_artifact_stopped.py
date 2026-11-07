"""Real CLI/Distribution gates for portable raw images and stopped checkpoints.

All producer and consumer Homes are private. Registry oracles inspect actual OCI
edges and bytes; local catalog observations are independent read-only queries.
No hosted registry, SDK, fake server or guest-executing Cargo test is involved.
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
    OCI_INDEX, OCI_MANIFEST, DistributionRegistry, install_distribution,
)
from silo_smoke.workspace import Workspace
# These fixtures intentionally stay owned by their existing modules, not conftest.
from .test_cloud_disk import CONVERTED_PROCESS, Roots, cloud_roots, convert_image
from .test_stopped import stopped_silo

pytestmark = pytest.mark.linux_only

RAW_CHUNK = "application/vnd.silo.vm.chunk.v1"
ZSTD_CHUNK = RAW_CHUNK + "+zstd"
RECORD = "application/vnd.silo.vm.record.v1+json"


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
    return json.loads(silo.run(*args, timeout=300).stdout)


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
    assert top["artifactType"] == "application/vnd.silo.vm.v1"
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
        assert manifest["artifactType"] == f"application/vnd.silo.vm.{expected_type}.v1"
        assert len(manifest["layers"]) <= 4096
        for blob in [manifest["config"], *manifest["layers"]]:
            content = client.blob(repository, blob["digest"])
            assert content is not None and len(content) == blob["size"]
            reachable.add(blob["digest"])
            if blob["mediaType"] == "application/vnd.silo.vm.config.v1+json":
                assert position == 0 and config is None
                config = json.loads(content)
            elif position > 0 and blob["mediaType"] != "application/vnd.oci.empty.v1+json":
                assert blob["digest"] not in payloads, "payload descriptors must be unique across children"
                payloads[blob["digest"]] = blob
    assert config is not None and config["encoding"] == "silo-chunks-v1"
    assert any(item["mediaType"] == RECORD for item in payloads.values())
    assert any(item["mediaType"] in {RAW_CHUNK, ZSTD_CHUNK} for item in payloads.values())
    return Graph(index_digest, config, payloads, frozenset(reachable))


def _push_encodings(source: Silo, registry: DistributionRegistry, reference: str, *, checkpoint: bool) -> tuple[Graph, Graph]:
    repository = "portable/vm"
    graphs = []
    source_id = cloud_disk.inspect(source, reference)["info"]["id"]
    for encoding in ("zstd", "raw"):
        destination = registry.reference(repository, encoding)
        report = _json(source, "image", "push", reference, destination,
                       *(["--raw"] if encoding == "raw" else []),
                       *(["--acknowledge-checkpoint"] if checkpoint else []))
        assert report["repository"] == f"{registry.address}/{repository}"
        assert report["source"] == {"kind": "snapshot" if checkpoint else "image", "id": source_id}
        assert report["purpose"] == ("checkpoint" if checkpoint else "image")
        assert report["captureKind"] == ("stopped-storage" if checkpoint else None)
        assert report["tag"] == encoding
        graph = _graph(registry, repository, report["indexDigest"])
        assert registry.client().manifest(repository, encoding).digest == graph.index
        assert graph.config["purpose"] == report["purpose"]
        graphs.append(graph)
    compressed, raw = graphs
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
        assert _graph(registry, "portable/vm", graph.index) == graph


def _inspect_and_refuse(consumer: Silo, registry: DistributionRegistry, graph: Graph, *, checkpoint: bool) -> None:
    reference = registry.reference("portable/vm", "zstd")
    before = (stopped.catalog(consumer), stopped.inventory(consumer.ws.silo_home), stopped.inventory(consumer.ws.run_root))
    inspected = _json(consumer, "image", "inspect-remote", reference)
    assert inspected["indexDigest"] == graph.index and inspected["rootFamily"] == "opaque-raw"
    assert inspected["purpose"] == ("checkpoint" if checkpoint else "image")
    assert inspected["captureKind"] == ("stopped-storage" if checkpoint else None)
    assert inspected["liveRestore"] is False
    assert before == (stopped.catalog(consumer), stopped.inventory(consumer.ws.silo_home), stopped.inventory(consumer.ws.run_root))
    assert consumer.ls() == [], "inspection must never create or boot imported code"
    wrong = "sha256:" + ("0" if graph.index[7] != "0" else "1") * 64
    for flags in (
        ("--approve-digest", wrong),
        ("--require-signature",),
        (),
    ):
        cloud_disk.refuse_without_effects(consumer, "image", "pull", reference, *flags, "--name", "untrusted")
    cloud_disk.refuse_without_effects(consumer, "create", reference, "--name", "not-a-container", "--network", "none")
    assert consumer.ls() == []


def _pull_both(consumer: Silo, registry: DistributionRegistry, graphs: tuple[Graph, Graph], expected: dict, *, checkpoint: bool) -> str:
    for encoding, graph in zip(("zstd", "raw"), graphs):
        report = _json(consumer, "image", "pull", registry.reference("portable/vm", encoding),
                       "--approve-digest", graph.index, "--name", f"acquired-{encoding}")
        assert report["indexDigest"] == graph.index
        assert report["publisher"] == "unauthenticated", "digest consent is not publisher authentication"
        assert report["source"]["kind"] == ("snapshot" if checkpoint else "image")
        info = report["source"]["info"]
        assert info["id"] == expected["id"] and info["recordDigest"] == expected["recordDigest"]
        assert info["retained"] is True
        if not checkpoint:
            assert info["record"] == expected["record"]
    immutable = "image:" + expected["id"]
    info = cloud_disk.inspect(consumer, immutable)["info"]
    assert set(info["aliases"]) == {"acquired-zstd", "acquired-raw"}
    for encoding in ("zstd", "raw"):
        consumer.run("image", "remove", f"image:acquired-{encoding}")
    assert cloud_disk.inspect(consumer, immutable)["info"]["retained"] is True
    assert cloud_disk.inspect(consumer, immutable)["info"]["aliases"] == []
    return immutable


def _chunk_only(consumer: Silo, stream_ids: list[str]) -> None:
    shutdown.storage_tool(consumer, "prune")
    for stream_id in stream_ids:
        flat = consumer.ws.silo_home / "images/streams/sha256" / stream_id.removeprefix("sha256:")
        assert not flat.exists(), "prune must exercise retained chunk-only reconstruction, not an existing flat copy"
        assert procs.query(consumer.ws.state_db(), f"SELECT flat_state FROM storage_stream WHERE stream_id='{stream_id}'") == [("absent",)]
        assert procs.query(consumer.ws.state_db(), f"SELECT root_digest FROM stream_representation WHERE stream_id='{stream_id}'")


@pytest.mark.parametrize("daemon_mode", [False, pytest.param(True, marks=pytest.mark.daemon)], ids=["local", "daemon"])
def test_raw_artifact_same_identity_trust_and_offline_reconstruction(stopped_silo: Silo, artifact_destination: Silo,
                                                                    artifact_registry: DistributionRegistry,
                                                                    cloud_roots: Roots, daemon_mode: bool) -> None:
    source, consumer, registry = stopped_silo, artifact_destination, artifact_registry
    disk = cloud_disk.sparse_clone(cloud_roots.root, source.ws.root / "input.raw")
    expected_sha = overlay.digest(disk)
    _start_daemon(source, daemon_mode)
    imported = cloud_disk.import_disk(source, disk, root="whole-disk", name="raw-source")
    graphs = _push_encodings(source, registry, "image:raw-source", checkpoint=False)
    _start_daemon(consumer, daemon_mode)
    _inspect_and_refuse(consumer, registry, graphs[0], checkpoint=False)
    immutable = _pull_both(consumer, registry, graphs, imported, checkpoint=False)
    registry.stop()
    _chunk_only(consumer, [imported["record"]["root"]["stream"]["stream"]])
    consumer.create("raw-child", immutable, "--cpus", "1", "--memory", "512mib", "--network", "none", "--vsock")
    root = cloud_disk.root_disk(consumer, "raw-child")
    assert root.stat().st_size == disk.stat().st_size and overlay.digest(root) == expected_sha
    assert stopped.record(consumer, "raw-child")["boot"] == imported["record"]["boot"]
    cloud_disk.assert_pool_objects(consumer, imported["record"]["boot"]["binding"])
    consumer.run("image", "release", immutable)
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
    converted = _json(source, "image", "convert", reference, "--name", "converted-source")
    assert converted["record"]["process"] == CONVERTED_PROCESS
    stream = converted["record"]["root"]["stream"]["stream"]
    flat = source.ws.silo_home / "images/streams/sha256" / stream.removeprefix("sha256:")
    expected_sha, expected_length = overlay.digest(flat), flat.stat().st_size
    graphs = _push_encodings(source, registry, "image:converted-source", checkpoint=False)
    _gc_source(registry, image.manifest_digest, graphs, source)
    source.run("image", "remove", "image:converted-source")
    source.run("image", "release", "image:" + converted["id"])
    shutdown.storage_tool(source, "remove-image", reference)
    shutdown.storage_tool(source, "prune")
    assert not flat.exists(), "the producer's decoded OCI cache must not rescue the consumer"
    _start_daemon(consumer, daemon_mode)
    immutable = _pull_both(consumer, registry, graphs, converted, checkpoint=False)
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


@pytest.mark.parametrize("daemon_mode", [False, pytest.param(True, marks=pytest.mark.daemon)], ids=["local", "daemon"])
def test_stopped_checkpoint_exact_closure_boot_and_config_after_registry_gc(stopped_silo: Silo, artifact_destination: Silo,
                                                                         artifact_registry: DistributionRegistry,
                                                                         overlay_image_bytes: images.OciImage, daemon_mode: bool) -> None:
    source, consumer, registry = stopped_silo, artifact_destination, artifact_registry
    reference = _publish_oci(registry, overlay_image_bytes)
    source.create("checkpoint-source", reference, "--cpus", "1", "--memory", "512mib", "--disk-size", "512mib", "--network", "none", "--vsock")
    stopped.install_managed_fixture(source, "checkpoint-source", custom_boot=True)
    _start_daemon(source, daemon_mode)
    source.start("checkpoint-source")
    source.wait_ready("checkpoint-source")
    source.exec("checkpoint-source", overlay.PROBE, "durable", "/stopped-common", user="root")
    stopped.stop(source, "checkpoint-source", require_clean=False)
    before = stopped.backing(source, "checkpoint-source", "artifact-source")
    expected_config = stopped.configured_semantics(stopped.configuration(source, "checkpoint-source"))
    expected_boot = stopped.record(source, "checkpoint-source")["boot"]
    snapshot = _json(source, "snapshot", "create", "checkpoint-source", "--name", "checkpoint-source")
    rows = procs.query(source.ws.state_db(), f"SELECT CAST(record_bytes AS TEXT) FROM storage_snapshot WHERE id='{snapshot['id']}'")
    assert len(rows) == 1
    record_bytes = rows[0][0]
    record = json.loads(record_bytes)
    destination = registry.reference("portable/refused", "checkpoint")
    registry_before = registry.stored_blob_digests()
    refusal = source.run("image", "push", "image:checkpoint-source", destination, expect=None)
    assert refusal.returncode != 0
    assert registry.stored_blob_digests() == registry_before
    graphs = _push_encodings(source, registry, "image:checkpoint-source", checkpoint=True)
    source.rm("checkpoint-source")
    _gc_source(registry, overlay_image_bytes.manifest_digest, graphs, source)
    source.run("image", "remove", "image:checkpoint-source")
    source.run("snapshot", "remove", "image:" + snapshot["id"])
    shutdown.storage_tool(source, "remove-image", reference)
    shutdown.storage_tool(source, "prune")
    source_flat = source.ws.silo_home / "images/streams/sha256" / record["root"]["stream"]["stream"].removeprefix("sha256:")
    assert not source_flat.exists(), "the producer's snapshot cache must be unavailable before acquisition"
    _start_daemon(consumer, daemon_mode)
    _inspect_and_refuse(consumer, registry, graphs[0], checkpoint=True)
    immutable = _pull_both(consumer, registry, graphs, snapshot, checkpoint=True)
    actual_rows = procs.query(consumer.ws.state_db(), f"SELECT CAST(record_bytes AS TEXT) FROM storage_snapshot WHERE id='{snapshot['id']}'")
    assert actual_rows == [(record_bytes,)], "canonical snapshot configuration/storage record changed in transport"
    registry.stop()
    streams = [record["root"]["stream"]["stream"], *(disk["content"]["stream"] for disk in record["disks"])]
    _chunk_only(consumer, streams)
    # Both public stopped-artifact acquisition routes must preserve the same
    # snapshot semantics, not create an ordinary raw image with lost settings.
    stopped.restore(consumer, immutable, "restored-child")
    consumer.create("created-child", immutable)
    copies = [stopped.backing(consumer, name, "artifact-child-before-boot") for name in ("restored-child", "created-child")]
    for copy in copies:
        stopped.same_content(before, copy)
    stopped.independent(before, *copies)
    for name in ("restored-child", "created-child"):
        assert stopped.record(consumer, name)["boot"] == expected_boot
        assert stopped.configured_semantics(stopped.configuration(consumer, name)) == expected_config
    consumer.run("snapshot", "remove", immutable)
    shutdown.storage_tool(consumer, "prune")
    assert procs.query(consumer.ws.state_db(), f"SELECT id FROM storage_snapshot WHERE id='{snapshot['id']}'") == []
    for name in ("restored-child", "created-child"):
        cloud_disk.assert_pool_objects(consumer, expected_boot["binding"])
        consumer.start(name)
        consumer.wait_ready(name)
        assert consumer.exec(name, "cat", "/stopped-common", user="root").stdout == "committed\n"
        assert consumer.exec(name, "sh", "-eu", "-c", 'printf "%s\\n" "$CAPTURE_UNICODE" "$CAPTURE_SECRET_WARNING"', user="root").stdout == "雪/é\nexact-not-sanitized\n"
        assert cloud_disk.guest_agent_sha256(consumer, name) == expected_boot["binding"]["agent"]
        data = consumer.exec(name, "sh", "-eu", "-c", 'for p in /sys/block/*; do if test "$(cat "$p/serial" 2>/dev/null)" = silo-data-0; then dd if=/dev/${p##*/} bs=1 skip=4096 count=23 2>/dev/null; fi; done', user="root").stdout
        assert data == "managed-before-capture\n"
        stopped.stop(consumer, name, require_clean=False)
        other = "created-child" if name == "restored-child" else "restored-child"
        if name == "restored-child":
            stopped.same_content(copies[1], stopped.backing(consumer, other, "unbooted-sibling"))


def test_failed_pull_reuses_verified_chunks_and_refetches_corrupt_cache(
    stopped_silo: Silo, artifact_destination: Silo,
    artifact_registry: DistributionRegistry, cloud_roots: Roots,
) -> None:
    source, consumer, registry = stopped_silo, artifact_destination, artifact_registry
    disk = cloud_disk.sparse_clone(cloud_roots.root, source.ws.root / "resume.raw")
    imported = cloud_disk.import_disk(source, disk, root="whole-disk", name="resume-source")
    _, graph = _push_encodings(source, registry, "image:resume-source", checkpoint=False)
    chunks = sorted(digest for digest, item in graph.descriptors.items() if item["mediaType"] == RAW_CHUNK)
    assert len(chunks) >= 3, "fixture needs distinct failed, corrupted and reusable chunks"
    corrupt, reusable, missing = chunks[0], chunks[1], chunks[-1]
    client = registry.client()
    missing_bytes = client.blob("portable/vm", missing)
    assert missing_bytes is not None
    client.delete_blob("portable/vm", missing)
    reference = registry.reference("portable/vm", "raw")
    failed = consumer.run("image", "pull", reference, "--approve-digest", graph.index,
                          "--name", "resumed", expect=None, timeout=300)
    assert failed.returncode != 0
    assert procs.query(consumer.ws.state_db(), "SELECT id FROM storage_image") == []
    cache = consumer.ws.silo_home / "images/transport/sha256"
    for digest in (corrupt, reusable):
        assert overlay.digest(cache / digest.removeprefix("sha256:")) == digest.removeprefix("sha256:")
    damaged = cache / corrupt.removeprefix("sha256:")
    damaged.chmod(0o600)
    damaged.write_bytes(b"corrupt completed cache entry")
    assert client.push_blob("portable/vm", missing_bytes) == missing
    before = registry.log_text()
    acquired = _json(consumer, "image", "pull", reference, "--approve-digest", graph.index, "--name", "resumed")
    after = registry.log_text()
    assert acquired["source"]["info"]["id"] == imported["id"]
    # A valid completed chunk requires no network access on retry. A cache
    # pathname or prior completion bit cannot authorize the damaged chunk.
    assert after.count(f"/blobs/{reusable}") == before.count(f"/blobs/{reusable}")
    assert after.count(f"/blobs/{corrupt}") > before.count(f"/blobs/{corrupt}")
    assert overlay.digest(damaged) == corrupt.removeprefix("sha256:")
    registry.stop()
    consumer.create("resumed-child", "image:resumed", "--network", "none")
    root = cloud_disk.root_disk(consumer, "resumed-child")
    assert root.stat().st_size == disk.stat().st_size
    assert overlay.digest(root) == overlay.digest(disk)
