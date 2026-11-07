"""Phase 18: a real live execution checkpoint crosses a real registry exactly.

    source home (restore candidate)          controlled Distribution 3.1.2
    ---------------------------------        -----------------------------
    guest witness -> snapshot --live  --push (acknowledged)-->  index/children/blobs
                                                                   | offline GC, tag kept
    fresh destination home  <--pull --approve-digest (index)------+
       source stopped, removed, pruned, home quarantined          | manifest deleted,
       registry graph deleted, collected, server stopped          | offline GC sweeps it
       runtime boot assets replaced with garbage
    restore -> exact RAM/disk cut continues, captured boot bytes, private disk
    retention released -> imported closure collected after the child is reaped

Ownership: `silo` (conftest) is the source home, `destination` below is a
second fresh home and `distribution` a private registry root; each is created
and released by exactly one fixture. Admission is compiled into Main's isolated
capture+restore candidate (SILO_SMOKE_BIN_DIR/SILO_SMOKE_RUNTIME_DIR); no
capability or trust is granted here. Digest approval is integrity consent,
never publisher authentication.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
import json
from pathlib import Path
import platform
import ssl
from urllib.error import HTTPError
from urllib.request import urlopen

import pytest

from silo_smoke import capture, incremental, overlay, procs, restore, shutdown, stopped
from silo_smoke.cli import TIMINGS_PROPERTY, Result, Silo, release
from silo_smoke.config import SmokeConfig
from silo_smoke.distribution_registry import (
    OCI_EMPTY, OCI_INDEX, OCI_MANIFEST, DistributionClient, DistributionRegistry, digest_of, install_distribution,
)
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.restore import restore_image  # noqa: F401, pytest fixture
from silo_smoke.workspace import Workspace

# Admission is compiled into Main's isolated candidate, not production policy.
pytestmark = [pytest.mark.linux_only, pytest.mark.slow]

REPOSITORY = "silo-smoke/live-checkpoint"
SOURCE = "artifact-source"
ARTIFACT_TYPE = "application/vnd.silo.vm.v1"
METADATA_TYPE = "application/vnd.silo.vm.metadata.v1"
PAYLOAD_TYPE = "application/vnd.silo.vm.payloads.v1"
CONFIG_MEDIA = "application/vnd.silo.vm.config.v1+json"
RECORD_MEDIA = "application/vnd.silo.vm.record.v1+json"
RAW_CHUNK = "application/vnd.silo.vm.chunk.v1"
ZSTD_CHUNK = "application/vnd.silo.vm.chunk.v1+zstd"
EXECUTION_MEDIA = "application/vnd.silo.vm.execution.v1"
DEVICE_MEDIA = "application/vnd.silo.vm.device-state.v1"
PAYLOAD_MEDIA = {RECORD_MEDIA, RAW_CHUNK, ZSTD_CHUNK, EXECUTION_MEDIA, DEVICE_MEDIA}
CHUNK_BYTES = 8 * 1024 * 1024
TRANSFER = 600
BOOT_ASSETS = {"kernel": "kernel-default", "baseInitramfs": "initramfs", "agent": "agent"}


@pytest.fixture
def artifact_processes(silo: Silo) -> Iterator[list[shutdown.Process]]:
    """Adopt only this test's monitor/worker generations, in both homes, and reap them."""
    with shutdown.subreaper():
        processes: list[shutdown.Process] = []
        try:
            yield processes
        finally:
            with shutdown.owned_processes(*processes):
                pass


@pytest.fixture
def distribution(config: SmokeConfig, tmp_path: Path, request: pytest.FixtureRequest) -> Iterator[DistributionRegistry]:
    instance = DistributionRegistry(install_distribution(config.cache_dir), config.cache_dir, tmp_path)
    failures = request.session.testsfailed
    try:
        instance.start()
        yield instance
    finally:
        instance.close(retain=request.session.testsfailed > failures or config.keep)


@pytest.fixture
def destination(config: SmokeConfig, registry: LoopbackRegistry, request: pytest.FixtureRequest) -> Iterator[Silo]:
    """A fresh home with a private runtime copy; it shares no catalog or pool with the source."""
    instance = Workspace(config, registry.ca_path)
    failures = request.session.testsfailed
    try:
        runtime = instance.root / "destination-runtime"
        overlay.copy_runtime(config.runtime_dir, runtime)
        instance.config = replace(config, runtime_dir=runtime)
        yield Silo(instance)
    finally:
        release(instance, failed=request.session.testsfailed > failures,
                publish=lambda summary: request.node.user_properties.append(
                    (TIMINGS_PROPERTY + "-destination", summary)))


def own(silo: Silo, name: str, processes: list[shutdown.Process]) -> None:
    holders, _ = shutdown.holder(silo, name)
    processes.extend(shutdown.Process(entry["pid"]) for entry in holders["holders"])


def stop_owned(silo: Silo, name: str, processes: list[shutdown.Process]) -> None:
    stopped.stop(silo, name, require_clean=False)
    for process in processes[:]:
        if process.terminal():
            try:
                process.reap()
            except ChildProcessError:
                # Workers normally belong to, and are reaped by, their monitor.
                pass
            finally:
                process.close()
                processes.remove(process)


def mark(silo: Silo, name: str, value: str) -> None:
    silo.exec(name, "sh", "-eu", "-c", 'printf "%s\\n" "$1" >/restore-private; sync',
              "restore-private", value, user="root")


def marker(silo: Silo, name: str) -> str:
    return silo.exec(name, "cat", "/restore-private").stdout.strip()


def rows(silo: Silo, statement: str) -> list[tuple[str, ...]]:
    return procs.query(silo.ws.state_db(), statement)


def count(silo: Silo, statement: str) -> int:
    return int(rows(silo, statement)[0][0])


def guest_architecture() -> str:
    return {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[platform.machine().lower()]


def pools(silo: Silo) -> dict[str, list[str]]:
    """Every published immutable byte in a home: objects and streams pools."""
    result = {}
    for kind in ("objects", "streams"):
        directory = silo.ws.silo_home / "images" / kind / "sha256"
        result[kind] = sorted(path.name for path in directory.iterdir()) if directory.is_dir() else []
    return result


def pool_path(silo: Silo, kind: str, digest: str) -> Path:
    return silo.ws.silo_home / "images" / kind / "sha256" / digest.removeprefix("sha256:")


def blob_requests(distribution: DistributionRegistry) -> int:
    return distribution.log_text().count(f"/v2/{REPOSITORY}/blobs/")


@dataclass(frozen=True)
class PublishedGraph:
    """Independent reading of the registry bytes, never Silo's own decoder."""

    index_digest: str
    digests: frozenset[str]
    layers: dict[str, str]
    config: dict
    record: bytes
    evidence: bytes
    provenance_digest: str
    streams: frozenset[str]
    direct: dict[str, str]
    chunk_media: frozenset[str]


def published_graph(client: DistributionClient, reference: str) -> PublishedGraph:
    index = client.manifest(REPOSITORY, reference)
    assert index is not None and index.media_type == OCI_INDEX, index
    top = json.loads(index.body)
    assert top["mediaType"] == OCI_INDEX and top["artifactType"] == ARTIFACT_TYPE, top
    children = top["manifests"]
    assert len(children) >= 2 and all(child["mediaType"] == OCI_MANIFEST for child in children), children
    assert children[0]["artifactType"] == METADATA_TYPE
    assert children[0]["platform"] == {"os": "linux", "architecture": guest_architecture()}, children[0]
    assert all(child["artifactType"] == PAYLOAD_TYPE and "platform" not in child for child in children[1:])
    digests = {index.digest}
    manifests = []
    for child in children:
        fetched = client.manifest(REPOSITORY, child["digest"])
        assert fetched is not None and len(fetched.body) == child["size"], child
        digests.add(fetched.digest)
        manifests.append(json.loads(fetched.body))
    metadata, payloads = manifests[0], manifests[1:]
    assert metadata["artifactType"] == METADATA_TYPE and metadata["config"]["mediaType"] == CONFIG_MEDIA
    assert [layer["mediaType"] for layer in metadata["layers"]] == [OCI_EMPTY]
    digests |= {metadata["config"]["digest"], metadata["layers"][0]["digest"]}
    layers: dict[str, str] = {}
    sizes: dict[str, int] = {}
    for manifest in payloads:
        assert manifest["artifactType"] == PAYLOAD_TYPE and manifest["config"]["mediaType"] == OCI_EMPTY
        digests.add(manifest["config"]["digest"])
        for layer in manifest["layers"]:
            assert layer["mediaType"] in PAYLOAD_MEDIA, layer
            assert layer["digest"] not in layers, "payload descriptor listed twice"
            layers[layer["digest"]] = layer["mediaType"]
            sizes[layer["digest"]] = layer["size"]
            assert client.blob_exists(REPOSITORY, layer["digest"]), layer
    digests |= set(layers)
    config_bytes = client.blob(REPOSITORY, metadata["config"]["digest"])
    assert config_bytes is not None and len(config_bytes) == metadata["config"]["size"]
    config = json.loads(config_bytes)
    referenced: set[str] = set()

    def payload(digest: str, media: str, size: int | None = None) -> bytes:
        assert layers.get(digest) == media, (digest, media, layers.get(digest))
        assert size is None or sizes[digest] == size, (digest, size, sizes[digest])
        referenced.add(digest)
        data = client.blob(REPOSITORY, digest)
        assert data is not None and len(data) == sizes[digest]
        return data

    def record(reference: dict) -> dict:
        return json.loads(payload(reference["digest"], RECORD_MEDIA, reference["size"]))

    def pages(root: dict, kind: str) -> list[dict]:
        assert root["schema"] == 1 and root["kind"] == kind, root
        entries = []
        for page_reference in root["pages"]:
            page = record(page_reference)
            assert page["kind"] == kind + "-page" and page["firstEntry"] == len(entries), page
            entries.extend(page["entries"])
        assert len(entries) == root["entries"]
        return entries

    record_bytes = payload(config["content"]["record"]["digest"], RECORD_MEDIA, config["content"]["record"]["size"])
    streams: set[str] = set()
    chunk_media: set[str] = set()
    for binding in pages(record(config["streams"]), "stream-table"):
        streams.add(binding["stream"])
        transfer = record(binding["transport"])
        assert transfer["stream"] == binding["stream"] and transfer["length"] == binding["length"], transfer
        assert transfer["chunkSize"] == CHUNK_BYTES
        decoded = 0
        for page_digest in transfer["pages"]:
            for entry in json.loads(payload(page_digest, RECORD_MEDIA))["entries"]:
                assert 0 < entry["length"] <= CHUNK_BYTES, entry
                decoded += entry["length"]
                if entry["kind"] == "data":
                    encoded = entry["encoded"]
                    assert encoded["mediaType"] in {RAW_CHUNK, ZSTD_CHUNK}
                    assert layers.get(encoded["digest"]) == encoded["mediaType"], encoded
                    assert sizes[encoded["digest"]] == encoded["size"]
                    referenced.add(encoded["digest"])
                    chunk_media.add(encoded["mediaType"])
                else:
                    assert entry["kind"] == "zero", entry
        assert decoded == binding["length"], "transfer pages do not cover the whole stream"
    direct: dict[str, str] = {}
    for binding in pages(record(config["objects"]), "object-table"):
        if binding["kind"] == "direct":
            assert binding["payload"]["digest"] == binding["object"]
            assert binding["payload"]["size"] == binding["size"]
            assert layers.get(binding["object"]) == binding["payload"]["mediaType"], binding
            referenced.add(binding["object"])
            direct[binding["object"]] = binding["payload"]["mediaType"]
        else:
            assert binding["kind"] == "stream" and binding["stream"] in streams, binding
    provenance = record(config["captureProvenance"])
    assert provenance["schema"] == 1 and provenance["kind"] == "portable-capture-provenance", provenance
    assert provenance["snapshot"] == config["content"]["id"]
    evidence = payload(provenance["evidence"]["digest"], RECORD_MEDIA, provenance["evidence"]["size"])
    # No surplus payload: every descriptor is reachable from the config's typed
    # tables, not merely listed in a manifest.
    assert set(layers) == referenced, sorted(set(layers) ^ referenced)
    return PublishedGraph(index.digest, frozenset(digests), layers, config, record_bytes, evidence,
                          config["captureProvenance"]["digest"], frozenset(streams), direct, frozenset(chunk_media))


def source_closure(silo: Silo, saved: restore.Checkpoint) -> tuple[bytes, bytes, dict]:
    (record_hex,) = rows(silo, f"SELECT hex(record_bytes) FROM storage_snapshot WHERE id='{saved.snapshot}'")[0]
    provenance = rows(silo, f"SELECT hex(evidence_bytes) FROM snapshot_capture_provenance WHERE snapshot_id='{saved.snapshot}'")
    assert len(provenance) == 1
    record_bytes = bytes.fromhex(record_hex)
    return record_bytes, bytes.fromhex(provenance[0][0]), json.loads(record_bytes)


def verify_graph(graph: PublishedGraph, saved: restore.Checkpoint, record_bytes: bytes, evidence: bytes,
                 record: dict, *, profile: str, encoding: str, state_digests: dict[str, str]) -> None:
    config = graph.config
    assert (config["schema"], config["kind"], config["encoding"]) == (1, "vm-artifact", "silo-chunks-v1")
    assert config["purpose"] == "checkpoint" and config["captureKind"] == "live-execution"
    assert config["content"]["kind"] == "snapshot" and config["content"]["id"] == saved.snapshot
    family, backend, storage = (("opaque-raw", "raw-block", "opaque-raw-v1") if profile == "raw"
                                else ("linux-overlay", "krun-overlay", "linux-overlay-v1"))
    assert (config["rootFamily"], config["backendRequirement"]) == (family, backend)
    assert config["minimumCapabilities"]["storageProfile"] == storage
    assert config["minimumCapabilities"]["liveRestore"] is True
    assert config["guestPlatform"] == {"os": "linux", "architecture": guest_architecture()}
    execution = record["execution"]
    requirements = config["executionRequirements"]
    assert requirements["kind"] == "krun-v1"
    assert requirements["compatibilityProfile"] == execution["compatibilityProfile"]
    # Exact canonical record and sealed evidence bytes, not re-serializations.
    assert graph.record == record_bytes and digest_of(record_bytes) == config["content"]["record"]["digest"]
    assert graph.evidence == evidence
    # Native state travels under its own media types with the sealed bytes.
    for role, filename, media in (("execution", "execution.state", EXECUTION_MEDIA),
                                  ("devices", "devices.state", DEVICE_MEDIA)):
        assert graph.direct.get(execution[role]) == media, (role, execution[role])
        assert state_digests[filename] == execution[role]
    assert graph.direct.get(execution["layout"]) == RECORD_MEDIA
    assert execution["memory"]["stream"] in graph.streams
    if encoding == "raw":
        assert graph.chunk_media == {RAW_CHUNK}, graph.chunk_media
    else:
        assert ZSTD_CHUNK in graph.chunk_media, "RAM/disk chunks never used the zstd encoding"


def push(silo: Silo, source: str, reference: str, *flags: str, expect: int | None = 0) -> Result:
    return silo.run("image", "push", source, reference, *flags, expect=expect, timeout=TRANSFER, label="artifact-push")


def push_checkpoint(silo: Silo, distribution: DistributionRegistry, source: str, snapshot: str, tag: str,
                    *flags: str) -> dict:
    reference = distribution.reference(REPOSITORY, tag)
    before = distribution.stored_blob_digests()
    blobs = blob_requests(distribution)
    refused = push(silo, source, reference, *flags, expect=None)
    assert refused.returncode != 0, refused.stderr
    assert distribution.stored_blob_digests() == before and blob_requests(distribution) == blobs, (
        "unacknowledged checkpoint publication contacted the registry")
    assert tag not in distribution.client().tags(REPOSITORY)
    report = json.loads(push(silo, source, reference, *flags, "--acknowledge-checkpoint").stdout)
    assert report["repository"] == f"{distribution.address}/{REPOSITORY}" and report["tag"] == tag, report
    assert report["source"] == {"kind": "snapshot", "id": snapshot}, report
    assert report["purpose"] == "checkpoint" and report["captureKind"] == "live-execution", report
    silo.ws.record("artifact-publication", json.dumps(report, sort_keys=True) + "\n")
    return report


def refused_pull(silo: Silo, distribution: DistributionRegistry, reference: str, *trust: str) -> None:
    before_pools, blobs = pools(silo), blob_requests(distribution)
    result = silo.run("image", "pull", reference, *trust, "--name", "artifact-refused", expect=None,
                      timeout=TRANSFER, label="artifact-pull-refused")
    assert result.returncode != 0, result.stderr
    assert pools(silo) == before_pools, "refused acquisition published bytes"
    assert count(silo, "SELECT count(*) FROM storage_snapshot") == 0
    assert count(silo, "SELECT count(*) FROM managed_artifact_acquisition") == 0
    assert blob_requests(distribution) == blobs, "a payload was fetched before trust approval"


def pull(silo: Silo, reference: str, digest: str, alias: str) -> dict:
    result = silo.run("image", "pull", reference, "--approve-digest", digest, "--name", alias,
                      timeout=TRANSFER, label="artifact-pull")
    report = json.loads(result.stdout)
    silo.ws.record("artifact-acquisition", json.dumps(report, sort_keys=True) + "\n")
    return report


def verify_acquisition(silo: Silo, report: dict, graph: PublishedGraph, saved: restore.Checkpoint,
                       record_bytes: bytes, evidence: bytes, repository: str, alias: str) -> None:
    # Digest approval proves integrity of exactly this index, never who published it.
    assert report["publisher"] == "unauthenticated" and report["indexDigest"] == graph.index_digest, report
    assert report["repository"] == repository, report
    assert report["source"]["kind"] == "snapshot", report
    info = report["source"]["info"]
    assert info["id"] == saved.snapshot and info["captureKind"] == "live-execution", info
    assert info["retained"] is True and alias in info["aliases"], info
    assert info["provenance"] == [], "an import must not claim a local capture"
    snapshot = saved.snapshot
    assert rows(silo, f"SELECT hex(record_bytes) FROM storage_snapshot WHERE id='{snapshot}'") == [
        (record_bytes.hex().upper(),)], "imported semantic record bytes differ from the source"
    assert count(silo, f"SELECT count(*) FROM snapshot_capture_provenance WHERE snapshot_id='{snapshot}'") == 0
    assert count(silo, "SELECT count(*) FROM storage_operation WHERE kind='capture'") == 0
    assert count(silo, "SELECT count(*) FROM machine_config") == 0, "acquisition created a machine"
    imported = rows(silo, f"SELECT provenance_digest,evidence_digest FROM snapshot_imported_capture WHERE snapshot_id='{snapshot}'")
    assert imported == [(graph.provenance_digest, digest_of(evidence))], imported
    acquisitions = rows(silo, "SELECT managed_kind,managed_id,index_digest,receipt_digest,hex(receipt_bytes),"
                              f"provenance_digest FROM managed_artifact_acquisition WHERE managed_id='{snapshot}'")
    assert len(acquisitions) == 1, acquisitions
    kind, managed, index, receipt_digest, receipt_hex, provenance = acquisitions[0]
    receipt_bytes = bytes.fromhex(receipt_hex)
    assert (kind, managed, index, provenance) == ("snapshot", snapshot, graph.index_digest, graph.provenance_digest)
    assert receipt_digest == digest_of(receipt_bytes)
    receipt = json.loads(receipt_bytes)
    assert {key: value for key, value in receipt.items() if key != "approvedAtUnixMs"} == {
        "schema": 1, "kind": "approved-digest", "repository": repository,
        "indexDigest": graph.index_digest, "policyId": "explicit-digest-approval-v1"}, receipt
    assert receipt_bytes == json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()


@contextmanager
def quarantined_home(silo: Silo) -> Iterator[Path]:
    """Hide the source home entirely; anything still reading it fails with EACCES/ENOENT."""
    original = silo.ws.silo_home
    hidden = silo.ws.root / "quarantined-source-home"
    original.rename(hidden)
    hidden.chmod(0)
    try:
        yield hidden
    finally:
        hidden.chmod(0o700)
        hidden.rename(original)


@contextmanager
def unavailable_source(registry: LoopbackRegistry, reference: str) -> Iterator[None]:
    """Prove the original source manifest is really 404 over its TLS server."""
    authority, repository_tag = reference.split("/", 1)
    repository, tag = repository_tag.rsplit(":", 1)
    url = f"https://{authority}/v2/{repository}/manifests/{tag}"
    with registry.unpublished(reference):
        try:
            with urlopen(url, context=ssl.create_default_context(cafile=str(registry.ca_path)), timeout=10) as reply:
                raise AssertionError(f"removed source OCI still served HTTP {reply.status}")
        except HTTPError as error:
            assert error.code == 404, error
            error.close()
        yield


def allocation_state(silo: Silo) -> dict:
    roots = [silo.ws.silo_home / "machines", silo.ws.run_root]
    return {"catalog": stopped.catalog(silo), "directories": {
        str(root): sorted(str(path.relative_to(root)) for path in root.rglob("*")) if root.is_dir() else []
        for root in roots
    }}


@pytest.mark.parametrize(("profile", "encoding", "policy"), [
    ("raw", "zstd", "full"), ("flat", "raw", "full"), ("raw", "zstd", "incremental"),
], ids=["raw-root-zstd-chunks", "flat-root-raw-chunks", "incremental-standalone"])
def test_live_checkpoint_publishes_pulls_into_fresh_home_and_restores_exact_cut(
    silo: Silo, destination: Silo, distribution: DistributionRegistry, restore_image: str,  # noqa: F811
    registry: LoopbackRegistry, profile: str, encoding: str, policy: str,
    artifact_processes: list[shutdown.Process],
) -> None:
    expected_boot = {role: overlay.digest(silo.ws.config.runtime_dir / "assets" / filename)
                     for role, filename in BOOT_ASSETS.items()}
    destination.run("image", "list")
    empty_destination = pools(destination)

    # Real capture of a live guest witness in the source home.
    restore.create_source(silo, restore_image, name=SOURCE, profile=profile)
    own(silo, SOURCE, artifact_processes)
    mark(silo, SOURCE, "captured")
    initial = restore.start_witness(silo, SOURCE)
    armed = restore.witness(silo, SOURCE, "arm")
    assert armed["timerPending"] == armed["signalPending"] == 1
    saved = restore.checkpoint(silo, SOURCE, alias="artifact-checkpoint")
    if policy == "incremental":
        incremental.require_candidate(saved.source_info)
        incremental.authenticated_map(silo, saved, mode="full", reason="requested")
        baseline = saved
        silo.run("resume", SOURCE)
        restore.advances(silo, SOURCE, armed)
        parent = restore.checkpoint(silo, SOURCE, alias="artifact-incremental-parent", policy="incremental")
        incremental.authenticated_map(silo, parent, mode="incremental", baseline=baseline)
        silo.run("resume", SOURCE)
        restore.advances(silo, SOURCE, restore.witness(silo, SOURCE))
        saved = restore.checkpoint(silo, SOURCE, alias="artifact-incremental", policy="incremental")
        captured_map = incremental.authenticated_map(silo, saved, mode="incremental", baseline=parent)["map"]
        # The latest graph must stand alone even before transport. Parent
        # retention and aliases are not reconstruction dependencies.
        silo.run("image", "remove", "image:artifact-checkpoint")
        silo.run("snapshot", "remove", baseline.reference)
        silo.run("image", "remove", "image:artifact-incremental-parent")
        silo.run("snapshot", "remove", parent.reference)
    cut = restore.matched_cut(silo, saved, initial, profile=profile)
    sealed = capture.inventory(saved.staging)
    record_bytes, evidence, record = source_closure(silo, saved)
    state_digests = {filename: digest_of((saved.staging / filename).read_bytes())
                     for filename in ("execution.state", "devices.state")}
    if policy == "incremental":
        # Reap the capture owner before collection: its durable operation
        # legitimately retains earlier cuts until source cleanup.
        silo.run("resume", SOURCE)
        restore.resumed(silo, SOURCE, initial, cut)
        mark(silo, SOURCE, "source-before-publication")
        capture.unchanged(silo, saved.staging, sealed)
        stop_owned(silo, SOURCE, artifact_processes)
        silo.rm(SOURCE)
        shutdown.storage_tool(silo, "prune")
        assert count(silo, f"SELECT count(*) FROM storage_snapshot WHERE id='{baseline.snapshot}'") == 0
        assert count(silo, f"SELECT count(*) FROM storage_snapshot WHERE id='{parent.snapshot}'") == 0

    # Normal CLI publication; refused without the destination acknowledgement.
    flags = ("--raw",) if encoding == "raw" else ()
    report = push_checkpoint(silo, distribution, saved.reference, saved.snapshot, "v1", *flags)
    client = distribution.client()
    graph = published_graph(client, "v1")
    assert report["indexDigest"] == graph.index_digest
    verify_graph(graph, saved, record_bytes, evidence, record, profile=profile, encoding=encoding,
                 state_digests=state_digests)
    if policy == "full":
        capture.unchanged(silo, saved.staging, sealed)
    silo.ws.record("artifact-graph", json.dumps({
        "indexDigest": graph.index_digest, "digests": sorted(graph.digests), "layers": graph.layers,
        "config": graph.config, "streams": sorted(graph.streams), "chunkMedia": sorted(graph.chunk_media),
    }, sort_keys=True) + "\n")

    # Inspection reads only the immutable graph and retains nothing.
    reference = distribution.reference(REPOSITORY, "v1")
    inspected = json.loads(destination.run("image", "inspect-remote", reference, label="artifact-inspect").stdout)
    assert inspected["indexDigest"] == graph.index_digest and inspected["repository"] == report["repository"]
    assert inspected["content"] == {"kind": "snapshot", "id": saved.snapshot}, inspected
    assert (inspected["purpose"], inspected["captureKind"]) == ("checkpoint", "live-execution"), inspected
    assert (inspected["rootFamily"], inspected["backend"]) == (graph.config["rootFamily"],
                                                               graph.config["backendRequirement"]), inspected
    assert inspected["liveRestore"] is True
    assert pools(destination) == empty_destination

    # Real offline collection with the tag kept: only OCI descriptor edges retain
    # the graph, so a JSON-only edge would be swept here.
    distribution.stop()
    kept = distribution.garbage_collect(delete_untagged=True)
    assert graph.digests <= kept.marked and not graph.digests & kept.eligible_blobs, kept
    assert graph.digests <= distribution.stored_blob_digests()
    distribution.start()

    # Fresh destination: stricter or wrong trust refuses before any payload.
    refused_pull(destination, distribution, reference, "--require-signature")
    refused_pull(destination, distribution, reference, "--approve-digest", graph.config["content"]["record"]["digest"])
    acquired = pull(destination, reference, graph.index_digest, "artifact-pulled")
    verify_acquisition(destination, acquired, graph, saved, record_bytes, evidence, report["repository"],
                       "artifact-pulled")

    # Full captures also prove source divergence after publication. Incremental
    # sources were reaped before transport to prove parent-independent GC.
    if policy == "full":
        silo.run("resume", SOURCE)
        restore.resumed(silo, SOURCE, initial, cut)
        mark(silo, SOURCE, "source-after-publication")
        assert marker(silo, SOURCE) == "source-after-publication"
        stop_owned(silo, SOURCE, artifact_processes)
        silo.rm(SOURCE)
    silo.run("image", "remove", "image:" + ("artifact-incremental" if policy == "incremental" else "artifact-checkpoint"))
    silo.run("snapshot", "remove", saved.reference)
    shutdown.storage_tool(silo, "remove-image", restore_image)
    shutdown.storage_tool(silo, "prune")

    # Delete and physically collect the published graph, then stop the registry.
    client = distribution.client()
    client.delete_manifest(REPOSITORY, graph.index_digest)
    distribution.stop()
    swept = distribution.garbage_collect(delete_untagged=True)
    assert graph.digests <= swept.eligible_blobs, swept
    assert not graph.digests & distribution.stored_blob_digests(), "registry still holds the artifact"

    # Today's runtime boot bytes are garbage: only captured objects may boot.
    for filename in BOOT_ASSETS.values():
        asset = destination.ws.config.runtime_dir / "assets" / filename
        mode = asset.stat().st_mode & 0o7777
        asset.unlink()
        asset.write_bytes(b"not the checkpoint boot bytes\n")
        asset.chmod(mode)
    shutdown.storage_tool(destination, "prune")
    assert json.loads(destination.run("snapshot", "inspect", "image:artifact-pulled").stdout)["retained"] is True

    child = "artifact-restored"
    pulled = replace(saved, reference="image:artifact-pulled")
    with quarantined_home(silo) as hidden, unavailable_source(registry, restore_image):
        source_requests = registry.requests
        restored = restore.restore_child(destination, pulled, child)
        own(destination, child, artifact_processes)
        restore.exact_boot(destination, child, expected_boot)
        assert stopped.record(destination, child)["boot"] == record["boot"]
        assert marker(destination, child) == "captured", "restore observed post-publication source writes"
        restore.resumed(destination, child, initial, cut)
        for path in stopped.writable_paths(destination, child).values():
            assert destination.ws.silo_home in path.parents and path.stat().st_nlink == 1, path
        mark(destination, child, "destination-only")
        assert marker(destination, child) == "destination-only"

        if policy == "incremental":
            restore.witness(destination, child, "arm")
            child_checkpoint = restore.checkpoint(destination, child, alias="artifact-child-incremental",
                                                   policy="incremental")
            # Its imported source has no capture staging directory, so bind the
            # expected complete map to the independently retained source map.
            inherited = incremental.authenticated_map(destination, child_checkpoint,
                                                       mode="incremental", baseline=saved, baseline_map=captured_map)
            assert inherited["stats"]["liveBytesRead"] < child_checkpoint.seal["memory"]["packedLength"]
            child_cut = restore.matched_cut(destination, child_checkpoint, initial, profile=profile)
            destination.run("resume", child)
            restore.resumed(destination, child, initial, child_cut)
            destination.run("image", "remove", "image:artifact-child-incremental")
            destination.run("snapshot", "remove", child_checkpoint.reference)
        # Explicit retention and alias released while running: leases, not the
        # catalog root, protect the imported closure until the child is reaped.
        streams = sorted(graph.streams)
        objects = sorted(graph.direct)
        destination.run("image", "remove", "image:artifact-pulled")
        destination.run("snapshot", "remove", saved.reference)
        shutdown.storage_tool(destination, "prune")
        restore.advances(destination, child, restore.witness(destination, child))
        stop_owned(destination, child, artifact_processes)
        destination.rm(child)
        shutdown.storage_tool(destination, "prune")
        for table, column in (("storage_snapshot", "id"), ("snapshot_imported_capture", "snapshot_id"),
                              ("managed_artifact_acquisition", "managed_id")):
            assert count(destination, f"SELECT count(*) FROM {table} WHERE {column}='{saved.snapshot}'") == 0, table
        assert not any(pool_path(destination, "streams", stream).exists() for stream in streams)
        assert not any(pool_path(destination, "objects", digest).exists() for digest in objects)
        assert hidden.stat().st_mode & 0o777 == 0
        assert registry.requests == source_requests, "standalone restore contacted removed source OCI"
    destination.ws.record("artifact-live", json.dumps({
        "profile": profile, "encoding": encoding, "snapshot": saved.snapshot, "indexDigest": graph.index_digest,
        "registry": distribution.identity(), "keptMarked": len(kept.marked), "swept": sorted(graph.digests),
        "sourceIdentity": saved.source_info["id"], "childIdentity": restored["id"],
        "cut": {"committed": cut.committed, "durable": cut.durable},
    }, sort_keys=True) + "\n")


def test_incompatible_imported_execution_refuses_before_child_allocation(
    silo: Silo, destination: Silo, distribution: DistributionRegistry, restore_image: str,  # noqa: F811
    registry: LoopbackRegistry, artifact_processes: list[shutdown.Process],
) -> None:
    """Exact Phase 20 portability refusal, then separately named cold recovery.

    The CPUID mutation keeps every header and binding valid, so publication,
    graph verification and import succeed. Only execution admission refuses.
    """
    restore.create_source(silo, restore_image, name=SOURCE)
    own(silo, SOURCE, artifact_processes)
    mark(silo, SOURCE, "recoverable-disk-cut")
    silo.exec(SOURCE, "sh", "-eu", "-c", "printf live-only >/dev/shm/recovery-live-only", user="root")
    saved = restore.checkpoint(silo, SOURCE, alias="artifact-checkpoint")
    captured_disks = list((saved.staging / "disks").glob("*.raw"))
    assert len(captured_disks) == 1
    captured_disk = stopped.read_bytes(captured_disks[0])
    stop_owned(silo, SOURCE, artifact_processes)
    with restore.incompatible_checkpoint(silo, saved, "cpu") as (source_reference, subject):
        forged = source_reference.removeprefix("image:")
        push_checkpoint(silo, distribution, source_reference, forged, "incompatible")
    graph = published_graph(distribution.client(), "incompatible")
    assert graph.config["content"]["id"] == forged and graph.config["captureKind"] == "live-execution"
    reference = distribution.reference(REPOSITORY, "incompatible")
    acquired = pull(destination, reference, graph.index_digest, "artifact-incompatible")
    assert acquired["source"]["info"]["id"] == forged and acquired["publisher"] == "unauthenticated", acquired

    child = "artifact-incompatible-child"
    before = allocation_state(destination)
    leases = destination.ws.silo_home / "images/locks/leases"
    original_leases = set(leases.iterdir()) if leases.is_dir() else set()
    destination.ws.register_machine(child)
    result = destination.run(*restore.restore_argv("image:artifact-incompatible", child), expect=None, timeout=60)
    after = allocation_state(destination)
    new_leases = (set(leases.iterdir()) if leases.is_dir() else set()) - original_leases
    destination.ws.record("artifact-incompatible-refusal", json.dumps({
        "snapshot": forged, "indexDigest": graph.index_digest, "exit": result.returncode, "stderr": result.stderr,
        "before": before, "after": after, "newVerificationLeases": sorted(map(str, new_leases)),
    }, sort_keys=True) + "\n")
    assert result.returncode != 0, "an incompatible imported execution restored"
    assert subject in result.stderr, result.stderr
    for required in ("restore-preflight", "pin cpu.cpuid", "expected ", "destination ",
                     "no execution child was started"):
        assert required in result.stderr, (required, result.stderr)
    assert before["directories"] == after["directories"], "refusal allocated child directories"
    for table, catalog_rows in before["catalog"].items():
        actual = after["catalog"][table]
        if table == "storage_operation" or table.startswith("storage_operation_"):
            # Opening the runtime may retire the completed pull's operation.
            assert set(map(tuple, actual)) <= set(map(tuple, catalog_rows)), table
        else:
            assert actual == catalog_rows, table
    assert all(not shutdown.lease_busy(path) for path in new_leases)
    assert not any(machine["name"] == child for machine in destination.ls())

    # Import/inspection is independent of execution admission. The artifact
    # stays authentic and transferable; recovery is an explicitly different
    # operation, never a fallback inside the failed restore request.
    imported_record = rows(destination, f"SELECT hex(record_bytes) FROM storage_snapshot WHERE id='{forged}'")
    assert json.loads(bytes.fromhex(imported_record[0][0]))["captureKind"] == "live-execution"
    immutable_paths = [pool_path(destination, "streams", stream) for stream in graph.streams]
    immutable_paths += [pool_path(destination, "objects", digest) for digest in graph.direct]
    immutable = {path: stopped.read_bytes(path) for path in immutable_paths}
    silo.rm(SOURCE)
    silo.run("image", "remove", "image:artifact-checkpoint")
    silo.run("snapshot", "remove", saved.reference)
    shutdown.storage_tool(silo, "remove-image", restore_image)
    shutdown.storage_tool(silo, "prune")
    client = distribution.client()
    client.delete_manifest(REPOSITORY, graph.index_digest)
    distribution.stop()
    collected = distribution.garbage_collect(delete_untagged=True)
    assert graph.digests <= collected.eligible_blobs
    assert not graph.digests & distribution.stored_blob_digests()

    recovered = "artifact-disk-recovery"
    with quarantined_home(silo), unavailable_source(registry, restore_image):
        source_requests = registry.requests
        destination.ws.register_machine(recovered)
        destination.run("recover-disks", "image:artifact-incompatible", "--name", recovered, timeout=240)
        info = destination.info(recovered)
        assert info["name"] == recovered and info["id"] != saved.source_info["id"]
        assert info["state"] == "stopped" and info["run_id"] is None and info["ready"] is False
        storage = stopped.record(destination, recovered)
        assert storage["snapshot"] == forged and storage["stopOutcome"] == "unknown"
        assert storage["boot"] == json.loads(bytes.fromhex(imported_record[0][0]))["boot"]
        assert count(destination, "SELECT count(*) FROM restore_memory_reservation") == 0
        directory = overlay.machine_dir(destination, recovered)
        assert not any(path.name in {"memory.ram", "execution.state", "devices.state"}
                       for path in directory.rglob("*")), "disk recovery installed execution inputs"
        private = stopped.backing(destination, recovered, "recovery-before-boot")
        assert set(private) == {"root"}
        assert private["root"].content() == captured_disk.content()
        stopped.independent({"root": captured_disk}, private)
        assert rows(destination, f"SELECT hex(record_bytes) FROM storage_snapshot WHERE id='{forged}'") == imported_record
        # Ordinary explicit start is a new boot, not resumed incompatible RAM.
        destination.start(recovered)
        destination.wait_ready(recovered)
        own(destination, recovered, artifact_processes)
        assert destination.exec(recovered, "cat", "/proc/sys/kernel/random/boot_id").stdout != saved.boot_id
        assert marker(destination, recovered) == "recoverable-disk-cut"
        destination.exec(recovered, "test", "!", "-e", "/dev/shm/recovery-live-only")
        mark(destination, recovered, "recovered-private-write")
        assert marker(destination, recovered) == "recovered-private-write"
        for path, before_bytes in immutable.items():
            assert stopped.read_bytes(path) == before_bytes, "cold recovery mutated immutable imported closure"
        assert rows(destination, f"SELECT hex(record_bytes) FROM storage_snapshot WHERE id='{forged}'") == imported_record
        assert registry.requests == source_requests, "disk recovery contacted removed source OCI"
        stop_owned(destination, recovered, artifact_processes)
    destination.ws.record("artifact-disk-recovery", json.dumps({
        "checkpoint": forged, "machine": recovered, "sourceBootId": saved.boot_id,
        "privateDiskSha256": private["root"].sha256, "registryGraphCollected": True,
        "executionRefusal": result.stderr, "stopOutcomeAtCreation": storage["stopOutcome"],
    }, sort_keys=True) + "\n")
