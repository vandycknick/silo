"""Real OCI ingest performance cohort and pure summary budget gates."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tarfile

import pytest

from silo_smoke import fork_budget, images, ingest_budget, shutdown
from silo_smoke.cli import Silo, TIMINGS_PROPERTY, release
from silo_smoke.config import RUN_ROOT_PARENT, SmokeConfig
from silo_smoke.distribution_registry import DistributionRegistry, install_distribution
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.workspace import Workspace


def _budget_workspace(config: SmokeConfig, ca_path: Path) -> Workspace:
    supplied = os.environ.get("SILO_SMOKE_BUDGET_DIR")
    parent = Path(supplied) if supplied else None
    if parent is not None:
        assert parent.is_absolute() and parent.is_dir(), "SILO_SMOKE_BUDGET_DIR must name an existing mounted directory"
    return Workspace(config, ca_path, parent=parent,
                     runtime_parent=Path(RUN_ROOT_PARENT) if parent is not None else None)


@dataclass(frozen=True)
class IngestCorpus:
    registry: DistributionRegistry
    images: list[ingest_budget.CorpusImage]
    base_reference: str
    base_manifest: str
    initial_space: dict[str, ingest_budget.Json]


@pytest.fixture(scope="session")
def ingest_corpus(config: SmokeConfig, registry: LoopbackRegistry, request: pytest.FixtureRequest,
                  record_testsuite_property: Callable[[str, object], None]) -> Iterator[IngestCorpus]:
    """Generate once per session; never retain bulk blobs, even after failed setup."""
    workspace = _budget_workspace(config, registry.ca_path)
    local: DistributionRegistry | None = None
    failed = True
    try:
        space = fork_budget.headroom(Silo(workspace), ingest_budget.SCRATCH_BYTES)
        base = images.build(images.BASIC, images.fetch_alpine(config.cache_dir))
        base_reference = registry.publish(base, "ingest-budget-base")
        local = DistributionRegistry(install_distribution(config.cache_dir), config.cache_dir,
                                     parent=workspace.root)
        local.start()
        corpus = ingest_budget.publish_corpus(local, base)
        yield IngestCorpus(local, corpus, base_reference, base.manifest_digest, space)
        failed = False
    finally:
        try:
            if local is not None:
                try:
                    workspace.record("ingest-registry", local.log_text())
                finally:
                    # Unlike ordinary failed registries, never retain bulk storage.
                    local.close(retain=False)
        finally:
            release(workspace, failed=failed or request.session.testsfailed > 0,
                    publish=lambda summary: record_testsuite_property(
                        f"{TIMINGS_PROPERTY}-ingest-corpus", summary))


@pytest.fixture(name="silo")
def ingest_silo(config: SmokeConfig, registry: LoopbackRegistry,
                request: pytest.FixtureRequest) -> Iterator[Silo]:
    workspace = _budget_workspace(config, registry.ca_path)
    try:
        yield Silo(workspace)
    finally:
        release(workspace, failed=request.session.testsfailed > 0,
                publish=lambda summary: request.node.user_properties.append((TIMINGS_PROPERTY, summary)))


@pytest.mark.linux_only
@pytest.mark.slow
def test_ingest_budget_full_prepare_and_linearity(silo: Silo, ingest_corpus: IngestCorpus) -> None:
    """Fixed 1/4/12 GiB corpus, five cold and warm samples, never a scaled substitute."""
    local = ingest_corpus.registry
    assert local.storage.stat().st_dev == silo.ws.silo_home.stat().st_dev
    host = fork_budget.reference_host(silo)
    host["registry"] = local.identity()
    host["registryLink"] = "TLS over host loopback; same endpoint for baseline and prepare"
    host["scratchBytes"] = ingest_budget.SCRATCH_BYTES
    evidence = fork_budget.Evidence("ingest", host, summarize=ingest_budget.summarize,
                                    markdown=ingest_budget.markdown)
    shutdown.storage_tool(silo, "prune")
    ingest_budget.assert_empty_pool(silo)
    evidence.record("fixture.json", {"sizes": list(ingest_budget.SIZES),
                                     "corpus": [asdict(image) for image in ingest_corpus.images],
                                     "generator": "head /dev/urandom | tee sha256sum | gzip -1; curl streaming upload",
                                     "generationSecondsPerGiB": ingest_budget.GENERATION_SECONDS_PER_GIB,
                                     "baseReference": ingest_corpus.base_reference,
                                     "baseManifest": ingest_corpus.base_manifest,
                                     "space": ingest_corpus.initial_space, "privateRawCopies": 0,
                                     "prepareCommand": "silo create REF --name NAME --pull missing --disk-size 256mib --network none"})
    for cohort, index in fork_budget.SCHEDULE:
        sizes: list[ingest_budget.SizeSample] = []
        for image in ingest_corpus.images:
            measured = ingest_budget.measure_size(silo, local, image, cohort, index)
            sizes.append(measured)
            # Persist completed sizes even if a subsequent create fails.
            evidence.record(f"size-{cohort}-{index}-{image.entry_bytes}.json", measured)
        evidence.sample(ingest_budget.sample(cohort, index, sizes))
    summary = evidence.finish()
    silo.ws.record("ingest-budget-summary", json.dumps(summary, sort_keys=True) + "\n")
    assert len(summary["pass"]) == 4 and all(summary["pass"].values()), (
        f"ADR ingest median exceeds target; evidence: {evidence.directory}", summary["pass"])


def _size(entry: int, prepare: float, baseline: float) -> ingest_budget.SizeSample:
    """Synthetic measurements for the pure summary calculation, not a product double."""
    return {"entryBytes": entry, "expandedBytes": entry, "compressedBytes": entry,
            "reference": "synthetic", "unpreparedCreateSeconds": prepare + 1.0,
            "warmCreateSeconds": 1.0, "prepareSeconds": prepare, "baselineSeconds": baseline,
            "baselineMethods": {"urllib-zlib": baseline, "curl-gzip": baseline + 1.0},
            "baselineCache": {}, "prepareCache": {"label": "cold"},
            "coldPrepareRatio": prepare / baseline, "prepareSecondsPerGiB": prepare / (entry / ingest_budget.GIB),
            "lower": {}, "space": {}}


def _samples(ratio: float, linearity: float) -> list[ingest_budget.Sample]:
    samples: list[ingest_budget.Sample] = []
    for cohort, index in fork_budget.SCHEDULE:
        # Deliberately bad discarded warm-up must never poison a real median.
        measured_ratio = 100.0 if cohort == "warm-up" else ratio
        measured_linearity = 100.0 if cohort == "warm-up" else linearity
        sizes = [_size(ingest_budget.SIZES[0], 4.0, 4.0 / measured_ratio),
                 _size(ingest_budget.SIZES[1], 16.0, 16.0 / measured_ratio),
                 _size(ingest_budget.SIZES[-1], 48.0 * measured_linearity,
                       48.0 * measured_linearity / measured_ratio)]
        samples.append(ingest_budget.sample(cohort, index, sizes))
    return samples


@pytest.mark.parametrize(("ratio", "expected"), [(1.0, True), (1.5, True), (1.5001, False)])
def test_ingest_ratio_budget_gate(ratio: float, expected: bool) -> None:
    samples = _samples(ratio, 1.0)
    summary = ingest_budget.summarize(samples)
    for cohort in ("cold", "warm"):
        metric = summary["metrics"]["coldPrepareRatio"][cohort]
        assert metric["samples"] == fork_budget.SAMPLES
        assert metric["median"] == pytest.approx(ratio)
        assert metric["budgeted"] is True
        assert summary["pass"][f"coldPrepareRatio/{cohort}"] is expected
        assert summary["pass"][f"linearity/{cohort}"] is True
        assert summary["sizes"][str(ingest_budget.SIZES[-1])][cohort]["prepareSeconds"]["median"] == 48.0


@pytest.mark.parametrize(("linearity", "expected"), [(1.0, True), (1.25, True), (1.2501, False)])
def test_ingest_linearity_budget_gate(linearity: float, expected: bool) -> None:
    summary = ingest_budget.summarize(_samples(1.0, linearity))
    for cohort in ("cold", "warm"):
        metric = summary["metrics"]["linearity"][cohort]
        assert metric["samples"] == fork_budget.SAMPLES
        assert metric["median"] == pytest.approx(linearity)
        assert metric["budgeted"] is True
        assert summary["pass"][f"linearity/{cohort}"] is expected
        assert summary["pass"][f"coldPrepareRatio/{cohort}"] is True
        largest = summary["sizes"][str(ingest_budget.SIZES[-1])][cohort]
        assert largest["prepareSecondsPerGiB"]["median"] == pytest.approx(4.0 * linearity)


def test_ingest_median_and_optional_budget_gate() -> None:
    samples = _samples(1.5, 1.25)
    for cohort in ("cold", "warm"):
        chosen = [sample for sample in samples if sample["cohort"] == cohort]
        chosen[0]["coldPrepareRatio"] = 9.0
        chosen[0]["linearity"] = 9.0
        chosen[-1]["coldPrepareRatio"] = 0.5
        chosen[-1]["linearity"] = 0.5
        for sample in chosen:
            sample["gates"] = ["coldPrepareRatio"]
    summary = ingest_budget.summarize(samples)
    for cohort in ("cold", "warm"):
        assert summary["pass"][f"coldPrepareRatio/{cohort}"] is True
        assert f"linearity/{cohort}" not in summary["pass"]
        assert summary["metrics"]["linearity"][cohort]["budgeted"] is False
        assert summary["metrics"]["coldPrepareRatio"][cohort]["min"] == 0.5
        assert summary["metrics"]["coldPrepareRatio"][cohort]["max"] == 9.0


def test_ingest_worst_size_and_cache_budget_gate() -> None:
    samples = _samples(1.0, 1.0)
    for sample in samples:
        sample["sizes"][1]["coldPrepareRatio"] = 1.5001
        sample["sizes"][0]["baselineCache"] = {"urllib-zlib": {"label": "partial-cold"}}
        updated = ingest_budget.sample(sample["cohort"], sample["index"], sample["sizes"])
        sample.update(updated)
    summary = ingest_budget.summarize(samples)
    assert summary["coldFullyEvicted"] is False
    assert "cold:partial-cold" in summary["cacheLabels"]
    assert summary["pass"]["coldPrepareRatio/cold"] is False
    assert summary["pass"]["coldPrepareRatio/warm"] is False


def test_ingest_sample_count_budget_gate() -> None:
    with pytest.raises(AssertionError):
        ingest_budget.summarize(_samples(1.0, 1.0)[1:])


@pytest.mark.parametrize(("size", "seconds"), [
    (1, 120.0), (ingest_budget.GIB, 120.0),
    (4 * ingest_budget.GIB, 480.0), (12 * ingest_budget.GIB, 1440.0),
])
def test_ingest_generation_timeout_budget_gate(size: int, seconds: float) -> None:
    assert ingest_budget.generation_timeout(size) == seconds
    assert ingest_budget.TIMEOUT == 300, "fixture bounds must not extend measured-operation bounds"


@pytest.mark.parametrize("size", [0, -1])
def test_ingest_generation_empty_input_budget_gate(size: int) -> None:
    with pytest.raises(ValueError):
        ingest_budget.generation_timeout(size)


@pytest.mark.linux_only
@pytest.mark.slow
def test_ingest_native_layer_streaming_and_failure_cleanup(
    silo: Silo, config: SmokeConfig, tmp_path: Path,
) -> None:
    """Real producer/upload and OCI reference removal, including failure cleanup."""
    local = DistributionRegistry(install_distribution(config.cache_dir), config.cache_dir, parent=tmp_path)
    size = 64 * 1024
    try:
        local.start()
        blob = ingest_budget._random_layer(local, "smoke/native-ingest", size)
        encoded = local.client().blob("smoke/native-ingest", blob["digest"])
        assert encoded is not None and len(encoded) == blob["size"]
        assert "sha256:" + hashlib.sha256(encoded).hexdigest() == blob["digest"]
        raw = gzip.decompress(encoded)
        assert len(raw) == blob["expandedBytes"]
        assert "sha256:" + hashlib.sha256(raw).hexdigest() == blob["diffId"]
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            assert len(members) == 1
            assert members[0].name == "ingest-budget.payload" and members[0].size == size
        assert not list(local.root.glob("ingest-layer-*")), "completed producer retained compressed scratch"
        with pytest.raises(ValueError):
            ingest_budget._random_layer(local, "INVALID", size)
        assert not list(local.root.glob("ingest-layer-*")), "failed upload retained compressed scratch"
        base = images.build(images.BASIC, images.fetch_alpine(config.cache_dir))
        image = ingest_budget.publish_corpus(local, base, sizes=(size,))[0]
        name = "ingest-prune-proof"
        silo.create(name, image.reference, "--disk-size", "256mib", "--network", "none")
        silo.rm(name)
        # Prune alone must preserve the still-named OCI selection. The harness
        # must release that reference before claiming the next prepare is cold.
        shutdown.storage_tool(silo, "prune")
        with sqlite3.connect(f"file:{silo.ws.state_db()}?mode=ro", uri=True) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM image_composition_artifact WHERE manifest_digest=?",
                (image.manifest_digest,),
            ).fetchone()[0] == 1
            assert connection.execute("SELECT COUNT(*) FROM machine_storage").fetchone()[0] == 0
        previous = ingest_budget.retained_inputs(silo, image)
        assert any(path.exists() for path in previous), "real prepare did not retain any lower input"
        ingest_budget.remove_prepared_image(silo, image)
        ingest_budget.assert_unprepared(silo, image, previous)
    finally:
        local.close(retain=False)
    assert not local.root.exists(), "registry teardown retained blob storage"
