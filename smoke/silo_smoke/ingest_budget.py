"""ADR 0014 full OCI prepare versus local download/decode and expanded-size scaling.

Only container create prepares an OCI container lower. A sample retains both the
unprepared and prepared create durations; their difference removes ordinary
stopped-machine creation. Registry fixtures are streamed, never retained in RAM.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import signal
import sqlite3
import ssl
import subprocess
import tarfile
import tempfile
import time
from typing import TypedDict, cast
import urllib.request
from urllib.parse import quote
import zlib

from . import images, page_cache, shutdown
from .cli import Silo
from .distribution_registry import DistributionRegistry, OCI_MANIFEST
from .fork_budget import SAMPLES, cache_state, describe, headroom, owned_inputs

GIB = 1024 ** 3
SIZES = (GIB, 4 * GIB, 12 * GIB)
TARGETS = {"coldPrepareRatio": 1.5, "linearity": 1.25}
CHUNK = 4 * 1024 * 1024
TIMEOUT = 300
GENERATION_SECONDS_PER_GIB = 120
# Retained gzip corpus plus source download, staged/published packs and margin.
SCRATCH_BYTES = sum(SIZES) + 3 * max(SIZES) + 2 * GIB
Json = str | int | float | bool | None | list["Json"] | dict[str, "Json"]


class Blob(TypedDict):
    digest: str
    size: int
    expandedBytes: int
    diffId: str


@dataclass(frozen=True)
class CorpusImage:
    reference: str
    repository: str
    entry_bytes: int
    blobs: tuple[Blob, ...]
    manifest_digest: str


class SizeSample(TypedDict):
    entryBytes: int
    expandedBytes: int
    compressedBytes: int
    reference: str
    unpreparedCreateSeconds: float
    warmCreateSeconds: float
    prepareSeconds: float
    baselineSeconds: float
    baselineMethods: dict[str, float]
    baselineCache: dict[str, dict[str, Json]]
    prepareCache: dict[str, Json]
    coldPrepareRatio: float
    prepareSecondsPerGiB: float
    lower: dict[str, Json]
    space: dict[str, Json]


class Sample(TypedDict):
    cohort: str
    index: int
    cache: dict[str, Json]
    gates: list[str]
    sizes: list[SizeSample]
    coldPrepareRatio: float
    linearity: float


class Distribution(TypedDict):
    samples: int
    median: float
    min: float
    max: float
    values: list[float]


class Metric(Distribution):
    budgeted: bool


# 'pass' is a Python keyword, so declare its evidence field functionally.
SummaryRecord = TypedDict("SummaryRecord", {
    "targets": dict[str, float], "metrics": dict[str, dict[str, Metric]],
    "sizes": dict[str, dict[str, dict[str, Distribution]]], "pass": dict[str, bool],
    "cacheLabels": list[str], "coldFullyEvicted": bool, "cohorts": list[str],
})


def summarize(samples: list[Sample]) -> SummaryRecord:
    """Gate five medians per cache cohort; the ratio covers the worst size."""
    result: SummaryRecord = {
        "targets": TARGETS, "metrics": {}, "sizes": {}, "pass": {},
        "cacheLabels": sorted({f"{sample['cohort']}:{sample['cache']['label']}" for sample in samples}),
        "coldFullyEvicted": all(sample["cache"]["label"] == "cold"
                                for sample in samples if sample["cohort"] == "cold"),
        "cohorts": sorted({sample["cohort"] for sample in samples}),
    }
    for cohort in ("cold", "warm"):
        chosen = [sample for sample in samples if sample["cohort"] == cohort]
        if not chosen:
            continue
        assert len(chosen) == SAMPLES, (cohort, len(chosen))
        for metric, target in TARGETS.items():
            values = [sample["coldPrepareRatio"] if metric == "coldPrepareRatio" else sample["linearity"]
                      for sample in chosen]
            described = cast(Metric, describe(values))
            described["budgeted"] = all(metric in sample["gates"] for sample in chosen)
            result["metrics"].setdefault(metric, {})[cohort] = described
            if described["budgeted"]:
                result["pass"][f"{metric}/{cohort}"] = described["median"] <= target
        byte_sizes = [size["entryBytes"] for size in chosen[0]["sizes"]]
        assert all([size["entryBytes"] for size in sample["sizes"]] == byte_sizes for sample in chosen)
        for position, size in enumerate(byte_sizes):
            records = [sample["sizes"][position] for sample in chosen]
            result["sizes"].setdefault(str(size), {})[cohort] = {
                key: cast(Distribution, describe([float(record[key]) for record in records]))
                for key in ("entryBytes", "expandedBytes", "compressedBytes", "unpreparedCreateSeconds",
                            "warmCreateSeconds", "prepareSeconds", "baselineSeconds", "coldPrepareRatio",
                            "prepareSecondsPerGiB")
            }
    return result


def markdown(summary: SummaryRecord, host: dict[str, Json]) -> str:
    lines = ["| Metric (ratio) | Cohort | Median | Min | Max | Target | Result |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    for metric, cohorts in summary["metrics"].items():
        for cohort, value in cohorts.items():
            passed = summary["pass"].get(f"{metric}/{cohort}")
            verdict = "recorded (not budgeted)" if passed is None else ("pass" if passed else "FAIL")
            lines.append(f"| {metric} | {cohort} | {value['median']:.4f} | {value['min']:.4f} | "
                         f"{value['max']:.4f} | {TARGETS[metric]:.2f} | {verdict} |")
    lines += ["", "| Entry GiB | Cohort | Prepare median s | Baseline median s | Prepare median s/GiB |",
              "| --- | --- | --- | --- | --- |"]
    for size, cohorts in summary["sizes"].items():
        for cohort, value in cohorts.items():
            lines.append(f"| {int(size) / GIB:g} | {cohort} | {value['prepareSeconds']['median']:.3f} | "
                         f"{value['baselineSeconds']['median']:.3f} | "
                         f"{value['prepareSecondsPerGiB']['median']:.3f} |")
    lines += ["", f"Host: {host['cpu']}; registry: {host['registry']}.",
              f"Cache labels: {', '.join(summary['cacheLabels'])}.",
              "Prepare = unprepared create minus prepared create; baseline = faster of streaming "
              "urllib/zlib and curl/gzip, independently cache-conditioned before each dispatch."]
    return "\n".join(lines) + "\n"


def generation_timeout(size: int) -> float:
    """Fixture construction is untimed, with a separate size-proportional bound."""
    if size <= 0:
        raise ValueError("The incompressible entry must be nonempty")
    return GENERATION_SECONDS_PER_GIB * max(1.0, size / GIB)


def _random_layer(registry: DistributionRegistry, repository: str, size: int) -> Blob:
    """Native random/tar/hash/gzip pipeline, followed by one streaming upload."""
    timeout = generation_timeout(size)
    header = tarfile.TarInfo("ingest-budget.payload")
    header.mode, header.size = 0o644, size
    encoded_header = header.tobuf(format=tarfile.GNU_FORMAT)
    end = bytes((-size) % tarfile.BLOCKSIZE + 2 * tarfile.BLOCKSIZE)
    end += bytes((-(len(encoded_header) + size + len(end))) % tarfile.RECORDSIZE)
    # No expanded payload file and no Python compression or upload chunk loop.
    # The FIFO hashes the exact tar stream while gzip writes its sole disk copy.
    with tempfile.TemporaryDirectory(prefix="ingest-layer-", dir=registry.root) as temporary:
        root = Path(temporary)
        prefix, suffix = root / "header", root / "trailer"
        fifo, raw_hash, compressed = root / "hash.fifo", root / "diff-id", root / "layer.gz"
        prefix.write_bytes(encoded_header)
        suffix.write_bytes(end)
        os.mkfifo(fifo, mode=0o600)
        script = (
            'set -euo pipefail\n'
            'sha256sum "$4" > "$5" &\n'
            'hasher=$!\n'
            '(cat "$1"; head -c "$2" /dev/urandom; cat "$3") | tee "$4" | gzip -1\n'
            'wait "$hasher"\n'
        )
        with compressed.open("wb") as output:
            with subprocess.Popen(
                ["bash", "-c", script, "ingest-layer", str(prefix), str(size), str(suffix),
                 str(fifo), str(raw_hash)], stdout=output, stderr=subprocess.PIPE,
                start_new_session=True,
            ) as process:
                try:
                    _, errors = process.communicate(timeout=timeout)
                    assert process.returncode == 0, errors.decode(errors="replace")
                except BaseException:
                    # Kill the whole pipeline, including a hasher blocked opening its FIFO.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=20)
                    raise
        encoded_bytes = compressed.stat().st_size
        assert encoded_bytes >= size, "fixture unexpectedly compressed: not the required random corpus"
        raw_checksum = raw_hash.read_text().split()[0]
        encoded_checksum = subprocess.run(
            ["sha256sum", str(compressed)], check=True, capture_output=True, text=True,
            timeout=timeout,
        ).stdout.split()[0]
        assert len(bytes.fromhex(raw_checksum)) == len(bytes.fromhex(encoded_checksum)) == 32
        digest = "sha256:" + encoded_checksum
        client = registry.client(timeout=TIMEOUT)
        upload = client.start_upload(repository)
        separator = "&" if "?" in upload.location else "?"
        url = f"https://{registry.address}{upload.location}{separator}digest={quote(digest)}"
        completed = subprocess.run(
            ["curl", "--fail", "--silent", "--show-error", "--noproxy", "*",
             "--cacert", str(registry.ca_path), "--max-time", str(timeout),
             "--request", "PUT", "--header", "Content-Type: application/octet-stream",
             "--upload-file", str(compressed), "--output", os.devnull,
             "--write-out", "%{http_code}", url],
            check=True, capture_output=True, text=True, timeout=timeout,
        )
        assert completed.stdout == "201", (completed.stdout, completed.stderr)
        assert client.blob_exists(repository, digest), "streaming upload did not commit its digest"
        return {"digest": digest, "size": encoded_bytes,
                "expandedBytes": len(encoded_header) + size + len(end),
                "diffId": "sha256:" + raw_checksum}


def publish_corpus(registry: DistributionRegistry, base: images.OciImage,
                   sizes: tuple[int, ...] = SIZES) -> list[CorpusImage]:
    """Reuse the ordinary BASIC builder; add exactly one random entry per image."""
    client = registry.client(timeout=TIMEOUT)
    repository = "smoke/ingest-budget"
    client.push_blob(repository, base.layer)
    base_manifest = json.loads(base.manifest)
    base_config = json.loads(base.config)
    base_blob: Blob = {"digest": base.layer_digest, "size": len(base.layer),
                       "expandedBytes": len(zlib.decompress(base.layer, wbits=31)),
                       "diffId": base_config["rootfs"]["diff_ids"][0]}
    corpus: list[CorpusImage] = []
    for size in sizes:
        layer = _random_layer(registry, repository, size)
        config = dict(base_config)
        config["rootfs"] = {"type": "layers", "diff_ids": [base_blob["diffId"], layer["diffId"]]}
        config_bytes = json.dumps(config, separators=(",", ":")).encode()
        config_digest = client.push_blob(repository, config_bytes)
        manifest = json.dumps({
            "schemaVersion": 2, "mediaType": OCI_MANIFEST,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                       "digest": config_digest, "size": len(config_bytes)},
            "layers": [*base_manifest["layers"], {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": layer["digest"], "size": layer["size"]}],
        }, separators=(",", ":")).encode()
        tag = f"bytes-{size}"
        digest = client.push_manifest(repository, tag, manifest, OCI_MANIFEST)
        corpus.append(CorpusImage(registry.reference(repository, digest), repository,
                                  size, (base_blob, layer), digest))
    return corpus


def conditioned_cache(silo: Silo, registry: DistributionRegistry, cohort: str) -> dict[str, Json]:
    """Include the actual disk-backed registry inputs, not only Silo's pool."""
    if cohort == "cold":
        return cast(dict[str, Json], page_cache.evict(owned_inputs(silo) + page_cache.inputs(registry.storage)))
    product = cast(dict[str, Json], cache_state(silo, cohort))
    remote = cast(dict[str, Json], page_cache.residency(page_cache.inputs(registry.storage)))
    return {"label": "warm-observed", "silo": product, "registry": remote}


def _python_baseline(urls: list[str], ca_path: Path, expected: int) -> float:
    context = ssl.create_default_context(cafile=str(ca_path))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context))
    expanded = 0
    started = time.monotonic()
    with open(os.devnull, "wb") as sink:
        for url in urls:
            decoder = zlib.decompressobj(wbits=31)
            with opener.open(url, timeout=TIMEOUT) as response:
                while chunk := response.read(CHUNK):
                    decoded = decoder.decompress(chunk)
                    expanded += len(decoded)
                    sink.write(decoded)
                    if time.monotonic() - started >= TIMEOUT:
                        raise TimeoutError(f"Python download/decode baseline exceeded {TIMEOUT}s")
            tail = decoder.flush()
            expanded += len(tail)
            sink.write(tail)
            assert decoder.eof and not decoder.unused_data, "truncated or concatenated gzip fixture"
    seconds = time.monotonic() - started
    assert expanded == expected, (expanded, expected)
    return seconds


def _native_baseline(urls: list[str], ca_path: Path) -> float:
    started = time.monotonic()
    with open(os.devnull, "wb") as sink, tempfile.TemporaryFile() as curl_errors:
        for url in urls:
            with subprocess.Popen(["curl", "--fail", "--silent", "--show-error", "--noproxy", "*",
                                   "--cacert", str(ca_path), "--max-time", str(TIMEOUT), url],
                                  stdout=subprocess.PIPE, stderr=curl_errors) as download:
                try:
                    assert download.stdout is not None
                    with subprocess.Popen(["gzip", "-dc"], stdin=download.stdout,
                                          stdout=sink, stderr=subprocess.PIPE) as decode:
                        download.stdout.close()
                        try:
                            _, errors = decode.communicate(timeout=max(0.001, TIMEOUT - (time.monotonic() - started)))
                            status = download.wait(timeout=max(0.001, TIMEOUT - (time.monotonic() - started)))
                            curl_errors.seek(0)
                            assert status == 0, curl_errors.read().decode(errors="replace")
                            assert decode.returncode == 0, errors.decode(errors="replace")
                        finally:
                            if decode.poll() is None:
                                decode.kill()
                finally:
                    if download.poll() is None:
                        download.kill()
    return time.monotonic() - started


def baseline(silo: Silo, registry: DistributionRegistry, image: CorpusImage, cohort: str,
             ) -> tuple[dict[str, float], dict[str, dict[str, Json]]]:
    urls = [f"https://{registry.address}/v2/{image.repository}/blobs/{blob['digest']}"
            for blob in image.blobs]
    expected = sum(blob["expandedBytes"] for blob in image.blobs)
    caches = {"urllib-zlib": conditioned_cache(silo, registry, cohort)}
    timings = {"urllib-zlib": _python_baseline(urls, registry.ca_path, expected)}
    caches["curl-gzip"] = conditioned_cache(silo, registry, cohort)
    timings["curl-gzip"] = _native_baseline(urls, registry.ca_path)
    return timings, caches


def assert_empty_pool(silo: Silo) -> None:
    """A warm re-prepare must never silently become a retained-lower cache hit."""
    with sqlite3.connect(f"file:{silo.ws.state_db()}?mode=ro", uri=True) as connection:
        for table in ("image_composition_artifact", "composition_result", "layer_result"):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0, table
    streams = silo.ws.silo_home / "images/streams/sha256"
    assert not list(streams.iterdir()), "prune left prepared pack streams in the pool"


def retained_inputs(silo: Silo, image: CorpusImage) -> list[Path]:
    """Exact prepared inputs for this manifest and its reusable layer diff IDs."""
    pool = silo.ws.silo_home / "images"
    objects: set[str] = set()
    streams: set[str] = set()
    with sqlite3.connect(f"file:{silo.ws.state_db()}?mode=ro", uri=True) as connection:
        for fsmeta, record, recipe in connection.execute(
            "SELECT c.fsmeta_digest,c.record_digest,p.record_digest "
            "FROM image_composition_artifact a JOIN composition_result c ON c.id=a.lower_id "
            "JOIN composition_recipe p ON p.id=c.recipe_id WHERE a.manifest_digest=?",
            (image.manifest_digest,),
        ):
            objects.update((fsmeta, record, recipe))
        for blob in image.blobs:
            objects.update(row[0] for row in connection.execute(
                "SELECT d.object_digest FROM layer_object_dependency d "
                "JOIN layer_result r ON r.id=d.result_id JOIN layer_recipe p ON p.id=r.recipe_id "
                "WHERE p.diff_id=?", (blob["diffId"],),
            ))
            streams.update(row[0] for row in connection.execute(
                "SELECT r.pack_stream FROM layer_result r JOIN layer_recipe p ON p.id=r.recipe_id "
                "WHERE p.diff_id=?", (blob["diffId"],),
            ))
    return sorted(
        [pool / "objects/sha256" / digest.removeprefix("sha256:") for digest in objects]
        + [pool / "streams/sha256" / digest.removeprefix("sha256:") for digest in streams]
        + [pool / "source-blobs/sha256" / blob["digest"].removeprefix("sha256:") for blob in image.blobs]
    )


def assert_unprepared(silo: Silo, image: CorpusImage, retired_inputs: list[Path] | None = None) -> None:
    """No selection, reusable layer result or former backing can satisfy this prepare."""
    with sqlite3.connect(f"file:{silo.ws.state_db()}?mode=ro", uri=True) as connection:
        for table in ("image_ref", "image_composition_artifact"):
            assert connection.execute(
                f"SELECT COUNT(*) FROM {table} WHERE manifest_digest=?", (image.manifest_digest,),
            ).fetchone()[0] == 0, (table, image.manifest_digest)
        for blob in image.blobs:
            assert connection.execute(
                "SELECT COUNT(*) FROM layer_result r JOIN layer_recipe p ON p.id=r.recipe_id "
                "WHERE p.diff_id=?", (blob["diffId"],),
            ).fetchone()[0] == 0, ("retained layer", blob["diffId"])
    remaining = [path for path in retained_inputs(silo, image) + (retired_inputs or []) if path.exists()]
    assert not remaining, ("prepare inputs survived image removal and prune", remaining)


def remove_prepared_image(silo: Silo, image: CorpusImage) -> None:
    """Release the OCI reference before pruning; a named selection is a GC root."""
    previous = retained_inputs(silo, image)
    with sqlite3.connect(f"file:{silo.ws.state_db()}?mode=ro", uri=True) as connection:
        referenced = connection.execute(
            "SELECT COUNT(*) FROM image_ref WHERE requested_reference=?", (image.reference,),
        ).fetchone()[0] != 0
    if referenced:
        shutdown.storage_tool(silo, "remove-image", image.reference)
    shutdown.storage_tool(silo, "prune")
    assert_unprepared(silo, image, previous)


def lower_proof(silo: Silo, payload: int) -> dict[str, Json]:
    """Record real catalog pack/index/fsmeta outputs after create has completed."""
    pool = silo.ws.silo_home / "images"
    with sqlite3.connect(f"file:{silo.ws.state_db()}?mode=ro", uri=True) as connection:
        lower = connection.execute(
            "SELECT fsmeta_digest,fsmeta_length,record_digest FROM composition_result").fetchall()
        layers = connection.execute(
            "SELECT pack_stream,pack_length,index_root,record_digest,pack_map FROM layer_result").fetchall()
    assert len(lower) == 1 and len(layers) == 2, (lower, layers)
    files: list[Json] = []
    for fsmeta, length, record in lower:
        for digest in (fsmeta, record):
            path = pool / "objects/sha256" / digest.removeprefix("sha256:")
            assert path.is_file() and path.stat().st_size > 0, path
            if digest == fsmeta:
                assert path.stat().st_size == length
            files.append({"role": "fsmeta" if digest == fsmeta else "composition", "digest": digest,
                          "logicalBytes": path.stat().st_size, "allocatedBytes": path.stat().st_blocks * 512})
    pack_bytes = 0
    for stream, length, index, result, stream_map in layers:
        path = pool / "streams/sha256" / stream.removeprefix("sha256:")
        assert path.is_file() and path.stat().st_size == length, path
        pack_bytes += length
        files.append({"role": "pack", "digest": stream, "logicalBytes": length,
                      "allocatedBytes": path.stat().st_blocks * 512})
        for role, digest in (("index", index), ("layer-result", result), ("pack-map", stream_map)):
            path = pool / "objects/sha256" / digest.removeprefix("sha256:")
            assert path.is_file() and path.stat().st_size > 0, path
            files.append({"role": role, "digest": digest, "logicalBytes": path.stat().st_size})
    assert pack_bytes >= payload, "full incompressible payload was not packed"
    return {"files": files, "packBytes": pack_bytes, "layerCount": len(layers)}


def _create(silo: Silo, image: CorpusImage, name: str) -> float:
    silo.ws.register_machine(name)
    started = time.monotonic()
    silo.run("create", image.reference, "--name", name, "--pull", "missing",
             "--disk-size", "256mib", "--network", "none", timeout=TIMEOUT)
    return time.monotonic() - started


def measure_size(silo: Silo, registry: DistributionRegistry, image: CorpusImage,
                 cohort: str, index: int) -> SizeSample:
    assert_unprepared(silo, image)
    # Corpus blobs already occupy disk. Reserve only the remaining working set.
    space = cast(dict[str, Json], headroom(silo, 3 * image.entry_bytes + 2 * GIB))
    methods, baseline_cache = baseline(silo, registry, image, cohort)
    cache = conditioned_cache(silo, registry, cohort)
    names: list[str] = []
    try:
        name = f"bi-{cohort}-{index}-{image.entry_bytes // GIB}-first"
        names.append(name)
        first = _create(silo, image, name)
        name = f"bi-{cohort}-{index}-{image.entry_bytes // GIB}-hit"
        names.append(name)
        hit = _create(silo, image, name)
        proof = lower_proof(silo, image.entry_bytes)
        prepare = first - hit
        assert prepare > 0, ("unprepared minus prepared create must be positive", first, hit)
        seconds = min(methods.values())
        expanded = sum(blob["expandedBytes"] for blob in image.blobs)
        return {"entryBytes": image.entry_bytes, "expandedBytes": expanded,
                "compressedBytes": sum(blob["size"] for blob in image.blobs), "reference": image.reference,
                "unpreparedCreateSeconds": first, "warmCreateSeconds": hit, "prepareSeconds": prepare,
                "baselineSeconds": seconds, "baselineMethods": methods, "baselineCache": baseline_cache,
                "prepareCache": cache, "coldPrepareRatio": prepare / seconds,
                "prepareSecondsPerGiB": prepare / (expanded / GIB), "lower": proof, "space": space}
    finally:
        # Creates remain stopped. Failed create may not have registered a product machine.
        existing = {str(machine["name"]) for machine in silo.ls()}
        for name in names:
            if name in existing:
                silo.rm(name)
        remove_prepared_image(silo, image)


def sample(cohort: str, index: int, sizes: list[SizeSample]) -> Sample:
    assert len(sizes) >= 2 and all(left["entryBytes"] < right["entryBytes"]
                                  for left, right in zip(sizes, sizes[1:]))
    cold = [record["prepareCache"] for record in sizes]
    cold += [cache for record in sizes for cache in record["baselineCache"].values()]
    label = "cold" if all(cache["label"] == "cold" for cache in cold) else "partial-cold"
    return {"cohort": cohort, "index": index,
            "cache": {"label": label if cohort == "cold" else "warm-observed"},
            "gates": list(TARGETS), "sizes": sizes,
            "coldPrepareRatio": max(record["coldPrepareRatio"] for record in sizes),
            "linearity": sizes[-1]["prepareSecondsPerGiB"] / sizes[0]["prepareSecondsPerGiB"]}
