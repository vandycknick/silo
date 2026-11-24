from __future__ import annotations

from collections.abc import Generator, Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import platform
import os
import tempfile

from pluggy import Result
import pytest

from silo_smoke import areas, cloud_disk, config as smoke_config, image_cache, images, incremental, overlay, preflight, prereqs, restore, stopped
from silo_smoke.cli import TIMINGS_PROPERTY, Silo, Vm, release, timed
from silo_smoke.config import SmokeConfig
from silo_smoke.daemon import Daemon
from silo_smoke.errors import SmokeEnvironmentError
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.workspace import Workspace
from silo_smoke.cloud_disk import Roots


_LIVE_MARK = pytest.StashKey[preflight.LiveDaemonMark | None]()
_FAILED = pytest.StashKey[bool]()


def pytest_addoption(parser: pytest.Parser) -> None:
    smoke_config.add_options(parser)
    group = parser.getgroup("silo smoke")
    group.addoption("--smoke-lane", choices=("parallel", "serial"), default=None)
    group.addoption("--area", action="append", default=[], choices=sorted(areas.AREAS),
                    help="run only this smoke area (repeatable); see silo_smoke/areas.py")


def pytest_configure(config: pytest.Config) -> None:
    if "SILO_SMOKE_EVIDENCE" not in os.environ:
        os.environ["SILO_SMOKE_EVIDENCE"] = tempfile.mkdtemp(prefix="run-", dir=prereqs.evidence_parent())
    for name, area in areas.AREAS.items():
        config.addinivalue_line("markers", f"{name}: {area.description}")
    lane = config.getoption("--smoke-lane")
    if lane is not None:
        selection = config.option.markexpr
        exclusive = "serial" if lane == "serial" else "not serial"
        config.option.markexpr = f"({selection}) and {exclusive}" if selection else exclusive
        if config.option.xmlpath:
            path = Path(config.option.xmlpath)
            config.option.xmlpath = str(path.with_name(f"{path.stem}-{lane}{path.suffix}"))
    if config.option.basetemp is None or hasattr(config, "workerinput"):
        # Fixture roots and probes are large: keep them off RAM-backed /tmp.
        config.option.basetemp = tempfile.mkdtemp(prefix="ss-", dir=prereqs.workspace_parent())


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> Generator[None, Result[pytest.TestReport], None]:
    outcome = yield
    report = outcome.get_result()
    if report.when in {"setup", "call"}:
        item.stash[_FAILED] = item.stash.get(_FAILED, False) or report.failed


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    selected_areas = set(config.getoption("--area"))
    selected, deselected = [], []
    for item in items:
        module = item.path.stem
        item_areas = areas.areas_of(module)
        if not item_areas:
            raise pytest.UsageError(f"{module} belongs to no smoke area; add it in smoke/silo_smoke/areas.py")
        for name in item_areas:
            item.add_marker(name)
        (selected if not selected_areas or selected_areas.intersection(item_areas) else deselected).append(item)
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = selected
    skip_unavailable(config, items)


def skip_unavailable(config: pytest.Config, items: list[pytest.Item]) -> None:
    system = platform.system()
    try:
        system_image = smoke_config.resolve(config).system_image
    except SmokeEnvironmentError:
        system_image = None
    for item in items:
        linux_only = item.get_closest_marker("linux_only")
        if linux_only and system != "Linux":
            item.add_marker(pytest.mark.skip(reason=linux_only.kwargs.get("reason", "requires Linux")))
        if item.get_closest_marker("macos_only") and system != "Darwin":
            item.add_marker(pytest.mark.skip(reason="requires macOS"))
        if item.get_closest_marker("system") and system_image is None:
            item.add_marker(pytest.mark.skip(reason="SILO_SMOKE_SYSTEM_IMAGE is empty"))


@pytest.fixture(scope="session")
def config(pytestconfig: pytest.Config) -> SmokeConfig:
    try:
        resolved = smoke_config.resolve(pytestconfig)
        if not hasattr(pytestconfig, "workerinput"):
            preflight.sweep_orphans()
        pytestconfig.stash[_LIVE_MARK] = preflight.check(resolved)
    except SmokeEnvironmentError as error:
        pytest.fail(str(error), pytrace=False)
    return resolved


@pytest.fixture(scope="session", autouse=True)
def live_guard(config: SmokeConfig, pytestconfig: pytest.Config) -> Generator[None, None, None]:
    mark = pytestconfig.stash[_LIVE_MARK]
    yield
    assert preflight.live_daemon_unchanged(mark), f"The live daemon socket changed during smoke: {mark}"


@pytest.fixture(scope="session")
def registry(config: SmokeConfig) -> Generator[LoopbackRegistry, None, None]:
    instance = LoopbackRegistry(config.cache_dir)
    instance.start()
    try:
        yield instance
    finally:
        instance.stop()


@pytest.fixture(scope="session")
def session_evidence(config: SmokeConfig, registry: LoopbackRegistry) -> Generator[Workspace, None, None]:
    """Keep one immutable-preparation evidence tree per worker, including successes."""
    evidence = Workspace(replace(config, keep=True), registry.address, registry.ca_path)
    evidence.record("worker", os.environ.get("PYTEST_XDIST_WORKER", "main") + "\n")
    try:
        yield evidence
    finally:
        evidence.cleanup(failed=False)


@pytest.fixture(scope="session")
def basic_image(config: SmokeConfig, registry: LoopbackRegistry) -> str:
    return registry.publish(images.build(images.BASIC, images.fetch_alpine(config.cache_dir)), "basic")


@pytest.fixture(scope="session")
def cloud_roots(config: SmokeConfig, registry: LoopbackRegistry, tmp_path_factory: pytest.TempPathFactory, request: pytest.FixtureRequest,
                session_evidence: Workspace) -> Roots:
    directory = tmp_path_factory.mktemp("phase17-roots")
    base = images.fetch_alpine(config.cache_dir)
    preparation = Workspace(config, registry.address, registry.ca_path)
    prepared: dict[str, Path] = {}
    try:
        silo = Silo(preparation)
        for identity in ("root", "clone"):
            reference = registry.publish(images.build(cloud_disk.root_image_spec(identity), base), f"phase17-{identity}")
            name = f"phase17-prepare-{identity}"
            silo.create(name, silo.raw_image(reference), "--disk-size", "512mib", "--network", "none")
            record = stopped.record(silo, name)
            assert record["root"]["kind"] == "opaque-raw" and record["root"]["layout"] == {"kind": "whole-disk"}, record["root"]
            output = cloud_disk.sparse_clone(cloud_disk.root_disk(silo, name), directory / f"{identity}.ext4")
            cloud_disk.e2fsck_clean(output)
            assert cloud_disk.debugfs_cat(output, cloud_disk.IDENTITY) == identity.encode() + b"\n"
            assert cloud_disk.debugfs_cat(output, cloud_disk.PROBE) == cloud_disk.PROBE_SCRIPT
            prepared[identity] = output
    finally:
        release(preparation, failed=len(prepared) != 2 or request.session.testsfailed > 0,
                publish=lambda summary: session_evidence.record(f"{TIMINGS_PROPERTY}-prepare-phase17-roots", summary + "\n"))
    return Roots(prepared["root"], prepared["clone"])


CONVERTED_DEFAULTS = {
    "Entrypoint": ["/bin/sleep"], "Cmd": ["3600"],
    "Env": ["PATH=/usr/sbin:/usr/bin:/sbin:/bin", "PHASE17_CONVERTED=exact value"],
    "WorkingDir": "/srv", "User": "root",
}


@pytest.fixture(scope="session")
def convert_image(config: SmokeConfig, registry: LoopbackRegistry) -> tuple[str, images.OciImage]:
    image = cloud_disk.with_process_defaults(images.build(cloud_disk.root_image_spec("root"), images.fetch_alpine(config.cache_dir)), CONVERTED_DEFAULTS)
    return registry.publish(image, "phase17-convert"), image


@pytest.fixture(scope="session")
def ca_trust_image(config: SmokeConfig, registry: LoopbackRegistry) -> str:
    return registry.publish(images.build(images.CA_TRUST, images.fetch_alpine(config.cache_dir)), "ca-trust")


@pytest.fixture(scope="session")
def restore_image(config: SmokeConfig, registry: LoopbackRegistry, tmp_path_factory: pytest.TempPathFactory) -> str:
    return restore.restore_image(config, registry, tmp_path_factory)


@pytest.fixture(scope="session")
def incremental_image(config: SmokeConfig, registry: LoopbackRegistry, tmp_path_factory: pytest.TempPathFactory) -> str:
    return incremental.incremental_image(config, registry, tmp_path_factory)


@pytest.fixture(scope="session")
def overlay_probe(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return overlay.compile_probe(tmp_path_factory.mktemp("overlay-probe") / "probe")


@pytest.fixture(scope="session")
def overlay_image_bytes(config: SmokeConfig, overlay_probe: Path) -> images.OciImage:
    """Share only immutable OCI fixture bytes, never a machine or private Home."""
    return overlay.image(config, overlay_probe)


@contextmanager
def _prepared_image_catalogs(config: SmokeConfig, registry: LoopbackRegistry, request: pytest.FixtureRequest, session_evidence: Workspace, references: dict[str, str]) -> Iterator[dict[str, Path]]:
    """Prepare image-only catalogs via explicit conversion, without boot admission."""
    preparations: list[tuple[str, Workspace]] = []
    caches: dict[str, Path] = {}
    prepared = False
    try:
        for name, reference in references.items():
            preparation = Workspace(config, registry.address, registry.ca_path)
            preparations.append((name, preparation))
            with timed(preparation, "image_cache.prepare"):
                Silo(preparation).raw_image(reference)
                cache = preparation.root / "prepared-images"
                assert image_cache.persist(cache, preparation.silo_home)
            caches[name] = cache
        prepared = True
        yield caches
    finally:
        for name, preparation in reversed(preparations):
            release(preparation, failed=not prepared or request.session.testsfailed > 0, publish=lambda summary, name=name: session_evidence.record(f"{TIMINGS_PROPERTY}-prepare-{name}", summary + "\n"))


@pytest.fixture(scope="session")
def overlay_image_caches(config: SmokeConfig, registry: LoopbackRegistry, overlay_image_bytes: images.OciImage, request: pytest.FixtureRequest, session_evidence: Workspace) -> Generator[dict[str, Path], None, None]:
    """Separate references/catalogs, so neither adds a retention root to the other."""
    references = {name: registry.publish(overlay_image_bytes, name) for name in ("overlay", "stopped")}
    with _prepared_image_catalogs(config, registry, request, session_evidence, references) as caches:
        yield caches


@pytest.fixture(scope="session")
def basic_image_cache(config: SmokeConfig, registry: LoopbackRegistry, basic_image: str, request: pytest.FixtureRequest, session_evidence: Workspace) -> Generator[Path, None, None]:
    """BASIC-only catalog for the common `vm` fixture; never merged with other caches."""
    with _prepared_image_catalogs(config, registry, request, session_evidence, {"basic": basic_image}) as caches:
        yield caches["basic"]


@pytest.fixture
def workspace(config: SmokeConfig, registry: LoopbackRegistry, request: pytest.FixtureRequest) -> Generator[Workspace, None, None]:
    instance = Workspace(config, registry.address, registry.ca_path)
    try:
        yield instance
    finally:
        release(instance, failed=request.node.stash.get(_FAILED, False), publish=lambda summary: request.node.user_properties.append((TIMINGS_PROPERTY, summary)))


@pytest.fixture
def silo(workspace: Workspace) -> Silo:
    return Silo(workspace)


@pytest.fixture
def vm(silo: Silo, basic_image: str, basic_image_cache: Path) -> Generator[Vm, None, None]:
    # Seed only this fixture's fresh Home. Create, boot and readiness stay real
    # and private; acquisition coverage lives in unseeded lifecycle/cache tests.
    with timed(silo.ws, "image_cache.seed"):
        seeded = image_cache.seed(basic_image_cache, silo.ws.silo_home)
    assert seeded == {basic_image}, seeded
    silo.ws.record("image-cache", f"seeded session-prepared BASIC image: {sorted(seeded)}\n")
    name = "smoke-vm"
    silo.create(name, basic_image, "--cpus", "1", "--memory", "512mb", "--vsock", "--network", "none")
    silo.start(name)
    ready = silo.wait_ready(name)
    yield Vm(name, str(ready["id"]))


@pytest.fixture
def daemon(workspace: Workspace) -> Daemon:
    return Daemon(workspace)


@pytest.fixture
def pulled_images(workspace: Workspace, config: SmokeConfig) -> Generator[None, None, None]:
    """Seed the workspace with previously pulled published images and keep what it pulls."""
    seeded = image_cache.seed(config.cache_dir, workspace.silo_home)
    workspace.record("image-cache", f"seeded {len(seeded)} cached tag(s) from {config.cache_dir}\n")
    try:
        yield
    finally:
        if image_cache.persist(config.cache_dir, workspace.silo_home):
            workspace.record("image-cache", f"persisted new pulls to {config.cache_dir}\n")
