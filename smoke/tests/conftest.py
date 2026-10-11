from __future__ import annotations

from collections.abc import Generator
import platform

from pluggy import Result
import pytest

from silo_smoke import config as smoke_config, image_cache, images, preflight
from silo_smoke.cli import Silo, Vm
from silo_smoke.config import SmokeConfig
from silo_smoke.daemon import Silod
from silo_smoke.errors import SmokeEnvironmentError
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.workspace import Workspace


_LIVE_MARK = pytest.StashKey[preflight.LiveDaemonMark | None]()
_FAILED = pytest.StashKey[bool]()


def pytest_addoption(parser: pytest.Parser) -> None:
    smoke_config.add_options(parser)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> Generator[None, Result[pytest.TestReport], None]:
    outcome = yield
    report = outcome.get_result()
    if report.when in {"setup", "call"}:
        item.stash[_FAILED] = item.stash.get(_FAILED, False) or report.failed


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    system = platform.system()
    try:
        system_image = smoke_config.resolve(config).system_image
    except SmokeEnvironmentError:
        system_image = None
    for item in items:
        if item.get_closest_marker("linux_only") and system != "Linux":
            item.add_marker(pytest.mark.skip(reason="requires Linux"))
        if item.get_closest_marker("macos_only") and system != "Darwin":
            item.add_marker(pytest.mark.skip(reason="requires macOS"))
        if item.get_closest_marker("system") and system_image is None:
            item.add_marker(pytest.mark.skip(reason="SILO_SMOKE_SYSTEM_IMAGE is empty"))
        if item.get_closest_marker("live") and "live" not in config.getoption("-m"):
            item.add_marker(pytest.mark.skip(reason="select -m live to run internet-dependent tests"))


@pytest.fixture(scope="session")
def config(pytestconfig: pytest.Config) -> SmokeConfig:
    try:
        resolved = smoke_config.resolve(pytestconfig)
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
def basic_image(config: SmokeConfig, registry: LoopbackRegistry) -> str:
    return registry.publish(images.build(images.BASIC, images.fetch_alpine(config.cache_dir)), "basic")


@pytest.fixture
def workspace(config: SmokeConfig, registry: LoopbackRegistry, request: pytest.FixtureRequest) -> Generator[Workspace, None, None]:
    instance = Workspace(config, registry.ca_path)
    try:
        yield instance
    finally:
        instance.cleanup(failed=request.node.stash.get(_FAILED, False))


@pytest.fixture
def silo(workspace: Workspace) -> Silo:
    return Silo(workspace)


@pytest.fixture
def vm(silo: Silo, basic_image: str) -> Generator[Vm, None, None]:
    name = "smoke-vm"
    silo.create(name, basic_image, "--cpus", "1", "--memory", "512mb", "--vsock", "--network", "none")
    silo.start(name)
    silo.wait_ready(name)
    yield Vm(name, silo.machine_id(name))


@pytest.fixture
def daemon(workspace: Workspace) -> Silod:
    return Silod(workspace)


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
