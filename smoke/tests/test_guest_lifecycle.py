from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from silo_smoke import guest_activation_network, guest_lifecycle, guest_restored, images, pause, procs
from silo_smoke.cli import Silo
from silo_smoke.config import SmokeConfig
from silo_smoke.registry import LoopbackRegistry

pytestmark = pytest.mark.linux_only


def test_freeze_real_kernel_counter_epochs_and_lost_thaw(silo: Silo, basic_image: str) -> None:
    """Actual cgroup events/counter/status, never native pause or restore evidence."""
    guest_lifecycle.run(silo, basic_image)


@pytest.fixture(scope="session")
def image_owned_lifecycle_init(config: SmokeConfig, registry: LoopbackRegistry) -> str:
    spec = replace(images.BASIC, name="guest-freezer-image-init", remove=frozenset(), files={
        **images.BASIC.files,
        "sbin/init": images.GuestFile(b"#!/bin/sh\nwhile :; do sleep 1; done\n", mode=0o755),
    })
    return registry.publish(images.build(spec, images.fetch_alpine(config.cache_dir)), "guest-freezer-image-init")


def test_freeze_refuses_uncontained_image_init_before_effects(silo: Silo, image_owned_lifecycle_init: str) -> None:
    guest_lifecycle.run(silo, image_owned_lifecycle_init, unsupported=True)


def test_pause_rejects_uncontained_guest_before_operation(silo: Silo, image_owned_lifecycle_init: str) -> None:
    name = "pause-uncontained"
    silo.create(name, image_owned_lifecycle_init, "--cpus", "1", "--memory", "512mib", "--vsock", "--network", "none")
    silo.start(name)
    running = silo.wait_ready(name)
    assert running["guest"]["boot"]["agent_is_pid1"] is False
    capability = running["lifecycle"]["report"]["live"]["pause"]
    assert capability["availability"]["status"] == "unsupported", capability
    assert capability["availability"]["reason"]["code"] == "device-profile-rejected", capability
    before = procs.query(silo.ws.state_db(), "SELECT COUNT(*) FROM live_command")
    counter = pause.Counter(silo, name)
    try:
        counter.advances()
        refused = silo.run("pause", name, expect=None)
        assert refused.returncode != 0
        counter.advances()
        after = silo.info(name)
        assert after["state"] == "running" and after["run_id"] == running["run_id"]
        assert after["lifecycle"]["lifecycle"]["currentPause"] is None
        assert procs.query(silo.ws.state_db(), "SELECT COUNT(*) FROM live_command") == before
    finally:
        counter.close()
        silo.stop(name)


@pytest.fixture(scope="session")
def activation_probe(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Static guest netlink/gateway probe, built by the existing host compiler (set CC if needed)."""
    return guest_activation_network.compile_probe(tmp_path_factory.mktemp("activation-probe") / "guest-activation-network")


@pytest.fixture(scope="session")
def activation_image(config: SmokeConfig, registry: LoopbackRegistry, activation_probe: Path) -> str:
    spec = replace(images.BASIC, name="guest-activation", files={
        **images.BASIC.files,
        guest_restored.PROBE.lstrip("/"): images.GuestFile(activation_probe.read_bytes(), mode=0o755),
    })
    return registry.publish(images.build(spec, images.fetch_alpine(config.cache_dir)), "guest-activation")


def test_activation_restored_generation_two_children(silo: Silo, activation_image: str, activation_probe: Path) -> None:
    """Real Silo source freeze, one native cut, two sequential fenced children: exact generation
    ACK, guest Activate/replay, destination Thaw, then provider fence release and wire oracles."""
    report = guest_restored.run(silo, activation_image, "positive", activation_probe)
    assert report["status"] == "passed" and len(report["children"]) == 2, report["evidence"]


@pytest.mark.slow
def test_activation_restored_failures_stay_frozen_and_fenced(silo: Silo, activation_image: str,
                                                             activation_probe: Path) -> None:
    """Fresh children: listener conflict, failing/timeout/background-descendant hooks,
    lost Activate reply replay and lost destination Thaw with a real next-epoch freeze."""
    report = guest_restored.run(silo, activation_image, "failures", activation_probe)
    assert set(report["children"]) == {"hook-exit", "hook-timeout", "hook-descendant", "listener-conflict",
                                       "lost-activation-reply", "lost-thaw"}, report["evidence"]


@pytest.mark.slow
def test_activation_restored_network_topology_refused(silo: Silo, activation_image: str,
                                                      activation_probe: Path) -> None:
    """Captured unsupported alias: presence mismatch rejects before effects, then a valid
    Activate fails sticky in the production topology check and the child stays fenced."""
    report = guest_restored.run(silo, activation_image, "topology", activation_probe)
    assert "network-topology" in report["children"], report["evidence"]
