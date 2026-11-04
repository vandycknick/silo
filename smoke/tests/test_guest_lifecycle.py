from __future__ import annotations

from dataclasses import replace

import pytest

from silo_smoke import guest_lifecycle, images
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
