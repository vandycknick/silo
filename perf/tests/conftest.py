"""Reuse the smoke fixtures, without smoke's autouse real-VM guard for unit tests."""
from __future__ import annotations

import os

import pytest

from smoke.tests.conftest import (
    basic_image,
    config,
    incremental_image,
    pytest_configure as configure_smoke,
    pytest_runtest_makereport,
    registry,
    restore_image,
    session_evidence,
    silo,
    skip_unavailable,
    workspace,
)
from silo_smoke.config import add_options


def pytest_addoption(parser: pytest.Parser) -> None:
    add_options(parser)
    parser.getgroup("silo smoke").addoption("--smoke-lane", choices=("parallel", "serial"), default=None)


def pytest_configure(config: pytest.Config) -> None:
    if getattr(config.option, "numprocesses", None) not in (None, 0) or hasattr(config, "workerinput"):
        raise pytest.UsageError("perf must run serially, without xdist")
    if os.environ.get("PROFILE") != "release":
        raise pytest.UsageError("perf measures only fresh release builds; run it through `make perf`")
    configure_smoke(config)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    skip_unavailable(config, items)
