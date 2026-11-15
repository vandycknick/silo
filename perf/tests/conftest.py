"""Reuse the smoke fixtures, without smoke's autouse real-VM guard for unit tests."""
from __future__ import annotations

import pytest

from smoke.tests.conftest import (
    basic_image,
    config,
    incremental_image,
    pytest_collection_modifyitems,
    pytest_configure as configure_smoke,
    pytest_runtest_makereport,
    registry,
    restore_image,
    session_evidence,
    silo,
    workspace,
)
from silo_smoke.config import add_options


def pytest_addoption(parser: pytest.Parser) -> None:
    add_options(parser)
    parser.getgroup("silo smoke").addoption("--smoke-lane", choices=("parallel", "serial"), default=None)


def pytest_configure(config: pytest.Config) -> None:
    if getattr(config.option, "numprocesses", None) not in (None, 0) or hasattr(config, "workerinput"):
        raise pytest.UsageError("perf must run serially, without xdist")
    configure_smoke(config)
