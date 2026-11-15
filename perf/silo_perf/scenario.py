from __future__ import annotations

import time

from silo_perf.drivers import Action, Driver

# Declaration order is the bench2 procedure, shared by every competitor.
SCENARIO = tuple(Action)


def sample(driver: Driver) -> dict[str, float]:
    measurements: dict[str, float] = {}
    failure: BaseException | None = None
    try:
        driver.prepare()
        for action in SCENARIO:
            if action == Action.FORK_FIRST:
                time.sleep(3)
            if action == Action.SNAPSHOT_FULL:
                driver.remove_fork_sources()
                driver.prepare_snapshots()
                time.sleep(3)
            measurements.update(driver.measure(action))
            if action == Action.EXEC:
                driver.populate_source()
    except BaseException as error:
        failure = error
    try:
        driver.cleanup()
    except BaseException as error:
        if failure is not None:
            raise BaseExceptionGroup("benchmark and cleanup failed", [failure, error])
        raise
    if failure is not None:
        raise failure
    return measurements
