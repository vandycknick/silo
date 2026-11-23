from __future__ import annotations

import time

from silo_perf.drivers import Action, Driver

# Declaration order is shared by every competitor, including untimed conditioning.
SCENARIO = tuple(Action)


def sample(driver: Driver) -> dict[str, float]:
    measurements: dict[str, float] = {}
    failure: BaseException | None = None
    try:
        driver.prepare()
        for action in SCENARIO:
            if action == Action.FORK_FIRST:
                time.sleep(3)
            if action == Action.FORK_SECOND:
                driver.rewrite_source(snapshot=False)
            if action == Action.SNAPSHOT_FULL:
                driver.remove_fork_sources()
                driver.prepare_snapshots()
                driver.before_snapshot()
                time.sleep(3)
            if action == Action.SNAPSHOT_INCREMENTAL:
                driver.rewrite_source(snapshot=True)
                driver.before_snapshot()
            if action == Action.SNAPSHOT_SOURCE_AFTER_FORKS:
                driver.prepare_fork_snapshots()
            measurements.update(driver.measure(action))
            if action == Action.EXEC:
                driver.populate_source()
            if action == Action.SNAPSHOT_INCREMENTAL:
                driver.after_snapshot()
            if action in (Action.RESTORE_FIRST_EXEC, Action.RESTORE_SECOND_EXEC):
                driver.check_restore(action)
            if action == Action.RESTORE_SECOND_EXEC:
                driver.check_fork()
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
