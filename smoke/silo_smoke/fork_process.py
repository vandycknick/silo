"""Actual CLI descendants for child-only live-fork boundary tracing.

Run under `silo_smoke.stopped_trace`: the source start and the real
`silo fork --live` manager (with every child monitor/worker it launches) are
traced descendants. The parent controls when the fork starts and when the
source stops over stdin. Nothing here synthesizes a result, seal or state.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


def main() -> None:
    request = json.loads(Path(sys.argv[1]).read_text())
    evidence = Path(request["evidence"])
    silo = request["silo"]
    name = request["name"]

    def record(filename: str, value: object) -> None:
        target = evidence / filename
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(json.dumps(value, sort_keys=True) + "\n")
        temporary.replace(target)

    started = subprocess.run([silo, "start", name], capture_output=True, text=True, timeout=90)
    record("fork-traced-start.json", {"code": started.returncode, "stdout": started.stdout,
                                     "stderr": started.stderr})
    assert started.returncode == 0, started.stderr
    assert sys.stdin.readline().strip() == "fork", "expected fork command"
    with (evidence / "fork-manager.stdout").open("wb") as output, \
            (evidence / "fork-manager.stderr").open("wb") as errors:
        process = subprocess.Popen([silo, *request["fork"]], stdout=output, stderr=errors)
        record("fork-manager-process.json", {"pid": process.pid})
        try:
            code = process.wait(timeout=600)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
        # A negative code is the actual signal that ended the manager.
        record("fork-manager-result.json", {"code": code})
    assert sys.stdin.readline().strip() == "stop", "expected stop command"
    stopped = subprocess.run([silo, "stop", name], capture_output=True, text=True, timeout=60)
    record("fork-traced-stop.json", {"code": stopped.returncode, "stdout": stopped.stdout,
                                    "stderr": stopped.stderr})


if __name__ == "__main__":
    main()
