"""Actual CLI descendants for child-only capture crash boundary tracing.

The parent controls when capture starts and when normal stop runs over stdin.
No production state, syscall return, seal or capability is synthesized here.
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

    def record(name: str, value: object) -> None:
        target = evidence / name
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(json.dumps(value, sort_keys=True) + "\n")
        temporary.replace(target)

    started = subprocess.run([silo, "start", name], capture_output=True, text=True, timeout=90)
    record("capture-traced-start.json", {"code": started.returncode, "stdout": started.stdout,
                                        "stderr": started.stderr})
    assert started.returncode == 0, started.stderr
    assert sys.stdin.readline().strip() == "capture", "expected capture command"
    with (evidence / "capture-manager.stdout").open("wb") as output, \
            (evidence / "capture-manager.stderr").open("wb") as errors:
        process = subprocess.Popen(
            [silo, "snapshot", "create", name, "--live", "--name", "crash-captured",
             *(["--preserve"] if request["preserve"] else [])],
            stdout=output, stderr=errors,
        )
        record("capture-manager-process.json", {"pid": process.pid})
        try:
            code = process.wait(timeout=180)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
        record("capture-manager-result.json", {"code": code})
    assert sys.stdin.readline().strip() == "stop", "expected stop command"
    stopped = subprocess.run([silo, "stop", name], capture_output=True, text=True, timeout=60)
    record("capture-traced-stop.json", {"code": stopped.returncode, "stdout": stopped.stdout,
                                       "stderr": stopped.stderr})


if __name__ == "__main__":
    main()
