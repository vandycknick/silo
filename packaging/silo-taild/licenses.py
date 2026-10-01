#!/usr/bin/env python3
"""Collect notices from the exact Go module graph, without a hand-maintained list."""
import json
from pathlib import Path
import shutil
import subprocess
import sys


def main() -> None:
    module, output = Path(sys.argv[1]), Path(sys.argv[2])
    data = subprocess.check_output(["go", "list", "-mod=readonly", "-deps", "-json", "./cmd/taild"], cwd=module, text=True)
    decoder = json.JSONDecoder()
    modules = []
    while data.strip():
        item, end = decoder.raw_decode(data.lstrip())
        if "Module" in item:
            modules.append(item["Module"])
        data = data.lstrip()[end:]
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    inventory = []
    seen = set()
    for item in modules:
        if item["Path"] in seen:
            continue
        seen.add(item["Path"])
        if item.get("Main") or item["Path"].startswith("github.com/vandycknick/silo/"):
            continue
        directory = Path(item.get("Replace", item)["Dir"])
        notices = sorted(p for p in directory.iterdir() if p.is_file() and p.name.upper().startswith(("LICENSE", "COPYING", "NOTICE")) and p.suffix.lower() not in {".go", ".rs", ".py", ".sh"})
        if not notices:
            raise RuntimeError(f"missing license material for {item['Path']} {item.get('Version', '')}")
        destination = output / item["Path"] / item.get("Version", "local")
        destination.mkdir(parents=True)
        for notice in notices:
            shutil.copyfile(notice, destination / notice.name)
        inventory.append({"module": item["Path"], "version": item.get("Version"), "notices": [str((destination / p.name).relative_to(output)) for p in notices]})
    (output / "modules.json").write_text(json.dumps(inventory, indent=2) + "\n")


if __name__ == "__main__":
    main()
