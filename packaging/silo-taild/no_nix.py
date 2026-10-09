#!/usr/bin/env python3
"""Run a native command in a rootless private mount namespace with /nix hidden."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command and command[0] == "--": command = command[1:]
    if not command: parser.error("native command required")
    if args.child:
        if Path("/nix").exists():
            subprocess.run(["/usr/bin/mount", "-n", "--bind", str(args.child), "/nix"], check=True)
        if Path("/nix/store").exists(): raise RuntimeError("Nix store is still accessible")
        env = {k: v for k, v in os.environ.items() if not k.startswith(("LD_", "DYLD_"))}
        os.execve(command[0], command, env)
    with tempfile.TemporaryDirectory(prefix="silo-no-nix-") as empty:
        result = subprocess.run(["/usr/bin/unshare", "--user", "--map-current-user", "--mount", "--keep-caps", "--propagation", "private", "/usr/bin/python3", str(Path(__file__).resolve()), "--child", empty, "--", *command])
        sys.exit(result.returncode)


if __name__ == "__main__":
    main()
