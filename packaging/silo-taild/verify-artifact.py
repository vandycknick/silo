#!/usr/bin/env python3
"""Native offline acceptance using the shipped executable and isolated state."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
from elf_audit import audit, loader_command, loader_for


def extract(archive: Path, destination: Path) -> Path:
    with subprocess.Popen(["zstd", "-dc", str(archive)], stdout=subprocess.PIPE) as process:
        with tarfile.open(fileobj=process.stdout, mode="r|") as tar:
            tar.extractall(destination, filter="data")
        if process.wait() != 0:
            raise RuntimeError("archive decompression failed")
    roots = list(destination.iterdir())
    if len(roots) != 1 or not roots[0].is_dir():
        raise RuntimeError("expected one archive root")
    return roots[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("portable", type=Path)
    parser.add_argument("runtime", type=Path)
    parser.add_argument("--audit-only", action="store_true", help="audit existing archive snapshots and execute helpers/version, without installation or VM boot")
    parser.add_argument("--require-no-nix", action="store_true", help="require rootless mount isolation with /nix hidden")
    args = parser.parse_args()
    portable, runtime = (p.resolve(strict=True) for p in (args.portable, args.runtime))
    with tempfile.TemporaryDirectory(prefix="silo-packaged-acceptance-") as temporary:
        root = Path(temporary)
        package = extract(portable, root / "package")
        expected = extract(runtime, root / "runtime")
        manifest_path = expected / "runtime-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        actual_files = {str(p.relative_to(expected)): hashlib.sha256(p.read_bytes()).hexdigest() for p in expected.rglob("*") if p.is_file() and not p.is_symlink() and p != manifest_path}
        if manifest["files"] != actual_files:
            raise RuntimeError("archive component inventory/digest mismatch")
        for directory in ("home", "secrets", "templates", "policies"):
            (root / directory).mkdir(mode=0o700)
        environment = {key: value for key, value in os.environ.items() if not key.startswith(("SILO_", "TS_", "LD_", "DYLD_"))}
        environment.pop("GODEBUG", None)
        environment.update(HOME=str(root / "home"), XDG_CACHE_HOME=str(root / "home/cache"), XDG_DATA_HOME=str(root / "home/data"))
        config = root / "config.yaml"
        settings = {"home": str(root / "home"), "secrets_dir": str(root / "secrets"), "templates_dir": str(root / "templates"), "policies_dir": str(root / "policies"), "runtime_archive": str(runtime), "install_root": str(root / "installed"), "enrollment": {"mode": "none"}}
        config.write_text(json.dumps(settings))  # JSON is a YAML subset.
        binary = package / "bin/taild"
        target = manifest["target"]
        loader = loader_for(target)
        elfs = {p: audit(p, target) for p in (*((package / "bin").iterdir()), *((expected / "bin").iterdir()), expected / "assets/agent")}
        isolation = ["/usr/bin/python3", str(Path(__file__).with_name("no_nix.py")), "--"]
        probe = subprocess.run([*isolation, "/usr/bin/true"], capture_output=True, text=True)
        isolated = probe.returncode == 0
        if args.require_no_nix and not isolated:
            raise RuntimeError("required rootless /nix isolation unavailable: " + probe.stderr)
        print("Rootless /nix isolation: " + ("enabled" if isolated else "UNQUALIFIED, unavailable: " + probe.stderr.strip()))

        def invoke(path: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
            command = loader_command(loader, path, *arguments) if elfs.get(path, None) is None or elfs[path].interpreter else [str(path), *arguments]
            if isolated: command = [*isolation, *command]
            return subprocess.run(command, env=environment, text=True, capture_output=True, timeout=90)

        for helper in (package / "bin/silo-vmm", package / "bin/netd"):
            # silo-vmm has no version flag; --help loads/executes the real supervisor.
            result = invoke(helper, "--help")
            netd_help = helper.name == "netd" and result.returncode == 1 and result.stderr.strip() == '{"type":"startup_error","message":"flag: help requested"}'
            if result.returncode != 0 and not netd_help: raise RuntimeError(f"actual helper execution failed: {helper.name}: {result.stderr}")
            print(f"Actual helper {helper.name} --help: passed ({'Nix hidden' if isolated else 'designated native loader'})")

        def run(*args: str, succeeds: bool = True) -> None:
            result = invoke(binary, *args)
            if (result.returncode == 0) != succeeds:
                raise RuntimeError(f"{args}: unexpected exit {result.returncode}\n{result.stdout}\n{result.stderr}")
            print(f"{args}: exit {result.returncode}")
            print(result.stdout, end="")
            print(result.stderr, end="")
            if succeeds and args[0] == "version":
                abi = re.search(r"ABI expected (\d+) verified (\d+)", result.stdout)
                if "SDK " + manifest["version"] not in result.stdout or abi is None or abi[1] != abi[2] or int(abi[1]) == 0:
                    raise RuntimeError("version output did not verify the expected numeric ABI/product version")

        run("version", "--config", str(config))
        bridges = list((root / "home").rglob("libsilo_go_ffi.so"))
        if len(bridges) != 1: raise RuntimeError("expected exactly one materialized embedded native bridge")
        audit(bridges[0], target)
        if args.audit_only:
            print("PASS: existing archive native closures and real helper/embedded-bridge execution; VM boot not tested")
            return
        run("install-runtime", "--config", str(config))
        run("--check", "--config", str(config))
        run("version", "--config", str(config))
        # Explicit runtime roots must receive the same version/inventory validation.
        settings["runtime_root"] = str(expected)
        config.write_text(json.dumps(settings))
        run("--check", "--config", str(config))
        original = manifest_path.read_bytes()
        for mutation in ("version", "digest", "path"):
            changed = json.loads(original)
            if mutation == "version":
                changed["version"] = "999.0.0"
            elif mutation == "digest":
                changed["files"]["assets/agent"] = "0" * 64
            else:
                changed["files"]["../outside"] = "0" * 64
            manifest_path.write_text(json.dumps(changed))
            run("--check", "--config", str(config), succeeds=False)
        manifest_path.write_bytes(original)
        damaged = root / "damaged.tar.zst"
        damaged.write_bytes(runtime.read_bytes() + b"corrupted")
        settings.pop("runtime_root")
        settings["runtime_archive"] = str(damaged)
        settings["install_root"] = str(root / "negative-install")
        config.write_text(json.dumps(settings))
        run("install-runtime", "--config", str(config), succeeds=False)
        print("PASS: packaged embedded bridge, offline installation, version/hash/path rejection")


if __name__ == "__main__":
    main()
