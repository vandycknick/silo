#!/usr/bin/env python3
"""Native integrated acceptance; blocked enrollment is NOT live-tailnet proof."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

sys.dont_write_bytecode = True
from elf_audit import audit


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract(archive, destination):
    with subprocess.Popen(["zstd", "-dc", str(archive)], stdout=subprocess.PIPE) as process:
        with tarfile.open(fileobj=process.stdout, mode="r|") as tar:
            tar.extractall(destination, filter="data")
        if process.wait() != 0:
            raise RuntimeError("archive decompression failed")
    roots = list(destination.iterdir())
    if len(roots) != 1 or not roots[0].is_dir():
        raise RuntimeError("expected one archive root")
    return roots[0].resolve()


def checked(command, **kwargs):
    result = subprocess.run([str(v) for v in command], capture_output=True, text=True, timeout=240, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{command}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def provenance(archive, root):
    data = json.loads(archive.with_name(archive.name.removesuffix(".tar.zst") + ".provenance.json").read_text())
    if data["archive"]["sha256"] != digest(archive):
        raise RuntimeError("archive provenance digest mismatch")
    for name, sha in data["file_hashes"].items():
        path = root / name
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root) or digest(path) != sha:
            raise RuntimeError(f"provenance component mismatch: {name}")
    return data


def assert_no_sdk(home):
    for path in home.rglob("*"):
        if path.name.startswith("libsilo_go_ffi") or path.name == "runtime-manifest.json" or path.name in ("runtimes", "bundles"):
            raise RuntimeError(f"unexpected SDK installation/materialization: {path}")


def signature(path):
    checked(["codesign", "--verify", "--strict", path])
    result = subprocess.run(["codesign", "-d", "--verbose=4", str(path)], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return result.stderr


def signed_app(app, reference, version):
    if app.stat().st_mode & 0o7777 != 0o755:
        raise RuntimeError("published app directory must have mode 0755")
    data = json.loads(app.with_name("Silo.app.provenance.json").read_text())
    if data["version"] != version or data["schema"] != "https://silo.dev/app-provenance/v1":
        raise RuntimeError("signed app provenance identity mismatch")
    outer = signature(app)
    team = data["signing"]["team_identifier"]
    actual = {str(path.relative_to(app)) for path in app.rglob("*") if path.is_file()}
    if actual != set(data["files"]):
        raise RuntimeError("signed app provenance inventory mismatch")
    def certificate(path):
        if data["signing"]["ad_hoc"]:
            if "Signature=adhoc" not in signature(path):
                raise RuntimeError("provenance claims ad-hoc but signature differs")
            return None
        with tempfile.TemporaryDirectory(prefix="silo-signature-") as temporary:
            prefix = Path(temporary) / "certificate"
            checked(["codesign", "-d", "--extract-certificates=" + str(prefix), path])
            return digest(Path(str(prefix) + "0"))
    if certificate(app) != data["signing"]["certificate_sha256"]:
        raise RuntimeError("outer certificate differs from signed provenance")
    for name, sha in data["files"].items():
        path = app / name
        if not path.resolve().is_relative_to(app) or path.is_symlink() or digest(path) != sha:
            raise RuntimeError(f"signed app digest mismatch: {name}")
    required = ["Contents/MacOS/silo"] + ["Contents/Helpers/" + name for name in ("silod", "taild", "libsilo_go_ffi.dylib", "silo-vmm", "netd")]
    for name in required:
        if name not in data["files"]:
            raise RuntimeError(f"missing signed app provenance component: {name}")
        details = signature(app / name)
        if certificate(app / name) != data["signing"]["certificate_sha256"]:
            raise RuntimeError("nested certificate differs from product")
        expected_mode = 0o644 if name.endswith(".dylib") else 0o755
        if (app / name).stat().st_mode & 0o777 != expected_mode:
            raise RuntimeError("incorrect app helper mode: " + name)
        if team and f"TeamIdentifier={team}" not in details:
            raise RuntimeError("nested signature team differs from product")
        authorities = [line for line in outer.splitlines() if line.startswith("Authority=")]
        if authorities != [line for line in details.splitlines() if line.startswith("Authority=")]:
            raise RuntimeError("nested signing identity differs from product")
        entitlements = subprocess.run(["codesign", "-d", "--entitlements", "-", str(app / name)], capture_output=True, text=True, timeout=30)
        if "com.apple.security.cs.disable-library-validation" in entitlements.stdout:
            raise RuntimeError("library validation must not be disabled")
        if name.endswith(("taild", ".dylib")) and "com.apple.security.virtualization" in entitlements.stdout:
            raise RuntimeError("taild/bridge must not receive VMM entitlements")
    for path in (reference / "assets").iterdir():
        if digest(path) != digest(app / "Contents/Resources/assets" / path.name):
            raise RuntimeError(f"app runtime asset mismatch: {path.name}")
    for name in ("THIRD_PARTY_NOTICES", "LICENSES/APACHE-2.0.txt"):
        if digest(reference / name) != digest(app / "Contents/Resources" / name):
            raise RuntimeError("app runtime notice mismatch: " + name)
    if not list((app / "Contents/Resources/LICENSES/taild").rglob("*")):
        raise RuntimeError("missing app taild notices")
    print("Signed app identity: " + ("ad-hoc (NOT Developer-ID qualification)" if data["signing"]["ad_hoc"] else str(data["signing"]["selected_identity"])))


def scenario(layout, work, driver, isolation, failure=None):
    work.mkdir()
    userhome = work / "home"
    userhome.mkdir(mode=0o700)
    home = userhome / "state"
    config = userhome / "config/silo"
    config.mkdir(parents=True, mode=0o700)
    app = layout.suffix == ".app"
    bin_dir = layout / ("Contents/Helpers" if app else "bin")
    cli = layout / ("Contents/MacOS/silo" if app else "bin/silo")
    bridge = bin_dir / ("libsilo_go_ffi.dylib" if sys.platform == "darwin" else "libsilo_go_ffi.so")
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("SILO_", "TS_", "LD_", "DYLD_")) and key != "GODEBUG"}
    environment.update(HOME=str(userhome), SILO_HOME=str(home), XDG_CONFIG_HOME=str(userhome / "config"), XDG_CACHE_HOME=str(userhome / "cache"), XDG_DATA_HOME=str(userhome / "data"))
    # Poison inherited discovery selectors; silod must select its own components
    # and scrub these from taild, not search or extract an SDK fallback.
    environment.update(SILO_GO_FFI_PATH=str(work / "wrong-bridge"), SILO_RUNTIME_ROOT=str(work / "wrong-runtime"))
    with socket.socket() as blocked:
        blocked.bind(("127.0.0.1", 0))
        blocked.listen()
        config.joinpath("config.yaml").write_text("daemon:\n  version: '1'\n  system:\n    enabled: false\n  tailscale:\n    enabled: true\n    control-url: 'http://127.0.0.1:%d'\n    enrollment:\n      mode: none\n" % blocked.getsockname()[1])
        log = work / "daemon.log"
        with log.open("w+") as output:
            daemon = subprocess.Popen([*isolation, str(bin_dir / "silod")], env=environment, stdout=output, stderr=output, start_new_session=True)
            try:
                status_path = home / "daemon/status.json"
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    if daemon.poll() is not None:
                        raise RuntimeError("actual manager exited: " + log.read_text())
                    try:
                        status = json.loads(status_path.read_text())
                    except (FileNotFoundError, json.JSONDecodeError):
                        time.sleep(.1)
                        continue
                    if status["core"] == "ready":
                        if os.getpgid(status["pid"]) != daemon.pid or Path(status["home"]) != home:
                            raise RuntimeError("status does not identify the launched manager")
                        if failure and status["tailscale"]["state"] == "failed" and status["tailscale"].get("diagnostic"):
                            evidence = status["tailscale"]["diagnostic"] + "\n" + log.read_text()
                            expected_error = {"ABI mismatch": "ABI mismatch", "version mismatch": "native Silo bridge version", "missing dependency": "Library not loaded" if sys.platform == "darwin" else "cannot open shared object file"}.get(failure)
                            if expected_error and expected_error.lower() not in evidence.lower():
                                raise RuntimeError(f"wrong native admission failure: {evidence}")
                            if failure == "missing asset":
                                admitted = checked([*isolation, driver, "--status-only", "--endpoint", status["control_endpoint"], "--home", home, "--config-dir", config, "--bridge", bridge.resolve(), "--components-root", layout], env=environment)
                                if json.loads(admitted)["generation"] != status["generation"]:
                                    raise RuntimeError("core probe admitted another manager")
                                print(f"Visible missing shared asset failure; core status RPC remains ready, VM operations require repaired assets: {status['tailscale']['diagnostic']}")
                            else:
                                checked([*isolation, cli, "ls"], env=environment)
                                print(f"Visible {failure} failure, core management usable: {status['tailscale']['diagnostic']}")
                            assert_no_sdk(userhome)
                            return
                        children = subprocess.run(["pgrep", "-P", str(status["pid"]), "-x", "taild"], capture_output=True, text=True)
                        ids = children.stdout.split()
                        if not failure and len(ids) == 1 and (home / "taild/tsnet").is_dir():
                            pid = int(ids[0])
                            if sys.platform == "linux":
                                mappings = Path(f"/proc/{pid}/maps").read_text()
                            else:
                                mappings = checked(["vmmap", str(pid)])
                            if str(bridge.resolve()) in mappings:
                                admitted = checked([*isolation, driver, "--inspect", "--endpoint", status["control_endpoint"], "--home", home, "--config-dir", config, "--bridge", bridge.resolve(), "--components-root", layout], env=environment)
                                selection = json.loads(admitted)
                                if selection["generation"] != status["generation"]:
                                    raise RuntimeError("driver admitted another manager generation")
                                if sys.platform == "darwin" and status["tailscale"]["shutdown_protection"] != "unsupported":
                                    raise RuntimeError("macOS shutdown protection must be unsupported")
                                assert_no_sdk(userhome)
                                print("PASS actual manager/helper mapping and exact six components: " + admitted.strip())
                                return
                    time.sleep(.1)
                raise RuntimeError(f"{failure or 'startup'} acceptance timed out: " + log.read_text())
            finally:
                try:
                    os.killpg(daemon.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass  # The entire isolated process group already exited.
                try:
                    daemon.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(daemon.pid, signal.SIGKILL)
                    daemon.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("portable", type=Path)
    parser.add_argument("runtime", type=Path)
    parser.add_argument("--app", type=Path, help="actual native signed Silo.app; uses the same runtime reference")
    parser.add_argument("--driver", type=Path, default=os.environ.get("SILO_ARTIFACT_DRIVER"), help="native kvm.go acceptance executable (or SILO_ARTIFACT_DRIVER)")
    parser.add_argument("--audit-only", action="store_true", help="audit and launch actual helpers; omit destructive failure fixtures, never VM proof")
    parser.add_argument("--require-no-nix", action="store_true", help="Linux only: require rootless mount isolation hiding /nix")
    args = parser.parse_args()
    if sys.platform not in ("linux", "darwin"):
        parser.error("native Linux/macOS required")
    if not args.driver:
        parser.error("--driver or SILO_ARTIFACT_DRIVER is required for exact management RPC admission")
    if args.app and sys.platform != "darwin":
        parser.error("--app requires native macOS")
    if args.require_no_nix and sys.platform != "linux":
        parser.error("--require-no-nix is Linux-only")
    if subprocess.run(["pgrep", "-u", str(os.getuid()), "-x", "silod"], capture_output=True).returncode == 0:
        raise RuntimeError("live silod found; use an idle dedicated test UID")
    driver = args.driver.resolve(strict=True)
    portable, runtime = (p.resolve(strict=True) for p in (args.portable, args.runtime))
    with tempfile.TemporaryDirectory(prefix="silo-integrated-acceptance-") as temporary:
        root = Path(temporary).resolve()
        package = extract(portable, root / "package")
        reference = extract(runtime, root / "runtime")
        manifest_path = reference / "runtime-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        files = {str(p.relative_to(reference)): digest(p) for p in reference.rglob("*") if p.is_file() and not p.is_symlink() and p != manifest_path}
        if manifest["files"] != files:
            raise RuntimeError("runtime component inventory/digest mismatch")
        if any((reference / "bin" / name).exists() for name in ("silo", "silod", "taild", "libsilo_go_ffi.so", "libsilo_go_ffi.dylib")):
            raise RuntimeError("SDK runtime archive contains product frontends/bridge")
        prov = provenance(portable, package)
        provenance(runtime, reference)
        bridge_name = "libsilo_go_ffi.dylib" if sys.platform == "darwin" else "libsilo_go_ffi.so"
        for name in ("silo", "silod", "taild", bridge_name):
            if "bin/" + name not in prov["file_hashes"]:
                raise RuntimeError("missing product component provenance: " + name)
        for name, sha in files.items():
            if digest(package / name) != sha:
                raise RuntimeError("product/runtime component mismatch: " + name)
        if not (package / "LICENSES/taild").is_dir() or not list((package / "LICENSES/taild").rglob("*")):
            raise RuntimeError("missing taild dependency notices")
        shipped = package / "share/silo-taild"
        if shipped.exists() and any(path.name != "examples" for path in shipped.iterdir()):
            raise RuntimeError("standalone packaging/tooling shipped in integrated product")
        isolation = []
        if sys.platform == "linux":
            for path in [*(package / "bin").iterdir(), reference / "assets/agent"]:
                audit(path, manifest["target"])
            candidate = ["/usr/bin/python3", str(Path(__file__).with_name("no_nix.py").resolve()), "--"]
            probe = subprocess.run([*candidate, "/usr/bin/true"], capture_output=True, text=True)
            if probe.returncode == 0:
                isolation = candidate
            elif args.require_no_nix:
                raise RuntimeError("required /nix isolation unavailable: " + probe.stderr)
            print("/nix isolation: " + ("enabled" if isolation else "UNQUALIFIED: " + probe.stderr.strip()))
        scenario(package, root / "portable-positive", driver, isolation)
        if args.app:
            app = args.app.resolve(strict=True)
            signed_app(app, reference, manifest["version"])
            scenario(app, root / "app-positive", driver, [])
        if not args.audit_only:
            # Mutate only disposable extracted copies, never the supplied app.
            bridge = package / "bin" / bridge_name
            original = bridge.read_bytes()
            bridge.unlink()
            try:
                scenario(package, root / "missing-bridge", driver, isolation, "missing bridge")
                bridge.write_bytes(b"not a native shared library\n")
                scenario(package, root / "dependency-failure", driver, isolation, "native loader")
            finally:
                bridge.write_bytes(original)
            # Deliberately incompatible wrappers link the actual shipped bridge,
            # exercising native admission, never mocking management or tsnet.
            held = bridge.with_name("admission-original" + bridge.suffix)
            held.write_bytes(original)
            try:
                if sys.platform == "darwin":
                    checked(["install_name_tool", "-id", held, held])
                    checked(["codesign", "--force", "--sign", "-", held])
                for kind, declaration in (
                    ("ABI mismatch", "unsigned int silo_ffi_abi_version(void) { return 0; }"),
                    ("version mismatch", 'const char *silo_ffi_sdk_version(void) { return "999.0.0"; }'),
                    ("missing dependency", ""),
                ):
                    source = root / "incompatible.c"
                    source.write_text("extern void silo_runtime_open(void);\nvoid *anchor = (void *)&silo_runtime_open;\n" + declaration + "\n")
                    checked([os.environ.get("CC", "cc"), "-dynamiclib" if sys.platform == "darwin" else "-shared", "-fPIC", source, held, "-o", bridge])
                    if sys.platform == "darwin":
                        checked(["codesign", "--force", "--sign", "-", bridge])
                    if kind == "missing dependency":
                        hidden = held.with_suffix(".unavailable")
                        held.rename(hidden)
                        try:
                            scenario(package, root / "missing-dependency", driver, isolation, kind)
                        finally:
                            hidden.rename(held)
                    else:
                        scenario(package, root / kind.replace(" ", "-"), driver, isolation, kind)
            finally:
                held.unlink()
                bridge.write_bytes(original)
            agent = package / "assets/agent"
            agent.rename(agent.with_suffix(".held"))
            try:
                scenario(package, root / "missing-agent", driver, isolation, "missing asset")
            finally:
                agent.with_suffix(".held").rename(agent)
        print("PASS integrated artifact admission; VM/HVF/KVM execution and live-tailnet/reboot NOT exercised")


if __name__ == "__main__":
    main()
