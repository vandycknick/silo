"""Real ELF mutations exercise packaging rejection without synthetic loaders."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
from elf_audit import Elf, audit, loader_for, validate


class AuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="silo-elf-test-")
        self.addCleanup(self.temporary.cleanup)
        self.binary = Path(self.temporary.name) / "native-true"
        shutil.copyfile("/usr/bin/true", self.binary)
        self.target = "linux-amd64-gnu" if platform.machine() == "x86_64" else "linux-arm64-gnu"

    def mutate(self, *args: str) -> None:
        subprocess.run(["patchelf", *args, str(self.binary)], check=True)

    def test_native_closure(self) -> None:
        audit(self.binary, self.target)

    def test_nix_interpreter(self) -> None:
        self.mutate("--set-interpreter", "/nix/store/unavailable/lib/ld-linux.so")
        with self.assertRaisesRegex(RuntimeError, "interpreter"): audit(self.binary, self.target)

    def test_build_rpath(self) -> None:
        self.mutate("--set-rpath", str(Path(self.temporary.name) / "build/lib"))
        with self.assertRaisesRegex(RuntimeError, "search paths"): audit(self.binary, self.target)

    def test_absolute_dependency(self) -> None:
        self.mutate("--add-needed", "/nix/store/unavailable/libc.so.6")
        with self.assertRaisesRegex(RuntimeError, "DT_NEEDED"): audit(self.binary, self.target)

    def test_missing_dependency(self) -> None:
        self.mutate("--add-needed", "libsilo-missing-qualification.so")
        with self.assertRaises((RuntimeError, subprocess.CalledProcessError)): audit(self.binary, self.target)

    def test_new_glibc_requirement(self) -> None:
        # Pure policy test, no fabricated positive ELF/runtime evidence.
        with self.assertRaisesRegex(RuntimeError, "glibc requirement"):
            validate(Elf(self.binary, None, (), (), (2, 40)), loader_for(self.target))

    def test_rootless_nix_hiding_preserves_uid(self) -> None:
        result = subprocess.run(["/usr/bin/python3", str(Path(__file__).with_name("no_nix.py")), "--", "/usr/bin/python3", "-c", f"import os; assert not os.path.exists('/nix/store'); assert os.getuid() == {os.getuid()}"], capture_output=True, text=True)
        if result.returncode != 0: self.skipTest("rootless mount isolation unavailable: " + result.stderr)


if __name__ == "__main__":
    unittest.main()
