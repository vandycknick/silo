"""Filesystem unit tests and an offline real Go dependency graph."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
from go_licenses import Module, collect, modules_from_packages


class LicenseTests(unittest.TestCase):
    def test_exact_graph_deduplication_and_replacements(self) -> None:
        dependency = {"Path": "example.org/dependency", "Version": "v1.0.0", "Replace": {"Dir": "/local/dependency", "Version": "v1.1.0"}}
        packages = [{"Module": {"Main": True, "Path": "example.org/main"}}, {}, {"Module": dependency}, {"Module": dependency}]
        self.assertEqual(modules_from_packages("\n".join(json.dumps(p) for p in packages)), [Module("example.org/dependency", "v1.1.0", Path("/local/dependency"))])
        self.assertEqual(modules_from_packages("  \n"), [])
        with self.assertRaises(json.JSONDecodeError):
            modules_from_packages("{broken")

    def test_collect_notices_and_replace_stale_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "dependency"
            source.mkdir()
            for name in ["LICENSE", "NOTICE.txt", "COPYING", "license.go", "README"]:
                (source / name).write_text(name)
            output = root / "notices"
            output.mkdir()
            (output / "stale").write_text("stale")
            collect([Module("example.org/dependency", "v1.2.3", source)], output)
            inventory = json.loads((output / "modules.json").read_text())
            self.assertEqual(inventory, [{"module": "example.org/dependency", "version": "v1.2.3", "notices": [f"example.org/dependency/v1.2.3/{name}" for name in ["COPYING", "LICENSE", "NOTICE.txt"]]}])
            self.assertFalse((output / "stale").exists())
            for notice in inventory[0]["notices"]:
                self.assertEqual((output / notice).read_text(), Path(notice).name)
                self.assertEqual((output / notice).stat().st_mode & 0o777, 0o644)

    def test_missing_notices_and_unsafe_paths_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "dependency"
            source.mkdir()
            with self.assertRaisesRegex(RuntimeError, "missing license material"):
                collect([Module("example.org/dependency", "v1.2.3", source)], root / "output")
            (source / "LICENSE").write_text("license")
            for name, version in [("../escape", "v1"), ("/absolute", "v1"), ("example.org//dependency", "v1"), ("example.org/dependency", "../escape"), ("example.org/dependency", "v1/escape")]:
                with self.assertRaises(ValueError):
                    collect([Module(name, version, source)], root / "output")

    def test_real_go_graph_copies_only_imported_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dependency = root / "dependency"
            dependency.mkdir()
            (dependency / "go.mod").write_text("module example.org/dependency\n\ngo 1.20\n")
            (dependency / "dep.go").write_text("package dependency\nfunc Value() int { return 42 }\n")
            (dependency / "LICENSE").write_text("real dependency license")
            (root / "go.mod").write_text("module example.org/main\n\ngo 1.20\nrequire example.org/dependency v1.2.3\nreplace example.org/dependency => ./dependency\n")
            (root / "main.go").write_text('package main\nimport "example.org/dependency"\nfunc main() { println(dependency.Value()) }\n')
            output = root / "notices"
            subprocess.run([sys.executable, str(Path(__file__).with_name("go_licenses.py")), str(root), str(output), "--package", "."], check=True, env={**os.environ, "GOTOOLCHAIN": "local", "GOPROXY": "off", "CGO_ENABLED": "0"}, timeout=60)
            inventory = json.loads((output / "modules.json").read_text())
            self.assertEqual(len(inventory), 1)
            self.assertEqual(inventory[0]["module"], "example.org/dependency")
            self.assertEqual((output / inventory[0]["notices"][0]).read_text(), "real dependency license")


if __name__ == "__main__":
    unittest.main()
