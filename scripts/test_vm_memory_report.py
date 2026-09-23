"""Unit tests for worker discovery and guest memory accounting."""

import importlib.util
import os
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "vm_memory_report", Path(__file__).with_name("vm-memory-report.py")
)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load vm-memory-report.py")
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


class WorkerDiscoveryTests(unittest.TestCase):
    def test_selects_only_the_supervisors_private_worker(self) -> None:
        rows = "\n".join([
            "10 1 /runtime/vmmon --id abc",
            "11 10 silo-krun",
            "12 99 silo-krun",
            "13 10 vmmon --name silo-krun",
            "14 10 /bin/sh -c silo-krun",
        ])
        self.assertEqual(report.worker_pid(rows, 10), 11)
        self.assertIsNone(report.worker_pid(rows, 42))
        self.assertEqual(report.worker_pid("11 10 /path/to/silo-krun", 10), 11)

    def test_rejects_multiple_workers_and_ignores_malformed_rows(self) -> None:
        with self.assertRaises(ValueError):
            report.worker_pid("11 10 silo-krun\n12 10 silo-krun", 10)
        self.assertIsNone(report.worker_pid("unknown\npid ppid args", 10))


class SiloHomeTests(unittest.TestCase):
    def test_prefers_silo_home_then_dot_silo(self) -> None:
        saved = os.environ.get("SILO_HOME")
        try:
            os.environ["SILO_HOME"] = "/custom/silo"
            self.assertEqual(report.silo_home(), Path("/custom/silo"))
            del os.environ["SILO_HOME"]
            self.assertEqual(report.silo_home(), Path.home() / ".silo")
        finally:
            if saved is not None:
                os.environ["SILO_HOME"] = saved


class ReportingGeometryTests(unittest.TestCase):
    def test_reads_guest_page_size_and_order(self) -> None:
        for page_size, order in [(4096, 0), (4096, 2), (4096, 9), (16384, 2)]:
            with self.subTest(page_size=page_size, order=order):
                self.assertEqual(
                    report.reporting_geometry([str(page_size), str(order)]),
                    (page_size, order),
                )

    def test_rejects_missing_or_invalid_geometry(self) -> None:
        for lines in [
            [], ["4096"], ["4096", "2", "extra"], ["unknown", "2"],
            ["0", "2"], ["-4096", "2"], ["4097", "2"],
            ["4096", "-1"], ["4096", "64"], ["4096", "4294967295"],
        ]:
            with self.subTest(lines=lines):
                with self.assertRaises(ValueError):
                    report.reporting_geometry(lines)

    def test_counts_only_blocks_below_the_live_order(self) -> None:
        zoneinfo = ["Node 0, zone Normal", "  pages free 2047", "  managed 4096"]
        buddyinfo = ["Node 0, zone Normal 1 1 1 1 1 1 1 1 1 1 1"]
        for page_size, order in [(4096, 0), (4096, 2), (4096, 9), (16384, 2)]:
            with self.subTest(page_size=page_size, order=order):
                zone = report.zones(zoneinfo, buddyinfo, page_size, order)["Normal"]
                self.assertEqual(zone["free"], 2047 * page_size)
                self.assertEqual(zone["managed"], 4096 * page_size)
                self.assertEqual(zone["fragments"], ((1 << order) - 1) * page_size)

    def test_accounts_for_each_zone(self) -> None:
        zones = report.zones(
            ["Node 0, zone DMA", "  managed 100", "Node 0, zone Normal", "  managed 200"],
            ["Node 0, zone DMA 2 3 99", "Node 0, zone Normal 4 5 99"],
            4096,
            2,
        )
        self.assertEqual(zones["DMA"]["fragments"], (2 + 3 * 2) * 4096)
        self.assertEqual(zones["Normal"]["fragments"], (4 + 5 * 2) * 4096)


if __name__ == "__main__":
    unittest.main()
