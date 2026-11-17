from __future__ import annotations

import argparse
from pathlib import Path
from typing import Mapping, Sequence

from silo_perf.history import Record, delta, history_path, load
from silo_perf.model import Cohort, Target, TargetKey, target_for


def render(records: Sequence[Record], history: Sequence[Record],
           targets: Mapping[TargetKey, Target], cohorts: Mapping[str, Cohort] | None = None) -> str:
    competitors = list(dict.fromkeys(["msb", *(entry.system for entry in records if entry.system != "silo")]))
    columns = ["cohort / metric", "image source", "Silo image s", "target image", "Silo agent s", "target agent"]
    for system in competitors:
        columns += [f"{system} s", f"Silo/{system} image / agent"]
    columns += ["delta " + " / ".join(["image", "agent", *competitors])]
    rows = [columns]
    for cohort, metric in dict.fromkeys((entry.cohort, entry.metric) for entry in records):
        selected = [entry for entry in records if (entry.cohort, entry.metric) == (cohort, metric)]
        by_mode = {(entry.system, entry.mode): entry for entry in selected}
        informational = any(entry.informational for entry in selected)
        silos = [by_mode.get(("silo", mode)) for mode in ("image", "agent")]
        def timing(entry: Record | None) -> str:
            return "-" if entry is None else f"{entry.median:.3f}"
        def gate(entry: Record | None) -> str:
            if entry is None:
                return "-"
            target = target_for(targets, entry.system, cohort.split("/")[0], entry.mode, metric)
            if informational:
                return "informational"
            if target is None:
                return "-"
            return f"{target.seconds:g} {target.evaluate(entry.median).render(target.tolerance)}"
        def change(entry: Record | None) -> str:
            value = None if entry is None else delta(entry, history)
            return "-" if value is None else f"{value:+.1f}%"
        label = f"{cohort} (informational)" if informational else cohort
        metric_label = {"create_first": "create_first (first create, includes image pull and preparation)",
                        "create": "create (repeated create)", "run_true": "run_true (warm run)"}.get(metric, metric)
        definition = (cohorts or {}).get(cohort.split("/")[0])
        if metric == "create_first" and definition is not None and definition.raw_root:
            metric_label = "create_first (first raw create, after image_convert_raw)"
        sources = " / ".join(dict.fromkeys(entry.image_source or "unknown" for entry in selected))
        row = [f"{label} / {metric_label}", sources,
               timing(silos[0]), gate(silos[0]), timing(silos[1]), gate(silos[1])]
        others = [by_mode.get((system, "default")) for system in competitors]
        for competitor in others:
            ratios = ["-" if entry is None or competitor is None or competitor.median == 0
                      else f"{entry.median / competitor.median:.2f}x" for entry in silos]
            row += [timing(competitor), " / ".join(ratios)]
        row += [" / ".join(change(entry) for entry in [*silos, *others])]
        rows.append(row)
    widths = [max(len(row[index]) for row in rows) for index in range(len(columns))]
    table = "\n".join("  ".join(value.ljust(width) for value, width in zip(row, widths, strict=True)).rstrip()
                      for row in rows)
    for cohort in (cohorts or {}).values():
        if len(cohort.disks) > 1 and any(entry.cohort.startswith(cohort.name + "/") for entry in records):
            table += (f"\n{cohort.name} timing invariant: absolute difference <= max("
                      f"{cohort.noise_absolute_seconds:g}s, {cohort.noise_relative:.0%} of smaller median)")
            for metric, seconds in sorted(cohort.metric_noise_absolute_seconds.items()):
                table += f"; {metric} accepted up to {seconds:g}s"
    return table


def trend(records: Sequence[Record]) -> str:
    lines = ["timestamp  host  system  cohort  mode  metric  median s  verdict  delta"]
    for index, record in enumerate(records):
        change = delta(record, records[:index])
        verdict = ("-" if record.verdict is None or record.tolerance is None
                   else record.verdict.render(record.tolerance))
        label = f"{record.cohort} (informational)" if record.informational else record.cohort
        lines.append(f"{record.timestamp}  {record.host.fingerprint[:12]}  {record.system}  "
                     f"{label}  {record.mode}  {record.metric}  {record.median:.3f}  "
                     f"{verdict}  "
                     + ("-" if change is None else f"{change:+.1f}%"))
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Print host-matched performance trends from JSONL history")
    parser.add_argument("--history", type=Path, default=history_path())
    args = parser.parse_args()
    print(trend(load(args.history)))


if __name__ == "__main__":
    main()
