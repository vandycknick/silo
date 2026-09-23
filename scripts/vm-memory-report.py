#!/usr/bin/env python3
"""Where a Silo VM's memory is held, host side and guest side, in one report.

Usage: scripts/vm-memory-report.py [VM]      (default: silo-system)

Read-only. Compares the private krun worker's host accounting with guest kernel metrics.
These are different views, not an additive physical-memory accounting: a residual
does not prove that pages leaked, were reported free, or became irreclaimable.
Needs `footprint` and `vmmap` (Xcode command line tools) and `silo exec`.
"""

import ctypes
import json
import re
import subprocess
import sys

MIB = 1024 * 1024
GUEST_SCRIPT = r"""
echo '@meminfo'; cat /proc/meminfo
echo '@zoneinfo'; grep -E '^Node|zone|pages free|managed' /proc/zoneinfo
echo '@buddyinfo'; cat /proc/buddyinfo
echo '@reporting_geometry'; getconf PAGESIZE; cat /sys/module/page_reporting/parameters/page_reporting_order
echo '@balloon'; for d in /sys/bus/virtio/drivers/virtio_balloon/virtio*; do [ -e "$d/features" ] && cat "$d/features"; done
echo '@tmpfs'; df -k -t tmpfs 2>/dev/null | tail -n +2
echo '@agent'; p=$(pidof silo-agent | cut -d' ' -f1); [ -n "$p" ] && for t in /proc/$p/task/*; do c=$(cat $t/comm 2>/dev/null); [ "$c" = memory-reclaim ] && grep -E '^policy' $t/sched; done; tr ',' '\n' < /run/agent/config.json 2>/dev/null | grep -A1 memory_reclaim
echo '@procs'; ps -eo rss,comm --sort=-rss 2>/dev/null | head -8
echo '@end'
"""


def run(cmd, check=True):
    return subprocess.run(cmd, capture_output=True, text=True, check=check).stdout


def parse_size(text):
    """'1.4G', '266.5M', '304K', '8G' -> bytes."""
    m = re.match(r"([\d.]+)\s*([KMGT]?)", text.strip())
    if not m:
        return 0
    value = float(m.group(1))
    return int(value * {"": 1, "K": 1024, "M": MIB, "G": 1024 * MIB, "T": 1024**4}[m.group(2)])


def phys_footprint(pid):
    """Exact phys_footprint via proc_pid_rusage(RUSAGE_INFO_V4)."""
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
    buf = (ctypes.c_uint64 * 64)()
    if libproc.proc_pid_rusage(ctypes.c_int(pid), ctypes.c_int(4), buf) != 0:
        return None
    # rusage_info_v4: ri_uuid (16 bytes = 2 u64), then u64 fields in header order:
    # user_time, system_time, pkg_idle_wkups, interrupt_wkups, pageins, wired_size,
    # resident_size, phys_footprint (index 7), ... lifetime_max_phys_footprint (index 28).
    return int(buf[2 + 7]), int(buf[2 + 28])


def find_machine(reference):
    rows = run(["silo", "ls"]).splitlines()[1:]
    for row in rows:
        fields = row.split()
        if len(fields) >= 5 and reference in (fields[0], fields[1]):
            return {"short_id": fields[0], "name": fields[1], "state": fields[2], "memory": parse_size(fields[4])}
    sys.exit(f"no machine named {reference!r} in `silo ls`")


def find_pid(binary, short_id):
    out = run(["pgrep", "-fl", f"{binary} --id {short_id}"], check=False)
    for line in out.splitlines():
        pid, _, cmd = line.partition(" ")
        if f"/{binary} " in cmd or cmd.startswith(binary):
            return int(pid)
    return None


def worker_pid(process_rows: str, supervisor_pid: int) -> int | None:
    """Select the vmmon worker belonging to this supervisor."""
    candidates: list[int] = []
    for line in process_rows.splitlines():
        fields = line.split(maxsplit=2)
        if len(fields) != 3:
            continue
        try:
            pid, parent = int(fields[0]), int(fields[1])
        except ValueError:
            continue
        command = fields[2].split()
        if (parent == supervisor_pid and len(command) >= 2
                and command[0].rsplit("/", 1)[-1] == "vmmon"
                and command[1] == "worker"):
            candidates.append(pid)
    if len(candidates) > 1:
        raise ValueError("supervisor has multiple private krun workers")
    return candidates[0] if candidates else None


def footprint_table(pid):
    out = run(["footprint", "-p", str(pid)])
    rows = {}
    for line in out.splitlines():
        m = re.match(r"\s*([\d.]+ ?[KMG]?B)\s+([\d.]+ ?[KMG]?B)\s+([\d.]+ ?[KMG]?B)\s+\d+\s+(.+)$", line)
        if m and not m.group(4).startswith("---") and m.group(4).strip() != "TOTAL":
            rows[m.group(4).strip()] = tuple(parse_size(m.group(i).replace(" ", "")) for i in (1, 2, 3))
    return rows


def vmmap_totals(pid):
    out = run(["vmmap", "--summary", str(pid)])
    for line in out.splitlines():
        if line.startswith("TOTAL "):
            fields = line.split()
            return {"virtual": parse_size(fields[1]), "resident": parse_size(fields[2]),
                    "dirty": parse_size(fields[3]), "swapped": parse_size(fields[4])}
    return {}


def guest_view(name):
    out = run(["silo", "exec", "-u", "root", name, "--", "sh", "-c", GUEST_SCRIPT])
    sections, current = {}, None
    for line in out.splitlines():
        if line.startswith("@"):
            current = line[1:]
            sections[current] = []
        elif current:
            sections[current].append(line)
    return sections


def kib_field(lines, key):
    for line in lines:
        if line.startswith(key):
            return int(line.split()[1]) * 1024
    return 0


def reporting_geometry(lines: list[str]) -> tuple[int, int]:
    if len(lines) != 2:
        raise ValueError("guest page size or reporting order is unavailable")
    page_size, order = map(int, lines)
    if page_size < 1024 or page_size & (page_size - 1) or not 0 <= order < 64:
        raise ValueError("invalid guest page size or reporting order")
    return page_size, order


def zones(zoneinfo, buddyinfo, page_size: int, reporting_order: int):
    result = {}
    zone = None
    for line in zoneinfo:
        if "zone" in line:
            zone = line.split("zone")[1].strip()
            result[zone] = {"free": 0, "managed": 0, "fragments": 0}
        elif zone and "pages free" in line:
            result[zone]["free"] = int(line.split()[-1]) * page_size
        elif zone and "managed" in line:
            result[zone]["managed"] = int(line.split()[-1]) * page_size
    for line in buddyinfo:
        m = re.match(r"Node \d+, zone\s+(\S+)\s+(.*)$", line)
        if not m:
            continue
        counts = [int(x) for x in m.group(2).split()]
        small = sum(count * (page_size << order) for order, count in enumerate(counts) if order < reporting_order)
        result.setdefault(m.group(1), {"free": 0, "managed": 0, "fragments": 0})["fragments"] = small
    return result


def mib(value):
    return f"{value / MIB:8.0f} MiB"


def main():
    reference = sys.argv[1] if len(sys.argv) > 1 else "silo-system"
    machine = find_machine(reference)
    vmmon = find_pid("vmmon", machine["short_id"])
    krun = worker_pid(run(["ps", "-axo", "pid=,ppid=,args="]), vmmon) if vmmon is not None else None
    if krun is None:
        sys.exit(f"{machine['name']} has no running private krun worker (state {machine['state']})")

    fp = phys_footprint(krun)
    table = footprint_table(krun)
    totals = vmmap_totals(krun)
    guest = guest_view(machine["name"])
    meminfo = guest.get("meminfo", [])
    try:
        page_size, reporting_order = reporting_geometry(guest.get("reporting_geometry", []))
    except ValueError as error:
        sys.exit(f"cannot determine guest free-page reporting threshold: {error}")
    report_block = page_size << reporting_order
    report_label = f"{report_block // MIB} MiB" if report_block >= MIB else f"{report_block // 1024} KiB"
    zone_table = zones(guest.get("zoneinfo", []), guest.get("buddyinfo", []), page_size, reporting_order)

    charged, peak = fp if fp else (0, 0)
    untagged_charge = table.get("untagged (VM_ALLOCATE)", (0, 0, 0))[0]
    vmm_overhead = sum(d for cat, (d, _, _) in table.items() if cat != "untagged (VM_ALLOCATE)")
    reusable = sum(r for (_, _, r) in table.values())

    mem_total = kib_field(meminfo, "MemTotal:")
    mem_free = kib_field(meminfo, "MemFree:")
    cached = kib_field(meminfo, "Cached:")
    shmem = kib_field(meminfo, "Shmem:")
    anon = kib_field(meminfo, "AnonPages:")
    slab = kib_field(meminfo, "Slab:")
    unevictable = kib_field(meminfo, "Unevictable:")
    guest_held = mem_total - mem_free
    kernel_reserved = max(machine["memory"] - mem_total, 0)
    fragments = sum(z["fragments"] for z in zone_table.values())
    expected = vmm_overhead + guest_held + kernel_reserved + fragments
    residual = charged - expected

    print(f"VM {machine['name']} ({machine['short_id']})  krun pid {krun}  vmmon pid {vmmon}  configured RAM {mib(machine['memory'])}")
    print()
    print("HOST (what macOS charges the krun process)")
    print(f"  phys_footprint            {mib(charged)}   peak {mib(peak)}")
    print(f"    mapped resident         {mib(totals.get('resident', 0))}   (vmmap RESIDENT; not total backing residency)")
    print(f"    compressed / swapped    {mib(totals.get('swapped', 0))}   (logical pages; not compressor RAM or swap-file bytes)")
    print(f"    marked reusable         {mib(reusable)}   (explicit accounting category; not all MADV_FREE pages)")
    print(f"    untagged mapping charge {mib(untagged_charge)}   (default footprint view; includes compressed)")
    print(f"    VMM overhead            {mib(vmm_overhead)}   (malloc, stacks, page tables)")
    print(f"  Inspect backing separately: footprint -p {krun} --wide --vmObjectDirty")
    print("  Neither that object-accounting view nor these totals establishes per-page discardability.")
    print()
    print("GUEST (what the Linux kernel holds)")
    print(f"  MemTotal {mib(mem_total)}   kernel reserved outside MemTotal {mib(kernel_reserved)}")
    print(f"  held = MemTotal - MemFree {mib(guest_held)}")
    print(f"    anon {mib(anon)}  page cache {mib(cached - shmem)}  shmem/tmpfs {mib(shmem)}  slab {mib(slab)}  unevictable {mib(unevictable)}")
    print(f"  free                      {mib(mem_free)}")
    for zone, z in zone_table.items():
        if z["managed"]:
            print(f"    zone {zone:7s} managed {mib(z['managed'])}  free {mib(z['free'])}  in blocks < {report_label} {mib(z['fragments'])}")
    features = "".join(guest.get("balloon", []))
    reporting = "yes" if len(features) > 5 and features[5] == "1" else "no"
    print(f"  balloon free-page reporting negotiated: {reporting}")
    print(f"  minimum reportable block: {report_label} (order {reporting_order}, {page_size // 1024} KiB guest pages)")
    agent_lines = [l.strip() for l in guest.get("agent", []) if l.strip()]
    policy = next((l.split()[-1] for l in agent_lines if l.startswith("policy")), None)
    policy_name = {"0": "SCHED_OTHER", "5": "SCHED_IDLE"}.get(policy, policy)
    config = " ".join(
        re.sub(r'[{}"]', "", l).replace("memory_reclaim:", "").strip()
        for l in agent_lines
        if "mode" in l or "idle_after" in l
    )
    thread = f"thread running at {policy_name}" if policy else "no thread"
    print(f"  agent reclaim: {thread}; config {config or 'absent'}")
    tmpfs = [l.split() for l in guest.get("tmpfs", []) if l.strip()]
    big_tmpfs = [(f[5], int(f[2]) * 1024) for f in tmpfs if len(f) >= 6 and int(f[2]) * 1024 >= 8 * MIB]
    if big_tmpfs:
        print("  tmpfs >= 8 MiB: " + ", ".join(f"{path} {mib(size).strip()}" for path, size in big_tmpfs))
    print("  largest processes (RSS): " + ", ".join(
        f"{f[1]} {int(f[0]) // 1024} MiB" for f in (l.split(None, 1) for l in guest.get("procs", [])[1:6]) if len(f) == 2))
    print()
    print("HEURISTIC COMPARISON (not an additive physical-memory accounting)")
    print(f"  VMM overhead              {mib(vmm_overhead)}")
    print(f"  guest held                {mib(guest_held)}")
    print(f"  kernel reserved           {mib(kernel_reserved)}")
    print(f"  unreportable fragments    {mib(fragments)}   (free but in blocks smaller than {report_label})")
    print(f"  = guest-based estimate    {mib(expected)}")
    print(f"  phys_footprint            {mib(charged)}")
    print(f"  accounting residual       {mib(residual)}   (not a leak or reported-page measurement)")
    print("  Host mappings, guest mappings and backing objects can account for the same pages differently.")
    try:
        status = json.load(open("/tmp/silo-501/daemon/status.json"))
        if status.get("machine_id", "").startswith(machine["short_id"]):
            print()
            print("DAEMON")
            print(f"  host reclaim: effective={status.get('host_memory_reclaim_effective')} probe={status.get('host_memory_reclaim_qualification')} advised {mib(status.get('host_memory_reclaim_released_bytes') or 0)} failed_ops {status.get('host_memory_reclaim_failed_operations')}")
            print(f"  guest reclaim: runs {status.get('memory_reclaim_runs')} last {status.get('memory_reclaim_at')} outcome {status.get('memory_reclaim_outcome')} cached fell {mib(status.get('memory_reclaim_observed_cache_delta_bytes') or 0)}")
    except (OSError, ValueError):
        pass


if __name__ == "__main__":
    main()
