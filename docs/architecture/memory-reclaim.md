# Memory Reclaim

Silo runs Linux in a VM whose RAM is host process memory. Two independent
mechanisms decide how much of that RAM the host actually pays for. They are
configured by two settings, use two different vocabularies, and are easy to
confuse. This document names them, explains what each one does and does not
do, and shows how they compose.

| Silo setting | Name used in this document | Where it runs | Kernel / spec term |
| --- | --- | --- | --- |
| `host-memory-reclaim` | **host memory reclaim** | libkrun in the `krun` helper, fed by the guest kernel | virtio-balloon **free page reporting** (`VIRTIO_BALLOON_F_REPORTING`) plus a host-side page release |
| `memory-reclaim` | **guest memory reclaim** | a thread inside the guest agent, configured at launch | cgroup v2 **proactive reclaim** (`memory.reclaim`) plus **memory compaction** |

Neither one is "ballooning" in the classic sense. Silo attaches a
virtio-balloon device, but only for its free page reporting queue. The
inflate and deflate queues are not used.

## The problem being solved

A page the guest kernel has touched once stays resident in the host process
until something tells the host it is free again. Without help, a VM's host
footprint is the high-water mark of everything the guest ever used, and it
never comes back down. Apple's Virtualization.framework has exactly this
behavior today; its balloon device does not release anything host-side.

Two things have to happen for host memory to come back:

1. The guest kernel has to consider the memory free. Page cache does not
   count. From the kernel's point of view cached file data is in use until
   it is reclaimed.
2. The VMM has to learn which guest pages are free and tell the host kernel
   to drop them.

Host memory reclaim does the second part. Guest memory reclaim makes the
first part happen sooner than the guest would do it by itself.

## Host memory reclaim

### Free page reporting, guest side

The guest kernel's `page_reporting` subsystem watches the free lists. When a
zone has enough free memory, it batches up free blocks and hands them to the
virtio-balloon driver, which places them on the balloon's reporting
virtqueue. While a block is being reported it is pulled off the free lists,
so the guest cannot allocate it until the VMM acknowledges the report. This
is what makes the protocol safe: the VMM never touches a page the guest is
using.

Facts that shape everything downstream:

- The guest's configured `page_reporting_order` sets the minimum block size.
  Silo's arm64 guest currently uses order 9, or 2 MiB with its 4 KiB pages.
  Free memory fragmented into smaller pieces is not reported; compaction can
  merge it back into reportable blocks. OrbStack's inspected guest uses order 2
  (16 KiB), a separate policy difference from host mapping maintenance.
- Reporting runs two seconds after free memory crosses the threshold, in
  batches of at most 32 blocks.
- Reporting stops while a zone is near its low watermark, so the guest
  always keeps a working reserve.
- Nothing is configured. The guest kernel enables this whenever the device
  advertises `VIRTIO_BALLOON_F_REPORTING`.

### Page release, host side

libkrun receives each report and releases the range to the host. On Linux
that is one `madvise(MADV_DONTNEED)`; the KVM stage-2 mapping is torn down by
the kernel's MMU notifiers and refaults are handled in-kernel. On macOS the
same primitive is a silent no-op for pages the guest dirtied, so Silo's
libkrun fork runs, per contiguous range:

```text
hv_vm_unmap  ->  madvise(MADV_FREE) once per native host page  ->  hv_vm_map
```

The range is remapped immediately. `MADV_FREE` makes backing eligible for
reclamation; it does not promise an immediate resident-size or footprint drop.
When backing is discarded, the host handles later guest refaults in-kernel
without a VM exit. Adjacent descriptors in one report are merged to amortize
HV TLB invalidations, but advice remains page-wise: bulk advice can miss backing
that the guest dirtied without populating host PTEs. Production reclaim does not
replace reported backing with `MAP_FIXED`.

Host device access to guest memory is never guarded. The host mapping stays
valid throughout, and the reporting protocol keeps a reported page out of the
guest allocator until the report is acknowledged. The only shared state is
one atomic per 2 MiB extent so that a vCPU that faults inside the unmap
window waits for the remap and retries.

### Host mapping maintenance

Host accesses to guest RAM also populate host page-table entries. Their charge
can survive successful free-page advice even when the backing is clean. To
remove those translations, the native VMM event loop performs same-address
`mach_vm_remap(copy=false)` over registered RAM every 30 seconds while host
reclaim is effective. This preserves the VM objects, guest mappings and live
contents; it is not a fresh anonymous allocation and does not discard old reports
again. The owning VMM keeps RAM alive throughout maintenance. Failure stops the
VM rather than continuing with uncertain host mappings.

This accounts for an important part of OrbStack's apparent memory efficiency.
In a matched 512 MiB Linux VM test, a 128 MiB disk-read/free workload left about
210 MiB charged without maintenance, versus 62 MiB after the maintenance pass.
Both runs still showed about 179 MiB in VM-object accounting. A footprint drop
therefore cannot be claimed as the same amount of physical RAM returned.

The implementation uses only the 30-second pass, not OrbStack's additional
report-triggered 250 ms scheduling or its 4 MiB backing allocation scheme.

### Qualification probe

At VM start the fork maps a 2 MiB scratch region and has a scratch vCPU dirty
it. Without first reading its payload through the host mapping, it runs the
production unmap, page-wise advice, immediate-remap cycle and checks that
`mincore` reports clean, unreferenced, uncompressed backing. It then verifies
guest read/write reuse. Host memory reclaim is only effective when the probe
passes; nested EL2 guests remain unqualified. `silo daemon status` reports the
probe result separately from the requested policy. Passing verifies page state
and reuse, not physical release under every future pressure condition.

### What it does not do

- It cannot release page cache, tmpfs, shmem, or anything the guest kernel
  still considers allocated. That is the job of guest memory reclaim, or of
  the guest's own workloads freeing memory.
- It does not track current physical savings. Clean `MADV_FREE` pages can stay
  resident until pressure, and subsequent writes cancel their discardability.
  The cumulative advice counter does not subtract re-dirtied or repeated pages.
- It does nothing on the Virtualization.framework backend, which owns guest
  RAM in Apple's helper process where Silo cannot advise it.

## Guest memory reclaim

The guest kernel only frees page cache when it needs the memory for
something else. In a VM that means cache accumulates to the VM's memory
limit and stays there, invisible to free page reporting. Guest memory reclaim
asks the kernel to give it up early. It follows WSL2's `autoMemoryReclaim`
closely, including the design choice that the policy runs inside the guest:
WSL runs it in its `init`, Silo runs it in the guest agent.

### Mechanism

The daemon translates `memory-reclaim` and `memory-reclaim-after` into the
machine's durable guest config, which libvm ships to the agent in
`/run/agent/config.json` at every launch. When the mode is not `off` the
agent starts a `memory-reclaim` thread at `SCHED_IDLE` priority, so it never
competes with workloads, and that thread:

1. Samples `/proc/stat` every ten seconds. The guest counts as idle when
   non-idle CPU stays at or below 0.5% across a rolling window of
   `memory-reclaim-after`, and the latest interval is idle too. A short burst
   postpones one tick without discarding the idle history.
2. In `gradual` mode computes the reclaimable cache as
   `Active(file) + Inactive(file) + SReclaimable`. Shared memory and tmpfs
   are not file cache and are never counted. It keeps a 128 MiB floor and asks
   the cgroup v2 root `memory.reclaim` for one bounded step per tick, RAM/32
   clamped between 256 MiB and 1 GiB, with `swappiness=0`. `EAGAIN` means the
   kernel freed part of the request and counts as progress. This interface is
   Linux's proactive reclaim, added in 5.19; it runs the same reclaim path
   `kswapd` uses, without the pressure.
3. In `dropcache` mode, or when `memory.reclaim` is missing, writes `3` to
   `/proc/sys/vm/drop_caches` once per idle period.
4. After a reclaim writes `1` to `/proc/sys/vm/compact_memory` so the freed
   pages merge into blocks large enough for free page reporting.
5. Re-samples CPU afterwards so its own work does not restart the idle
   window, and records the run: mode, outcome, bytes requested, and `Cached`
   before and after.

The record travels with the agent's normal metrics stream, so vmmon and the
daemon learn about it without any extra channel. The daemon only observes;
it runs nothing in the guest.

Pages the guest frees this way land on its free lists and, two seconds later,
free page reporting hands them to the host. Guest memory reclaim therefore
only helps when host memory reclaim is effective; on its own it just moves
the guest's memory from "cached" to "free".

### What it does not do

- It never touches memory the guest is actively using. `memory.reclaim` only
  reclaims what the kernel would reclaim under pressure anyway: clean page
  cache, and anonymous memory only if swap exists, which the guest has none.
- It does not reduce the VM's memory limit. The guest can use the full
  `memory` setting again at any time.
- It does not react to host memory pressure. The guest cannot see the host,
  and a host-to-agent signal would need a new RPC through vmmon. That was
  judged not worth the depth for now; the idle window is the only trigger.

## How they compose

```text
guest workload frees memory ─┐
                             ├─> guest free lists ─> free page reporting ─> backing made discardable
guest memory reclaim ────────┘        (2 MiB blocks,     (virtio-balloon        (unmap, page-wise
  after guest CPU idle                2 s delay)         reporting queue)       MADV_FREE, remap)

guest reuses discarded backing ─> stage-2 refault handled in the host kernel, no VM exit
```

`daemon status` shows both:

```text
Memory:               8GiB; last idle gradual reclaim in the guest reclaimed 2 minutes ago, guest cache fell by 512MiB
Host memory reclaim:  requested auto; effective on (probe passed); 7.01GiB advised free since VM start
```

The `Memory` row is guest memory reclaim as the agent reported it: mode,
outcome, and how far the guest's own `Cached` figure fell. The `Host memory reclaim` row is host
memory reclaim: requested policy, probe outcome, and cumulative bytes
successfully advised free. The underlying `released_bytes` counter includes
repeat reports and untouched memory reported at boot, so it can exceed the VM's
RAM ceiling. It is not current physical memory savings.

## Reading the numbers

The host process footprint of a healthy VM is roughly:

- guest memory the kernel considers in use: anonymous pages, slab, page
  cache, plus tmpfs and shmem, which never go away without swap
- guest free memory that is not reportable: blocks smaller than 2 MiB,
  per-CPU free lists, the low-watermark reserve
- reported pages whose clean backing the host has not yet discarded
- VMM overhead: virtio buffers, stacks, and any large buffers libkrun retains

A debug-profile agent binary of 170 MB staged on tmpfs under `/run/agent`
is real guest memory use, not a host reclaim leak; release builds shrink it.
The pinned fork now streams the external initramfs into guest RAM, removing
the former same-sized host heap staging buffer and its allocator retention.

## What Silo deliberately does not use

- **Traditional balloon inflate and deflate.** The host asks the guest to
  hand over N pages; the guest driver allocates them, which forces reclaim,
  and pins them until deflate. It is the only way to have the guest kernel
  itself perform the reclaim with no guest userspace involved, but it pins
  memory, interacts badly with THP and fragmentation, and risks guest OOM
  unless `DEFLATE_ON_OOM` is negotiated. libkrun does not implement these
  queues today. It remains a possible future lever for the pressure trigger.
- **Free page hinting** (`VIRTIO_BALLOON_F_FREE_PAGE_HINT`). A live-migration
  optimization that tells the host which pages need not be copied. It does
  not release memory.
- **virtio-mem.** Resizes the guest's memory in hot-pluggable blocks. Solves
  a different problem, changing the limit rather than returning cache.

## Testing

Force guest memory reclaim without waiting:

```sh
# lower the window to its 30 s minimum in daemon.yaml, restart, fill cache, leave it alone
docker run --rm alpine sh -c 'dd if=/dev/urandom of=/cache bs=1M count=1024 && sync && cat /cache >/dev/null'
silo daemon logs | tail -3          # "guest memory reclaim run N: ..."
silo exec silo-system -- journalctl -u silo-agent -n 5   # the agent's own log line

# kernel path only, bypassing the agent
silo exec -u root silo-system -- sh -c 'echo 512M > /sys/fs/cgroup/memory.reclaim; echo $?'
```

The agent's policy changes only at VM start: `silo daemon down && silo daemon up`
after editing the config.

Watch host memory reclaim with the released counter in `daemon status`, or
with `footprint -p <krun pid>` on the host. Inside the guest,
`/proc/buddyinfo` shows how much free memory sits in blocks too small to
report.

## Related

- [System daemon](../system-daemon.md) for the configuration keys.
- [libkrun dependency](../libkrun-deps.md) for the fork revision and the
  helper's status channel.
- [libkrun implicit behaviors](libkrun-implicit-behaviors.md) for the
  balloon device attachment.
