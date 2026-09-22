# Automatic memory reclamation

Silo targets macOS 26 and newer. The HVF path uses public Hypervisor.framework
and Mach APIs, with no older-macOS private-trap compatibility branch.

## Four separate components

| Component | Responsibility | Owner |
| --- | --- | --- |
| `FreePageReporter` | Reports guest-free pages through the negotiated virtio-balloon reporting queue. | Guest kernel and balloon device |
| `HostMemoryReclaimer` | Makes reported backing reclaimable while the guest report owns the pages. | libkrun HVF `ReclaimState` |
| `HostMemoryRemapper` | Removes stale host translations/accounting using content-preserving self-remapping. | libkrun guest-memory lifecycle/event loop |
| `GuestCacheReclaimer` | Turns cold guest file cache into free memory during idle periods. | Managed guest agent |

None of the four is proof of immediate host physical-memory savings. Guest-free
memory, successful advice, host footprint, compression, and actual discard are
different measurements.

## Balloon attachment and feature selection

vmmon explicitly enables the balloon in the krun launch builder. There is no
libvm or daemon balloon setting. The standalone helper accepts `--balloon`;
without it, it does not attach that device.

Adding `libkrun::BalloonDevice::new()` is sufficient to request automatic
capability selection. On macOS, reporting is advertised only after the existing
qualification probe passes for compatible private anonymous RAM and the VM has
**guest EL2 disabled**. Platform support for nesting alone does not disable it.
Unsupported providers, failed/inconclusive qualification, and nested guests keep
the balloon without reporting. Unrelated balloon features are preserved.
This is not a promise of traditional inflate/deflate functionality beyond what
libkrun already implements.

Qualification failure is a capability fallback, not a VM-start failure. Errors
that prevent safe cleanup of a qualification probe remain fatal. Linux retains
its existing reporting implementation.

## HostMemoryReclaimer

The guest kernel holds reported pages out of allocation until the host completes
the report. For validated ranges of registered private RAM, the host:

1. Removes the GPA mapping with `hv_vm_unmap`.
2. Advises each native host page with `MADV_FREE`.
3. Restores the same HVA/GPA mapping and its permissions immediately.
4. Acknowledges the report only after restoration or safe skipping.

Only completely reported, aligned host pages can be discarded. Coalescing must
not cross gaps, live pages, or region boundaries. No reports are retained for
later replay. No anonymous replacement mapping clears guest RAM.

Advice failure still attempts restoration. If restoration fails, the VM cannot
safely continue. An advice failure with successful restoration disables further
reclamation; negotiated guest features do not dynamically disappear, so the
agent cannot infer every subsequent host-side failure from sysfs alone.

The qualification probe checks guest-written page state and subsequent safe
reuse. It remains Silo/libkrun safety policy, not a claim about OrbStack's checks.
Successful advice is lazy and does not prove physical eviction under pressure.

## HostMemoryRemapper

Compatible guest-memory setup creates this component independently of balloon
attachment, reporting qualification, and guest EL2. Incompatible external/shared
providers do not get it. It operates on registered workload RAM only.

The VMM event loop owns scheduling:

- Initial and periodic deadline: 30 seconds.
- Before processing reports, remap immediately if at least 250 ms have elapsed
  since the last successful pass.
- Otherwise bring the deadline forward to that 250-ms boundary without delaying
  an earlier deadline.
- A successful pass schedules the next periodic pass 30 seconds from its start.

`mach_vm_remap(copy=false, FIXED|OVERWRITE)` reuses existing backing at the same
address. It does not discard guest cache or replay reported ranges. Callbacks
run while the owning VMM retains RAM; there is no detached worker surviving VM
teardown. Remapping failure remains fatal in libkrun, a deliberate stricter
policy than the recovered OrbStack timer's log-and-retry behavior.

## GuestCacheReclaimer

The agent has no reclaim configuration. Every ten seconds it checks for:

- A bound `virtio_balloon` device.
- Negotiated reporting feature bit 5, with FEATURES_OK and DRIVER_OK and no
  FAILED/NEEDS_RESET status.
- Writable cgroup v2 `memory.reclaim` interfaces.

Linux exposes negotiated features as a bit string in ascending bit-number
order, not a hexadecimal feature mask. Device presence alone is insufficient.
Negotiation/readiness is a prerequisite, not proof of reports arriving or host
physical discard.

The agent uses the root cgroup when that interface is available; otherwise it
uses writable immediate child cgroups. These include their descendants, so it
does not reclaim both parent and child. It does not create cgroups, move
workloads, change controller settings, or assume every guest has a suitable
hierarchy.

After twelve idle ten-second intervals, with CPU busy share at most 0.5%, it
reclaims from one target per tick in round-robin order. The requested amount is
bounded by RAM/32 (256 MiB to 1 GiB), retaining a 128 MiB cache floor in that
cgroup. File cache excludes shmem; reclaimable slab is included. Requests use
`swappiness=0`, and successful/partial requests may be followed by compaction.
The worker uses SCHED_IDLE and excludes its own work from idle sampling.

Missing capabilities reset the idle window and are rechecked automatically.
The agent logs capability transitions and failed operations. There is **no
fallback to global `drop_caches`**, and no tuning knobs or opt-out setting.
Guests without a managed agent do not run this policy. Guests without a usable
cgroup interface simply retain their cache.

The last-run metrics report requested bytes and observed guest cache before and
after. These are not a measurement of host savings or exact bytes reclaimed
from a particular cgroup under concurrent activity.

## Upgrades and validation

Remove `host-memory-reclaim`, `memory-reclaim`, and `memory-reclaim-after` from
daemon YAML. Old persisted installation records discard these retired settings;
old machine guest-policy fields are likewise not retained. New agent JSON
rejects the retired `memory_reclaim` key. Upgrade the CLI, vmmon (including its
private krun worker), and managed agent together. Running VMs are unchanged until restarted.

The OrbStack handoff in `~/Projects/orb-analyses2` informs this separation, but
Silo retains stock virtio reporting, its existing RAM provider, mapping
permissions, safety qualification, and fatal restoration/remapping error policy.
It does not copy OrbStack's custom report header or older-version private trap.
The handoff has not reconstructed the guest cache-reclaim service; the user's
knowledge of that service is separate evidence.

Unit tests cover feature masking, scheduler deadlines/throttling, guest sysfs
parsing, bounded reclaim policy, and retired configuration. Real HVF tests cover
successful qualification, unsupported-provider fallback, and live-data
preservation under periodic remapping without a balloon. Pressure-driven
physical-discard measurements remain separate, opt-in libkrun tests.
