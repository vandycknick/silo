# Real-VM smoke suite

This suite drives the staged CLI, daemon and runtime against real VMs. It is
intentionally outside CI and does not replace the unit or integration suites.

## Running

```sh
make smoke                                  # default: not slow
make smoke SMOKE_MARK=                       # all functional qualifications
make smoke SMOKE_WORKERS=1                   # default: 2, size for guest RAM
make smoke SMOKE_ARGS='-k lifecycle --keep'  # optional pytest selection
make smoke SMOKE_AREAS=restore,fork          # only these areas
make smoke SMOKE_AREAS=capture SMOKE_MARK=   # an area including its slow cases
make smoke-areas                             # list areas and their modules
```

Areas group test modules by feature (`silo_smoke/areas.py`). Each area is also a
pytest marker, so `SMOKE_ARGS='-m "restore and not daemon"'` works too. Every
module must belong to at least one area; collection fails otherwise.

`make smoke` stages and tests a fresh release build on every run, so results
never come from binaries older than the tree. `SMOKE_PROFILE=debug` selects a
debug build when that makes a failure easier to debug or trace.
Performance cohorts and budget arithmetic live in the separate
[serial perf suite](../perf/README.md); `make smoke` collects functional cases only.

`tests/test_exec_stdin.py` runs in the default selection with the small guest.
It checks a deterministic 64 MiB stdin SHA-256 digest, first-line and no-reader
early exits, an explicitly closed guest input pipe, empty input and `/dev/null`.
Run it with `make smoke SMOKE_ARGS='tests/test_exec_stdin.py'`.

Run as an ordinary user on a dev box with readable/writable `/dev/kvm` (or Apple
Silicon HVF). Use the repository's normal Rust/Go toolchain, Python 3.12+, `uv`,
ORAS, a C compiler that can link static binaries, `openssl`, `sqlite3`, OpenSSH, GNU coreutils, util-linux
(`findmnt`, `sfdisk`, `blkid`, `unshare`, `mount`, `umount`) and e2fsprogs
(`mkfs.ext4`, `e2fsck`, `debugfs`). The Rust toolchain file supplies both guest
musl targets. EROFS qualification additionally needs `fsck.erofs` and `dump.erofs`
from erofs-utils on PATH; those cases skip with an installation reason if absent.
First runs need internet access for pinned Cargo/Go modules, the published kernel,
Alpine fixture bytes and verified Distribution releases.

`smoke-prereqs` reuses `stage`, builds every Rust helper in `SMOKE_PROFILE` and
`CARGO_TARGET_DIR`, resolves Cargo's pinned libkrun sources and fetches the exact
resolved kernel config by its staged digest. No manual builds or environment
variables are needed. Overrides below remain optional. Slow selection also builds
the independent static collector when local Go >=1.26.6 is available, and an
isolated diagnostic IRQ runtime on Linux x86_64. Missing/old Go skips only the two
collector cases with the exact requirement. No Go toolchain is downloaded.

The parallel xdist lane (`--dist loadfile`) always finishes before the serial
lane starts. Both run even when the first fails; either failure makes Make fail.
No selected cases (pytest exit 5) is successful. `SMOKE_MARK=` removes the default
`not slow` filter; a final `-m` in `SMOKE_ARGS` overrides it. Reclaim and
fixed-port cases never overlap workers.

JUnit paths are suffixed `-parallel` and `-serial`. Each worker owns its fixtures,
Homes and short pytest base. Linux Homes, registries and the pytest base all
live under `${XDG_CACHE_HOME:-~/.cache}/silo/smoke`, which must be disk-backed:
guest disks are multi-GiB sparse files and reflink copies, and `/tmp` is usually
tmpfs (RAM). `TMPDIR` overrides the location (for example `TMPDIR=~/sm`) and is
refused if it is tmpfs. Long paths move only sockets/locks to `/tmp`.
Retained per-run evidence defaults to `$CARGO_TARGET_DIR/smoke/evidence/run-*`,
with unique cohort/worker suffixes. Failed workspaces remain; `--keep` also keeps
successes. Never share a live VM or mutable Home across workers.

### Remaining owner/tool opt-ins

```sh
# Existing owner-mounted writable ext4, visible in this process's mount namespace:
SILO_SMOKE_STOPPED_DIR=/absolute/owner-mounted-ext4 SILO_SMOKE_STOPPED_FS=ext4 \
  make smoke SMOKE_MARK= SMOKE_ARGS='tests/test_stopped.py -k host_ext4'

# Owner-published systemd/OpenSSH image with systemd-ssh-generator and vsock activation:
SILO_SMOKE_SYSTEMD_IMAGE="${SYSTEMD_IMAGE:?set the owner-published OCI reference}" \
  make smoke SMOKE_MARK= SMOKE_ARGS='tests/test_ssh_systemd_owned.py'

# Optional extra qcow2 oracle, if qemu-img is installed:
SILO_SMOKE_QEMU_IMG="$(command -v qemu-img)" make smoke SMOKE_ARGS='tests/test_cloud_disk.py'
```

The suite never mounts an ext4 filesystem on the host for you or requests sudo.
Published private images must already be accessible to Silo; anonymous public
system/distro defaults need no credentials. Local controlled registries are
automatically provisioned and never touch hosted credentials. Internet-dependent
`live` cases run with the normal selection, including `SMOKE_MARK=`.

### Prerequisite inventory

| Input / previous precondition | Resolution |
| --- | --- |
| CLI, daemon, monitor, netd, agent, initramfs, workload kernel | `smoke-prereqs: stage`, reusing normal build/acquisition/signing logic |
| `storage_acceptance`, `live_acceptance`, `root_metrics`, `overlay_candidate_lower`, `erofs_qualification` | Automatically built libvm examples in the selected profile |
| `format_upper` | Automatically built disk-image example |
| `native-live-api`, `guest-lifecycle-controller` | Automatically built silo-vmm examples; specific executable env overrides remain |
| Hardcoded debug/release example paths | Selected binary directory, derived from `CARGO_TARGET_DIR` and `SMOKE_PROFILE`; no cross-profile fallback |
| `SILO_NATIVE_ROOT` | Cargo metadata's pinned git libkrun checkout; read-only Python validators/sources, no native checkout build or mutation |
| `SILO_SMOKE_KERNEL_CONFIG` | Staged OCI kernel identity plus authenticated resolved-config blob; local `KERNEL_PATH` uses adjacent emitted `.config` |
| EROFS candidate kernel matrix | Staged kernel/config by default; `SILO_SMOKE_EROFS_KERNELS` optionally supplies named local kernels/configs |
| EROFS verifier source tree | Host `fsck.erofs`/`dump.erofs`, precise install skip if absent; `SILO_SMOKE_EROFS_UTILS` optionally selects a built tree |
| IRQ diagnostic producer/witness | Separate `smoke-diagnostic` target directory and real xtask stage with `restore-irq-probe`; per-test private runtime and automatically assembled witness |
| `SILO_SMOKE_FILESYSTEM_OBSERVER` / Go extractor | Existing `changeset-extractor` Make target, `CGO_ENABLED=0`, local Go >=1.26.6, only for eligible slow cases; precise Go skip otherwise |
| `SILO_SMOKE_EVIDENCE`, `SILO_SMOKE_RESTORED_EVIDENCE` | Automatically created durable per-run evidence; env overrides optional |
| `TMPDIR` | Optional durable scratch root (default `${XDG_CACHE_HOME:-~/.cache}/silo/smoke`); refused on tmpfs; runtime sockets stay short and separate |
| `SILO_SMOKE_STOPPED_DIR`, `SILO_SMOKE_STOPPED_FS` | Only actual host-ext4 gate is owner opt-in; exact enable command above |
| `SILO_SMOKE_CAPTURE_FS` | Optional assertion on the observed host filesystem, not fixture setup |
| Static C/Rust/assembly guest probes (`CC`, rustc, as/ld/objcopy/nm) | Built by session/test fixtures from repository or pinned native sources. The probe compiler is the first of `$CC`, `cc`, `gcc`, `/usr/bin/cc`, `/usr/bin/gcc`, `clang`, `musl-gcc` that links a static pthread program (`silo_smoke/toolchain.py`), so a dynamic-only `CC` such as Nix's clang falls through |
| Alpine and OCI fixtures, ext4 images | Downloaded with pinned integrity or constructed by existing fixture builders, never prebuilt by hand |
| Local loopback/Distribution registries and TLS CA | Existing automatic private registry fixtures and verified release cache |
| `SILO_SMOKE_SYSTEM_IMAGE`, `SILO_SMOKE_DISTRO_IMAGES` | Public defaults; optional reference overrides or explicit empty opt-out |
| `SILO_SMOKE_SYSTEMD_IMAGE` | Owner-published image opt-in, exact command above; no fabricated fallback image |
| `SILO_SMOKE_CURL_IMAGE` | Removed unused configuration; live provider test already uses the generated CA-trust fixture |
| `SILO_SMOKE_QEMU_IMG` | Optional extra oracle only, default PATH discovery when installed |
| `SILO_SMOKE_BIN_DIR`, `SILO_SMOKE_RUNTIME_DIR`, `SILO_SMOKE_BACKEND` | Derived target/profile/host paths and krun default; pytest options/env remain overrides |
| `SILO_SMOKE_CACHE`, `XDG_CACHE_HOME`, `SILO_SMOKE_KEEP` | Existing automatic cache and retention defaults |
| `PATH`, `HOME`, `PYTEST_XDIST_WORKER`, `SILO_NATIVE_API_EXECUTABLE` | Tool discovery, per-workspace isolation, worker labeling, internally supplied native entry, not manual inputs |


Phase 22 makes `linux-erofs-overlay-v1` the libkrun OCI default and removes the
flat profile and root-profile selector. Linux x86_64 stable 7.2.2 and
longterm 6.18.48 production roots passed boot/lifecycle and kernel-mutated
flatten export followed by raw boot. Independent umoci extraction used the prior
raw reference environment; a separate readonly EROFS traversal matched every
published-corpus row without exclusions. Performance must be remeasured in the
mandatory Phase 24 sweep. Live support follows native backend/host primitives. See the
[changeset conformance evidence](../runtime/oci/testdata/changesets/README.md#observed-admission-and-phase-22-default-gates).

### Controlled EROFS encoder qualification

`make smoke` builds the producer and uses the staged kernel plus its authenticated
resolved config. Install erofs-utils to enable the independent host verifier:

```sh
make smoke SMOKE_ARGS='tests/test_erofs.py --keep'
```

For an explicit multi-kernel matrix, `SILO_SMOKE_EROFS_KERNELS` may contain
`{"stable":"/absolute/stable/vmlinux","longterm":"/absolute/longterm/vmlinux"}`.
Each overridden kernel needs its emitted `.config` beside it.
The fixture producer authenticates packs, composes fsmeta twice, checks exact retained
loading, and publishes a descriptor through the existing storage/VMDK codec.
The suite runs upstream `fsck.erofs` and `dump.erofs`, then mounts the actual
VMDK in a guest using a static, independently authored C probe. It covers
empty/metadata-only packs, byte names and symlinks, ownership and timestamps,
xattrs and ACLs, hardlinks and special inode types, NULL chunks, 1024 device
slots, and a sparse file larger than 2 GiB. Rich fixtures also round-trip
export handles and verify indexed-overlay copy-up and clean remount.

The 1024-slot fixture uses structural fsck and guest reads instead of passing
1024 `--device` arguments, which exceed erofs-utils' 256-device CLI limit.
All other fixtures use `fsck.erofs --extract` to verify file data without
extracting host special files. Monitor identity, kernel/config digests,
descriptor backing digests, and guest output are retained. These are
controlled format/attachment checks, not end-to-end root or live-operation
evidence. Other host/architecture lanes remain pending.


### Controlled Distribution registry

`test_distribution_registry.py` runs CNCF Distribution 3.1.2 as a real local
TLS server, with anonymous access and deletion enabled. It verifies exact-byte
OCI VM artifact graphs, shared blobs, tag replacement, upload continuation
across restart, missing-dependency refusal and offline garbage collection.
The initial Linux run passed all 23 registry tests, including the existing
loopback-registry test. This is registry compatibility evidence, not yet an
end-to-end Silo artifact round trip or GHCR qualification. GHCR is deferred.

The harness downloads the official Linux amd64 or arm64 archive and verifies
both archive and extracted executable against pinned SHA-256 values in
`silo_smoke/distribution_registry.py`. No Docker daemon is needed. For offline
execution, seed the exact release archive under
`<SILO_SMOKE_CACHE>/distribution-registry/3.1.2/<arch>/`.
There is no macOS release asset or substitute server fallback.

```sh
uv run --project smoke pytest smoke/tests/test_distribution_registry.py smoke/tests/test_registry.py
```

The registry uses the suite's private CA. Offline GC requires the server to
be stopped; it restarts on the same address. Failed runs retain identity,
configuration and server/GC logs. A registry fixture never modifies the
user's Docker configuration or hosted registry credentials.

`test_artifact_stopped.py` drives the staged CLI in local and private-daemon
mode against this registry. It covers raw and converted images, raw/zstd
identity, source OCI deletion, offline registry GC, decoded-flat eviction,
chunk-only reconstruction and real guest boot with retained boot assets. Its
interrupted pull case removes a real registry chunk, corrupts one completed
local cache entry, then proves the retry refetches only invalid/missing bytes.
Snapshot push is not available, so the suite has no snapshot publication case.
`image pull` and `create` refuse a snapshot artifact, and `restore` refuses an
image artifact, with the right command and before any chunk or content-record
blob appears in the registry access log. The snapshot artifact is a real image
artifact whose config is relabelled as snapshot content.
This establishes the controlled Distribution lane only; GHCR remains deferred.

```sh
make smoke SMOKE_ARGS='tests/test_artifact_stopped.py'
```

### Stopped handoff between runtimes

The v1 handoff sends binary roots and map nodes qualified by digest, stream,
height and first index, separately from root/index-bound 8 MiB payloads.
Source authorization follows only the named root-to-node path; artifact object
tables remain digest-only. The independent disk oracle uses the sparse
map codec and raw decoded-byte SHA, preserving exact changed-chunk reuse,
prior-owner return and payload-byte accounting. It never equates a RAM's
64 KiB identity leaf to a transport object. Old protocol sessions are refused.
The warm-closure oracle excludes dirty-tracking-only baseline roots, not boot,
lower or managed read-only dependencies. It authenticates every required map
node and still requires the destination's immutable flat streams.


`test_handoff.py` drives two real daemons with independent Homes, runtime IDs,
config directories and run roots. It covers raw relocation and growth, a
deliberately stopped running-source fork, stale-plan refusal without catalog
mutation, destination crash/recovery, and repeated layered-overlay return cycles.
Read-only catalog queries, private-file hashes and guest markers verify the
result independently of the coordinator's reports. The old owner must refuse
start, and terminal recovery must work after payload cleanup.

```sh
uv run --project smoke pytest smoke/tests/test_handoff.py
```

All five Linux cases passed against the staged runtime in 207.63 s
(`.tmp/plan/evidence/phase-19/handoff-smoke-freshness.xml`). This qualifies the
two-local-runtime stopped protocol, not remote transport or live execution
relocation. The cases are included in the default non-slow suite.


### Guest lifecycle controller (Phase 12)

Make builds the host-only helper and stages the kernel/init/agent automatically.
The helper is an example with `test = false`, not a Cargo test or a production
control route:

```sh
make smoke SMOKE_ARGS='-k freeze_real_kernel'
```

`SILO_SMOKE_GUEST_LIFECYCLE_CONTROLLER` optionally selects an absolute helper path.
The matching target/profile example is used by default. Tests retain its digest,
staged kernel/agent/initramfs digests, private fixture,
serial output and observed counter/epoch values. A fresh ordinary production
`VirtualMachine` owns its production worker and native host-only vsock mux;
cleanup force-stops/reaps that exact worker and closes attachments even when
an assertion fails while the guest is frozen.

`SILO_SMOKE_GUEST_LIFECYCLE_KERNEL` selects Main's exact locally built workload
kernel instead of the staged default; its adjacent emitted `.config`, when
present, is copied and hashed with the evidence. This does not claim a runtime
generation acknowledgement merely because the emitted symbols are enabled.

The positive cold-guest test independently reads `cgroup.events`, observes
native-exec and SSH workload membership/counter progress, userdata placement,
double-forked descendants in a nested workload group, empty-root freeze,
responsive status/metrics while frozen, mutation refusal, joined duplicate
freezes, exact thaw, a deliberately discarded thaw acknowledgement, real
next-epoch recovery freeze, stale-thaw rejection and unchanged source
identity. Contained image-init coverage is in `test_contained_init.py` below.

These are cold guest API oracles only. They do not qualify native pause,
capture, restored generation/reseed ordering, restored network replacement,
inherited listener/session reset, activation hooks, or restored identity/
shutdown cutover. Those lanes are the restored activation tests below; no
absent lane is counted as passing and no cold activation substitutes for the
exact host generation barrier.

### Public pause and resident resume (Phase 13)

```sh
make smoke SMOKE_ARGS='tests/test_pause.py tests/test_guest_lifecycle.py -k pause --keep'
```

The real CLI gate retains one guest counter stream across pause and ClockOnly
resume. It checks frozen workload evidence, user-owned authority, fresh-manager
reconciliation, exact replay and GetOperation, stale-token and paused-cancel
refusal, fenced new execution, unchanged boot/run identity and reseed count,
and the exact generation acknowledgement. A second pause is stopped without
resuming; the gate waits for the actual owners and checks storage-lease release.
An uncontained handoff is rejected before allocating a live command.

`live_acceptance` is a standalone Rust public-API consumer, not a VM-starting
Cargo test. Live support follows the backend and host's native primitives;
runtime files and environment variables do not grant capabilities.

### Contained image init (Phase 29)

`tests/test_contained_init.py` is a Linux-only slow real-VM module. It boots
`ghcr.io/vandycknick/archlinux:latest` with systemd and
`docker.io/library/alpine:latest` with busybox init. The OpenRC cases install
`openrc busybox-openrc` into their own Alpine VM, enable cgroups and crond,
sync, then stop/start. No case overrides `init=` and no machine is shared
between tests. The ordinary `pulled_images` fixture caches published image
inputs; workspace teardown owns sources and all restore/fork children.

```sh
uv run --project smoke pytest smoke/tests/test_contained_init.py -m slow --keep
```

Public image pulls, OpenRC package installation and the networkd DNS probe
need working registry/package/network access. Arch probes use systemd tools and
`/proc`, not optional `ip` or `ps` packages. No ticker compiler or offline disk
reader is needed.

The raw and default layered-root matrix checks `contained-init`, PID 1 and
exec namespace membership, pause/resume with an existing counter session,
memory snapshot/restore and fork, retained boot identity, rotated child identity,
and surviving OpenRC services under the image cgroup. Systemd gates check
delegated `MemoryMax=` OOM and `CPUQuota=` enforcement, agent resource
protections, an exec's private cgroup mount, and a running ticker service in children.
The ticker appends realtime nanoseconds every 50 ms to `/run/silo-contained-ticks`
on tmpfs, so the child inherits the source prefix through captured RAM. The
ordering oracle finds the largest gap between consecutive ticks, requires a gap
of at least 500 ms, and rejects any tick after it that precedes the nanosecond
mtime of `/run/silo/generation`. A `.path` unit must record the child
run ID after activation, and the source identity stays unchanged. Busybox
children must not acquire a machine-id file; an existing empty file must stay empty.

Additional independent cases cover systemd-networkd DHCP after child network
replacement, a deliberate privileged `setns` escape into `silo/control`
refused with `guest-containment-escaped` while source exec remains usable,
successful pause after removing that task, and immediate write/stop/start
durability without a test-side sync. Every initial-namespace cgroup2 probe
mount preserves `nsdelegate,memory_recursiveprot` in a private mount namespace.
Commands, JSON identities, refusal diagnostics, inherited ticks, generation mtime
and post-thaw reactions are retained by the evidence-recording CLI/workspace.

Run the same selection with private workspaces on Btrfs and ext4; the module
does not substitute one host filesystem for the other or claim either lane
has passed merely from collecting it.

### Full live capture (Phase 14)

`tests/test_capture.py` runs directly against the staged runtime. Every live
operation is supported when the backend and host provide its native primitive.
The monitor's `buildIdentity` is informational `v1:silo:<target>:<version>` metadata.
Snapshot compatibility uses `liveStateSchema` and guest `architecture` only;
restore refuses mismatches in those fields, not different source or build inputs.

`test_native_capabilities.py` checks the selected staged monitor using ordinary,
launch-environment and mutable-grant queries without starting a machine. Native
live operations must report `supported`; mutable files cannot change the result.

Capture, restore, fork and incremental suites use the selected profile:

```sh
make smoke SMOKE_MARK=slow SMOKE_ARGS='tests/test_capture.py tests/test_capture_multidisk.py tests/test_capture_lifecycle.py --keep'
```

The root-family gates exercise raw and EROFS-overlay matched disk/RAM cuts,
source continuation, acquired and borrowed pause authority, sealed-file
immutability, independent retained RAM, and retention through source/name
removal, home relocation and GC. Unsupported readonly virtiofs must be refused
before staging or freezing. The child-only syscall tracer holds real capture
write and record-settlement boundaries for manager/monitor/worker death, plus
pool-file sync, pool publication and catalog checkpoint barriers. The catalog
boundary is an actual WAL sync after capture provenance commits but before
the checkpoint can be acknowledged.

The borrowed case deliberately omits `--preserve`: admission must persist
`resumePolicy: preserve`, keep the source paused and retain its exact user-owned
resume token, as specified by ADR 0021.

Pre-seal cancellation waits for the monitor's exact request-admission event
before releasing the held syscall; it verifies acquired-resume, acquired-preserve
and borrowed-pause policies. Post-seal cancellation preserves the known seal.
The cancellation gate held at temporary-seal unlink verifies the two names are
the same private inode with exactly two links. After release the normal immutable
inventory still requires a single link, identical seal bytes and disappearance
of that temporary name. Crash recovery must preserve and publish any linked
coherent seal; it must not silently downgrade the two-link crash window.
These are process-crash tests, not physical power-loss simulation. Retain failed
workspaces; archive evidence before pruning completed generated payloads.

The lifecycle cases hold real boundaries across manager death, stop and
post-seal cancellation. Reflink captures write an identity-pending cut before
continuation and the final seal afterwards. Stop is exercised before continuation
at execution/cut settlement and on a preserved source at final seal settlement;
neither stop path may resume or thaw. Run death during disk settlement leaves
a retained pending cut available for identity recovery, without fabricating a
continuation failure. Missing continuation evidence stays pending while the exact
run lives and becomes unknown after it ends; a pending cut is not published until
disk identities complete. Completed continuation evidence is retained unchanged
across final seal settlement and cancellation. If stop interrupts a manager after
publication, replay after exact-run death must finish release of the same capture.

After an identity-pending cut, the unchanged-file oracle admits newly staged
disk map nodes only after authenticating their exact closure from the sealed
disk roots. Inherited nodes resolve through the pool; arbitrary extra files,
unreachable nodes and missing or corrupt named nodes still fail. Every
pre-existing file retains its byte and inode checks.

Holding the worker's vsock muxer after cut publication, before continuation, exercises
genuine deadlines without injected errors or changed timeouts. The failure
oracle checks the coherent published seal, Error fences and the source's durable
workload counter, not survival of an exec session whose readiness was invalidated.
The snapshot durability gate records successful `fsync`/`fdatasync` calls
through real `/proc/<tid>/fd` device/inode observations. Every captured pool
payload must have a file barrier and a later publication-directory barrier,
followed by the catalog barrier. Capture staging must have none.


### Execution restore and retained closure (Phase 15)

`tests/test_restore.py` drives actual `silo snapshot create VM --name <snapshot> --memory`
followed by `silo restore <snapshot> --name <child>`, with automatic execution-kind
dispatch and no cold-boot recovery fallback:

```sh
uv run --project smoke pytest smoke/tests/test_restore.py -m slow -k 'not pending_hardware_irq' --keep
```

The raw and EROFS-overlay cases cover acquired and borrowed freeze authority,
fresh machine/run/generation identity and reseeding, unchanged boot ID, sibling
disk isolation, exact captured kernel/initramfs/agent objects, source removal,
home relocation, GC, recapture and generation-lease release after owned processes
are reaped. The detached `restore_execution.c` daemon is independent of the
source exec session. Its guest-local read protocol exposes sustained register
sentinels (GPR, x87, SSE, and YMM when genuinely enabled), a parked SIMD worker,
timer progress and pending timerfd/signalfd events. An independent host reader
reads the pinned RAM page and sealed disk log; every record at the boundary and
the exact first resumed append must be consecutive, not just a later larger value.
The timerfd/signal events are kernel-event witnesses, not hardware IRQ proof.

Corruption cases alter real captured RAM, disks, state/layout/maps, boot assets
and provenance. Compatibility cases use the public native execution codec to
alter a real CPU/profile/schema/architecture/XSAVE envelope, then rebuild the
object digests, canonical snapshot identity, dependency edges and
authenticated local seal. Only the precise native refusal subject satisfies
those cases. Schema and architecture refusal is intentionally checked before
device decoding; the original device binding is retained explicitly. All
rejections require no child/catalog/budget leak.
Verification consumers may leave an unlocked stable lease inode by pool design;
unsupported selected-backend refusal may not acquire even that consumer.
The live suites use automatically built matching-profile helpers next to the CLI.
`SILO_SMOKE_NATIVE_LIVE_API` optionally overrides the native entry.
Foreign-lane compatibility still requires a real foreign-lane snapshot, not a
synthetic mixed-architecture envelope.

The hardware IRQ case uses an isolated diagnostic stage built automatically for
eligible slow selections on Linux x86_64. The production stage remains unchanged.
A per-test private runtime replaces only its monitor and uses the diagnostic
manifest generated by the existing xtask staging path. The witness is assembled
from Cargo's resolved libkrun sources with `as`, `ld`, `objcopy` and `nm`, with
source/binary/symbol digests and exact monitor build identity retained.

### Restore activation lifecycle (Phase 15)

`tests/test_restore_lifecycle.py` uses the same staged runtime.
Its VM cases are `slow`; the host-only oracle cases are not:

```sh
uv run --project smoke pytest smoke/tests/test_restore_lifecycle.py -m slow --keep
```

Each case boots a one-vCPU `--network private` source with the
`restore-network` witness (`virt/vmm/tests/guest/restore_network.c`): a
keepalive TCP stream and an unconnected UDP sender (sequence plus fresh
getrandom UUID) to real host peers through netd's host-loopback NAT, a forward
target listener and a durable progress record. A preserving memory snapshot is
restored with the real `silo restore`. The workspace selects netd's own packet
capture (`networking.drivers.netd.pcap`); the child's capture and trace log are
followed from creation so destroyed children keep their evidence.
Before first launch, the network fixture materializes its fixed-size progress
record in the stopped private ext4 **upper**, including namespace and extents.
Seeding only the OCI lower would require guest OverlayFS copy-up, whose
directory metadata can remain journal-only even after the witness's
`fdatasync`. The independent `debugfs` oracle intentionally never replays that
journal and still requires the exact record and same-process progress.
The capture is nanosecond classic pcap with `LINKTYPE_ETHERNET=1`, recorded
at netd's vfkit datagram connection in both directions, before ingress switch
filtering and after successful egress writes. Original Ethernet headers,
including ARP and IPv6 frames, are retained; MAC addresses are never inferred
from configuration. The old stack-level `LINKTYPE_RAW=101` capture stripped
ingress MACs and observed egress before Ethernet headers were added, so it
cannot satisfy this oracle and is rejected. Capture write failures terminate
the attachment and are reported on close rather than silently losing evidence.

The positive case waits up to the normal 90-second readiness bound for the
final `restore activation started` event before asserting the full sequence.
CLI success can precede the asynchronous trace follower's next poll; no
acknowledgement or ordering assertion is omitted when waiting for those bytes.
Order evidence is the child monitor's `restore ...` trace events (listed in
`silo_smoke/restore_lifecycle.py`). Wire evidence is netd's capture and, under
`stopped_trace` with `observeNetEgress`, every native `virtio-net` send toward
netd. The positive case requires no frame before `restore exposure committing`,
only the reserved destination MAC/IPv4 (no source MAC, IPv4, ARP or
MAC-derived IPv6), host delivery, Running only after the native commit, the
same restored process, rebound machine forward, no reopened TCP stream, exec
session or session forward, and divergent UUIDs for equal sequences once the
source resumes. Failure cases hold real native threads only after the event
preceding the action: the sole `fc_vcpu` at its next `KVM_RUN` (missing or late
generation ACK), the `vsock muxer` (undelivered Activate, crashes) or the native
socket write carrying the actual guest THAWED gRPC response (lost Thaw ACK,
refrozen or reaped). That reply is matched to the logged activation ID, with
HTTP/2 DATA and short-write reassembly, not to a thread name or an unrelated
socket write: Unix proxy replies can be forwarded by the virtio event owner.
The held receipt retains the response bytes proving guest thaw before delivery.
Listener conflicts and failing activation hooks need no hold. Failed startup
never publishes Running or sends traffic past the fence. Manager death cancels
startup and requires positive child reaping, including after an uncertain Thaw.
Worker death is observed during activation rather than at the startup deadline.
The stop-only gate suspends the live manager so it cannot clean up the parked
`activation-failed` child before inspection: resume, start and pause are refused,
listeners remain closed, and normal stop must reap it. The tracer explicitly
detaches only that manager before SIGSTOP; monitor/worker tracing remains active.
These cases require monitor events and `--activation-hook`; without them they
fail, never skip.

### Live fork acceptance, crash and sharing gates (Phase 16)

`tests/test_fork.py` runs delivered native fork directly against the same staged
runtime selected by `SILO_SMOKE_BIN_DIR` and `SILO_SMOKE_RUNTIME_DIR`:

```sh
uv run --project smoke pytest smoke/tests/test_fork.py -m slow --keep
```

The default public-vsock-off regression creates without `--vsock`, captures and
restores one child, then live-forks two more from the same source. Every child
must reach Running, execute commands and continue the guest witness without
creating a public `vsock.sock`. The internal agent vsock mux remains required;
the optional public surface is recreated after Activate only when configured.
Run this case alone with the same staged runtime:

```sh
make smoke SMOKE_ARGS='tests/test_fork.py::test_live_restore_and_fork_without_public_vsock -m slow --keep'
```

Every case drives the real `silo fork SOURCE --live` against the detached
`restore_execution.c` witness. Oracles: the CLI's single `LiveForkResult`
document (strict keys, kebab `kind` tags, every requested child named with a
reserved machine/run identity), the durable journal (`live_fork`,
`live_fork_child`) and `fork_event` CLOCK_MONOTONIC phase stamps, bracketed by
the harness's own dispatch/exit clock; the authenticated local cut under
`images/tmp/<operation>/cut`; source monitor trace lines; `/proc`; and the guest.

- Four children (raw and flat profiles, `--network private`, a source host
  forward): all Running with distinct machine/run/MAC and private-network
  identities matching their bound restore requests. Each netd process owns
  a distinct instance and Unix data socket, and its reserved address matches
  the guest; numeric IPv4 may repeat across those isolated networks. Fresh
  VM generation, inherited boot ID, no
  inherited forward, matched RAM/disk cut read independently from the cut,
  exact continuation in every child and in the resumed source, distinct
  writable inodes, one shared RAM inode and no unowned VM process.
- Child k (index 2) fails in its own activation hook after the seal; the result
  names it `failed`/`activation` while its siblings run and continue the cut.
  A failed child is destroyed or stop-only `activation-failed`, never Running.
- Physical sharing for N = 1, 2 and 4: each child reads the same 128 MiB guest
  tmpfs blob from the baseline; the exact `rw-p` RAM VMAs of every child's
  krun worker share one (device, inode); RSS minus PSS proves shared clean pages;
  a 32 MiB private write grows only the writer's `Private_Dirty`. RSS sums are
  recorded but never used as physical RAM.
- Source stop, removal and prune leave the cut's RAM inode and bytes intact
  while children run; a child can be recaptured and restored. Stopping and
  removing the last child then lets prune remove the operation's transient root.
- Pre-freeze refusal: 17 children without `--max-children`, a 100%-private
  batch twice `MemAvailable`, and sixteen children under `RLIMIT_NOFILE=48` are
  refused with no capture staging, no source trace staging line, no child, no
  cut and no new ledger record for this home. A second same-user home holds an
  admitted batch (its capture held by `stopped_trace` before the seal); home
  A's batch that alone fits is refused with the reported requirement including
  home B's batch. Home B is then cancelled before its seal: no child or cut, its
  ledger records gone and the source `unchanged` and still running.
  Both batches are sized against `MemAvailable` minus the existing same-euid
  ledger reservations, including capture scratch, pending children and
  inode-deduplicated bound RAM. Existing homes are neither cleared nor ignored.
  The pre-seal gate remains the native `pwrite64` into `execution.state`;
  cancellation is checked when that execution stage completes, before sealing.
- Post-seal cancellation (held at final seal settlement) leaves every
  child Running or Cancelled. Manager SIGKILL before the seal recovers one cut
  (never a recapture) and abandons every child; SIGKILL right after the first
  durable child stamp recovers by reconciling submitted children and
  abandoning the rest. Recovery runs through `silo fork --operation`; no case
  leaves an orphan monitor/worker.
- A running source may keep mapping its accepted capture baseline, and capture
  GC waits for that exact source launch lease. Every case therefore asserts the
  cut's removal only after its children and the source run have ended and
  prune has run; the source-deletion case alone proves retention by children.

All new cases are `slow`; the default selection and its identities are
unchanged. Traced cases use the existing `stopped_trace` controller through
`silo_smoke.fork_process`, so its 240 s whole-session bound applies.


### Host memory reclaim (Phase 26)

`tests/test_reclaim.py` runs the host memory reclaim scenarios against real Linux/KVM
workers. It uses the same `linux_only` and `slow` markers as capture, restore,
fork and incremental suites, and parametrizes both raw and layered guest roots.
The ordinary workspace uses the Cargo target filesystem. To exercise ext4, point the
stopped-lane variables at an actual mounted writable ext4 directory;
all machine disks, snapshot RAM and catalog bytes stay on that mount, while
generated sockets use a short `/tmp` runtime directory. `findmnt` verifies the
requested filesystem in the test process's namespace.

```sh
make smoke SMOKE_MARK=slow SMOKE_ARGS='tests/test_reclaim.py --keep'

SILO_SMOKE_STOPPED_DIR="$MOUNT" SILO_SMOKE_STOPPED_FS=ext4 \
  make smoke SMOKE_MARK=slow SMOKE_ARGS='tests/test_reclaim.py --keep'
```

Use the same staged x86_64 live-capable workload kernel, agent and initramfs as
the restore suites, with `/dev/kvm`, `sqlite3`, `findmnt`, a static C toolchain
(`CC`, autodetected) and the matching `native-live-api inspect-devices` example.
The staged kernel's actual emitted config is resolved automatically;
`SILO_SMOKE_KERNEL_CONFIG` is an optional override. Missing `CONFIG_PAGE_REPORTING=y` or
`CONFIG_VIRTIO_BALLOON=y` fails with the missing options named. The test also
decodes a real saved balloon device to require negotiated free-page reporting.
An arbitrary config file is not proof that it built the tested kernel; retain
the staging/build provenance with the run.

Host reclaim telemetry is initially absent until the worker publishes its first
report; guest readiness is not a telemetry-publication barrier. Sampling waits
within its existing 60-second deadline for that report, still rejects malformed
or ineffective reports immediately, and never counts an absent sample as quiet.

The fixture uses the existing pinned BASIC Alpine image, whose `/sbin/init` is
removed, plus a small statically compiled C workload. Create explicitly passes
`--kernel-arg init=` so the agent remains PID 1. No Python/compiler is required
inside the guest. A dedicated 3 GiB tmpfs under `/dev/shm/reclaim` holds exactly
2 GiB of `0x5a`; rewriting changes the first 1 GiB to `0xa5`. Host and guest
SHA-256 checks cover every payload byte. A writable `MAP_POPULATE` anonymous
mapping then allocates and scans every byte of a fresh 2 GiB for zero, rather
than merely reading the guest's shared zero page.

Named bounds in `silo_smoke/reclaim.py` are intentionally fixed:

- `BASELINE_MARGIN = 512 MiB`: boot `RssAnon` must return within this margin of
  its pre-allocation baseline. A 2 GiB allocation/read and each free must move
  at least 1.5 GiB of residency/released-byte evidence where applicable.
- `COW_MARGIN = 256 MiB`: a 1 GiB rewrite must grow `RssAnon` by 768-1280 MiB.
  Freeing restored memory must drop at least 768 MiB each of `RssAnon` and
  `RssFile`, and return each within 512 MiB of the lazy-restore baseline.
  These tolerances admit kernel/agent/allocator metadata without accepting a
  missing gigabyte of reclaim.
- `RESTORE_RSS_DIVISOR = 4`: immediate restored RSS must be at most one quarter
  of the populated source's RSS, distinguishing lazy COW restore from copying.
- `RECLAIM_TIMEOUT = 60 s`, `POLL_INTERVAL = 0.5 s`: bounded monotonic polling
  checks actual `/proc/<krun-worker-pid>/status` values and public monitor
  counters. Elapsed time alone never passes a reclaim assertion.

Worker discovery follows the existing monitor-child helper, not the CLI's
monitor RSS. Every sample records worker PID, `RssAnon`, `RssFile`, `VmRSS`,
monotonic observation time and the snake_case `silo info --format json`
`host_memory_reclaim` object. Boot/restored-private backing, requested/effective
true, reason `none`, zero `mapping_limit_skips` and zero failed operations are
required; `released_bytes` must grow after every tested free.

The first scenario checks boot reclaim before and after capture, lazy restore,
shared reads, private rewrites, anonymous zero reuse, unchanged staging and
published snapshot RAM hashes, and a second restore of the original seeded
payload. After the restored child frees its payload, a genuine incremental
capture is authenticated and compared byte-for-byte with the existing
frozen-full oracle at the identical pause, then restored and scanned again.
A child-local full baseline before the rewrite prevents activation-time reports
of inherited free pages from hiding that check behind dirty-crossover fallback.
The second scenario live-forks two children, gives each private COW pages and
frees them separately: the sibling's private residency and exact bytes and the
source's seeded bytes must survive the other's reclaim.

These are 4 GiB VM tests with real 2 GiB resident payloads and multiple retained
4 GiB logical RAM artifacts. Provision host memory/disk space accordingly and
run sequentially, not with pytest-xdist. All registered VMs stop on teardown.
Successful ordinary runs remove their workspace/snapshots; `--keep` or a
failure retains stopped VM and snapshot evidence, including
`reclaim-samples.log`, snapshot hashes and kernel-config provenance.

### Incremental capture (Phase 20)

These are maintained **functional** gates, not timing budgets. Use the same
staged KVM x86_64 runtime and VM-generation-aware workload kernel as the restore
gates. The CLI, monitor and helper examples must be staged together:

```sh
make smoke SMOKE_MARK=slow SMOKE_ARGS='tests/test_incremental.py --keep'
make smoke SMOKE_MARK=slow SMOKE_ARGS='tests/test_restore.py -k "corrupt_real_closure or real_native_incompatibility" --keep'
```

Prerequisites are `/dev/kvm`, a static C toolchain (`CC`, autodetected), `debugfs`,
`sqlite3`, the restore fixture kernel/agent/initramfs and loopback TLS support.
The host-writer gate additionally requires the workload kernel's
`CONFIG_PAGE_REPORTING=y` and `CONFIG_VIRTIO_BALLOON=y`, a negotiated reporting
queue and the matching `native-live-api inspect-devices` example. No missing
driver, absent reports or unsupported lane is converted into a passing test.
Artifact gates also use the existing pinned controlled Distribution binary
(downloaded through its fixture when not already cached) and offline registry
GC. The child-only syscall gates require Linux x86_64 ptrace of owned descendants;
they never attach to an unrelated process. Every command is bounded, and failed
workspaces retain their evidence.

`test_incremental.py` pins guest tmpfs pages and independently reads their exact
GPAs from sealed RAM after CPU stores, real O_DIRECT block-read DMA, repeated
same-page writes and explicit nonzero-to-zero replacement. The independent
`silo_smoke.stream_map` oracle decodes binary roots and every authenticated node,
rebuilds roots with hashlib from all output bytes, and validates native streamed
change records. RAM identities are 64 KiB; disk identities and transport payloads
remain 8 MiB. Root/control records are bounded, not dense digest arrays. Tests
cover catalog bindings, exact changes within owned pinned pages, expected
64 KiB leaf coverage, the lowered crossover, explicit full selection and
worker-local baseline invalidation. Its first
restored-child recapture must reuse the inherited root/token while retaining
restore-time dirties. A real RAM-fsync
pre-seal cancellation must preserve the abandoned dirty union. The separate
coverage-loss case first observes an actual successful KVM_GET_DIRTY_LOG return
(and its returned bitmap), substitutes only `-EIO`, then requires actual-state
recovery, a full `coverage-lost` capture and renewed incremental reuse. This is
an explicitly recorded syscall fault, never injected success or synthetic RAM.
The canonical catalog authority is `stream_map_root`; a local capture or pack
need not have a `storage_stream` representation row. When that optional row
exists, its root, length and profile must agree with the admitted root.


The host-writer case requires an observed `/dev/hvc0` serial token, byte-exact
bidirectional vsock transport and actual balloon free-page-report completions.
The CLI's stderr also carries reconciliation diagnostics. The echo still requires
byte-identical stdout and exit zero; stderr may contain only the exact
`ActiveLease` cache-cleanup deferral diagnostic, never guest errors.
It decodes the bounded saved device queues, reads their real used indices and
entries from sealed RAM and requires the reporting ring's 64 KiB identities in
the native change coverage. An explicit full capture at the same borrowed pause must have identical
complete RAM bytes, identity and layout before the source can resume.

`tests/test_stream_map.py` supplies host-only real-file codec/oracle rejection,
boundary, short-tail, zero and randomized-edit evidence. `test_raw_live.py`
flips actual RAM/disk bytes after warming verification, then requires
`snapshot verify` to report the exact 64 KiB/8 MiB index and range. It also
refuses corrupt map-node closures, refuses a disk-only snapshot of a running VM
before capture, lists MEMORY `yes`/`no`, and restores a memory snapshot with
`--without-memory` as a stopped VM that cold-boots from the captured disks.
`test_harness.py` checks old-format home
refusal without conversion or deletion. Existing homes and artifacts must be
recreated for this hard-breaking cutover.

The existing real-closure corruption and exact-native-refusal matrices also run
against genuinely incremental-derived snapshots. They cover byte corruption of
RAM, root, layout, execution/device state, boot assets, map roots/nodes and
provenance, plus exact CPU, XSAVE, native-producer, host-build, unscaled TSC-rate
and captured MSR-model-value refusals before allocation. An empty actual MSR
inventory refuses fixture preparation instead of inventing a register. These
checksum-corruption cases do not claim to replace bounded
malformed-schema/ABI/GPA decoder tests. KVM arm64/GIC and HVF/macOS/timebase
lanes remain outside this KVM x86_64 fixture, not inferred qualified.

Native `liveBytesRead`, baseline copying, full/overlay writes,
`identityBytesHashed` and mandatory `wholeFileBytesHashed` are distinct evidence.
`zeroRunBytesCovered` counts complete zero runs represented in the resolved image,
whether omitted, punched or written. `zeroBytesPunched` counts zero bytes
deallocated from a reflink-seeded destination, never the baseline.
`knownZeroBytesSkipped` counts live boot RAM bytes not read because cut-bound
pagemap metadata proves zero origin. `explicitZeroBytesWritten` counts only
zero-valued bytes physically written, including zeros within mixed writes.
Zero-transition smoke checks use zero-run coverage together with byte comparisons,
not physical writes, because hole punching also represents zeros correctly.
The independent smoke oracle deliberately reads immutable output for
authentication; it does not count that as a live RAM scan. No unchanged timing
target is relaxed or qualified by these functional cases.

### Raw/qcow2 import, cloud disks, boot pinning and conversion (Phase 17)

`tests/test_cloud_disk.py` uses only the staged CLI and the staged monitor.
The automatically staged workload kernel supplies GPT/MBR scanning, `VFAT_FS`,
`NLS_CODEPAGE_437` and `NLS_UTF8`. Host tools include `sfdisk`, `blkid`,
`e2fsck`, `debugfs` and `sqlite3` on PATH. `SILO_SMOKE_QEMU_IMG` optionally
names a `qemu-img` for an additional `check`/`compare` of every qcow2 fixture;
when unset, PATH discovery enables it if installed; otherwise the log records no cross-check.

```sh
make smoke SMOKE_ARGS='tests/test_cloud_disk.py -m linux_only'
make smoke SMOKE_ARGS='tests/test_cloud_disk.py --backend vz'   # macOS VZ lane only
```

A session fixture creates two never-booted whole-disk ext4 roots from the
loopback registry (identical except `/etc/phase17-identity`, both carrying
`/usr/local/bin/phase17-probe` and an ESP fstab line). Smoke-only bounded
encoders then write GPT/MBR tables, a FAT16 ESP and qcow2 v2/v3 containers
(allocated, DEFLATE-compressed, unallocated and v3 explicit-zero clusters, exact
refcounts). Each table is read back by `sfdisk --json`, the ESP by `blkid`,
ext4 partitions by `e2fsck -fn`/`debugfs` on byte-range extracts; no Silo
parser is the oracle. The guest oracle is the probe: the mounted root's device
number, partition number/start/size and its parent's virtio serial.

Gates: raw and both qcow2 encodings import to one ImageId/stream with
accumulated names/provenance, never-booted private roots equal the raw
SHA-256, inputs stay unmodified; whole-disk, GPT (sparse slot 4) and MBR slot 4
roots boot with the identical pinned kernel/initramfs/agent and stop clean
(ESP never mounted); DPS auto refuses ambiguous/missing/wrong-ISA/no-auto/
read-only and foreign platforms with candidates; unsupported containers,
forbidden qcow2 features, special files, symlinks and incompatible layouts
refuse before image/name/machine publication; a cloned GPT on an attached
disk never replaces the `silo-root` serial; fstab-mounted vfat reads with NLS
options and a late ESP mount is never certified clean; opaque expansion keeps
both GPT copies, the partition and the ext4 block count; pinned bundles survive
source and packaged-asset removal and change only by `silo set
boot-assets=packaged` while stopped; snapshot creation preserves semantic
configuration and every snapshot disk; `silo create` refuses a snapshot with a
hint to use `silo restore`, which then restores it; an image and a snapshot
both named `hello` coexist, `create` and `restore` each resolve only their own
kind, and a name of the other kind is refused with the right command;
`image rm NAME` removes one name and the record with its last name, `image rm
ID` removes the record and all names, and `image prune` keeps unnamed images a
machine uses; explicit conversion is
cached per manifest/platform/flattener across packaged upgrades and boots.

Shuffled attachment order cannot be produced by libvm (root is always first),
so one test uses a disposable agentless candidate launch through the shipped
monitor: the cloned GPT is the first attachment and the root the second. It
writes no catalog or qualification state and is not product acceptance.
Invalid bootstraps there must print the init fail-closed line, never run the
probe, and leave both disks byte-identical. The VZ refusal/conversion test is
`macos_only` and requires `--backend vz`; on Linux it is `pending-lane:macos`,
never passed.

### Restored guest activation (Phase 12)

`silo_smoke/guest_restored.py` joins the standalone `native-live-api` owner
(`--silo-fixture` real-Silo boot) with the attach-only guest controller
(`guest-lifecycle-controller --attach`). It never uses the diagnostic native
init, console oracles or echo streams. Make resolves the matching built helpers,
read-only pinned libkrun validators and staged kernel config automatically:

```sh
make smoke SMOKE_ARGS='-m "not slow" -k "freeze or generation or activation" --keep'
make smoke SMOKE_ARGS='-m slow -k activation --keep'
```

`SILO_SMOKE_NATIVE_LIVE_API` optionally overrides the entry path.
`SILO_SMOKE_RESTORED_EVIDENCE` optionally selects a parent directory; otherwise
the per-run durable evidence tree is used. The staged config must contain
`CONFIG_VMGENID=y` and `CONFIG_VIRTIO_SILO_VMGENID=y`. No native-checkout env var
or native-checkout build is needed.

One cold AgentPid1 source (populated private root `disk0`, ext4 data `disk1`,
complete two-block shutdown manifest, real netd behind a transparent
datagram relay) starts a persistent userdata witness, renames its managed NIC
and seeds neighbours, proves source wire/gateway positives, holds captured
exec/SSH/forward sessions, collects same-boot capture profile files and freezes
through the real guest RPC before native pause and one full capture. Children
restore that read-only cut sequentially, each with its own subnet, MAC and
netd. Per child: parked/fenced native state, `generation-fresh`, CPU release,
exact timely native ACK correlated with the driver's `generation_state`, guest
`Activate` (replay, conflict, stale source Thaw), destination `Thaw`, and only
then native command `activate`, which is provider fence release, never guest
activation. After release the child must reach its new gateway, answer paired
destination ARP/ICMP probes but not its old address on the same wire, emit no
source identity, relay its selected listener with the destination token, and
reject the old instance, cursor and listener. The positive test runs two
children and an ordinary source ClockOnly resume/Thaw. Slow tests cover hook
failure/timeout/background descendants, listener conflict, lost Activate reply
replay, lost Thaw with a real next-epoch freeze, and replacement of captured
extra managed-link addresses. Network-presence mismatch still rejects without
effects. Failed children stay frozen and fenced and are stopped/reaped by their
native owner. `restored-report.json`, `attach/`, `wire.jsonl`, native command logs and
`inputs.json` under the cohort evidence directory are the evidence.
Activated status must report the destination IPv4 and no captured source IPv4.
The agent refreshes kernel-observed system facts once at activation completion
(including failure), notifying status watchers without syscalls on each read.

Options override environment variables. Paths should be absolute when supplied
explicitly. Make derives binary/runtime directories from the selected profile
unless their environment overrides are set.

| Environment | pytest option | Default / meaning |
| --- | --- | --- |
| `SILO_SMOKE_BIN_DIR` | `--silo-bin-dir` | `$CARGO_TARGET_DIR/$SMOKE_PROFILE`; must contain silo |
| `SILO_SMOKE_RUNTIME_DIR` | `--silo-runtime-dir` | `$CARGO_TARGET_DIR/silo-runtime/<host-target>/$SMOKE_PROFILE` |
| `SILO_SMOKE_BACKEND` | `--backend krun\|vz` | `krun`; `vz` requires macOS |
| `SILO_SMOKE_CACHE` | `--cache-dir` | `${XDG_CACHE_HOME:-~/.cache}/silo-smoke` |
| `SILO_SMOKE_KEEP` | `--keep` | `1` retains workspaces even on success |
| `SILO_SMOKE_SYSTEM_IMAGE` | none | Appliance OCI reference; defaults to `ghcr.io/vandycknick/silo/system:dev`; set it empty to skip system tests |
| `SILO_SMOKE_DISTRO_IMAGES` | none | `label=oci-ref` list for the SSH distro lane; defaults to `arch=ghcr.io/vandycknick/archlinux:latest,system=<system image>`; set it empty to skip |
| `SILO_SMOKE_SYSTEMD_IMAGE` | none | Optional Phase F systemd image with vsock SSH socket activation |

Failed tests and `--keep` preserve stopped machine files and per-machine logs,
not just the outer workspace directory. Teardown still force-stops every
registered VM and terminates owned daemons; retention never authorizes leaving
processes running. Only successful, non-retained workspaces remove their
registered machines and private root. Cleanup uses that workspace's private
Home and never removes machines from another Home.

Host targets are `linux-amd64-gnu`, `linux-arm64-gnu` and `darwin-arm64`.

Markers: `daemon` starts a private daemon; `system` needs the appliance image;
`linux_only` and `macos_only` select host-specific
checks. The default selection excludes `slow`; `make smoke SMOKE_ARGS='-m slow'`
overrides it to run extended checks. An explicit marker expression replaces the
default, so use `-m 'not daemon and not slow'` to retain the fast selection while
excluding daemon tests. `live` tests require explicit selection with `-m live`.

The system and distro lanes pull their published default images from
ghcr.io; `SILO_SMOKE_SYSTEM_IMAGE= SILO_SMOKE_DISTRO_IMAGES= make smoke` disables
those published-image lanes, but other first-run acquisitions still need network.
Pulled images are kept under `<cache>/image-catalog/<schema-hash>`:
each embedded initial schema gets a separate fixture cache. It contains immutable
`images/{objects,streams,source-blobs,transport}` bytes and a sanitized image-only
SQLite catalog. Fixtures use SQLite backup, never copy active database/WAL files,
and seed only unopened private Homes. Machine/private roots, operations, network
state, locks and temporary files are never copied. Stream paths are remapped to
the destination Home; no mutable JSON cache exists. Source-blob reuse verifies
size and SHA-256 on blocking workers with bounded scratch buffers. Old-format
state/cache is not imported; this hard-breaking release requires reinstalling and
wiping prior Silo state. The systemd-owned SSH lane and the curl image have no
published default; nothing in this repository builds them yet. On macOS, daemon-managed VMs use krun even when direct CLI tests
select vz.

### Default-suite cost strategy

The Phase 7 baseline in `.tmp/phase07-default-qualified.xml` ran the complete
73-case baseline selection in 966.09 seconds. The inode ENOSPC
case alone took 82.141 seconds. Its guest workload now creates empty files until
the actual create returns ENOSPC, then performs one checked `syncfs` before
reporting that errno. Committing the journal after every empty inode was setup
cost, not the resource-exhaustion oracle. The real ext4 upper, zero free inodes,
remaining free blocks, immutable-lower hash, ample host space and post-deletion
capacity recovery assertions are unchanged. Block, host-error and copy-up
workloads retain their per-file checked writes and fsyncs.

Overlay and stopped tests share one session-built probe and immutable OCI image
body, published under their existing separate registry references. Every case
still creates its own Home, catalog, writable root and real guest. No mutable
machine state or previously booted fixture is shared. Overlay diagnostics batch
all existing procfs/sysfs reads and `df` commands into one fail-fast guest exec.
Capacity checks obtain the same two independent guest statvfs projections with
one `stat` invocation, still comparing each fresh post-effect metrics frame
against both real filesystems. Stopped byte/inode oracles, full logical hashing,
copy/replay order, fresh boots and exact-boot closure checks are unchanged.

The Phase 14 default baseline,
`.tmp/plan/evidence/phase-14/default-journal-complete.xml`, contains 106 testcase
rows totaling 983.640 seconds (suite wall time 983.983 seconds). The suite header
reports 115 tests, so use the actual testcase rows for per-case comparisons.
Overlay cases contribute 423.935 seconds and stopped-storage cases 292.336
seconds, together 72.8% of the recorded case time. These totals identify the
dominant controllers, not a measurement of any individual setup operation.

Those two modules now seed each unopened private Home from a session-local
image-only cache prepared from that session's exact OCI bytes. Preparation
creates stopped, never booted machines through the staged CLI, then uses the
existing sanitized SQLite backup and reflink-aware immutable pool copier.
Overlay and stopped references have separate catalogs, so no extra image
reference can pin the OCI closure during stopped-storage collection checks.
Each case still creates its
own machines, writable disks, runtime namespace, catalog and locks; no
previously booted root or machine/operation/network row is carried over. The
cache is not reused across pytest sessions. Invalid OCI variants still take
their original acquisition/materialization paths, and acquisition/cache tests
retain fresh, unseeded Homes. The common `vm` fixture's Home is the only other
seeded Home; see the Phase 16 notes below.

The two exact-boot snapshot cases contribute 88.861 seconds and the retained
stage-replacement case 16.181 seconds to that baseline. Their private runtime
trees now use reflinks when the destination filesystem supports them, falling
back to ordinary copying otherwise. Copies still dereference staged symlinks,
preserve file modes/timestamps/xattrs and allocate private inodes, never
hardlinks. Replacing, modifying or unlinking either private tree cannot modify
the original stage or its sibling. All boot-byte hashes, held-FD/unlink oracles,
fresh boots, shutdown ownership and existing readiness/deadline checks remain.
No Phase 15 speed result is claimed until the complete default selection is
rerun with the same qualified inputs.

Phase 12 measured 199 `info` invocations taking 101.91 seconds in the six
stopped fork/replay and exact-boot snapshot cases. Identity-only path and SQL
lookups now use the existing independent read-only catalog process, without
caching machine identities or reconciling live state. Explicit CLI state,
readiness and clean-stop assertions remain. The same six cases passed before
and after, taking 291.08 and 233.94 seconds respectively; `info` calls fell to
80. These are targeted-run timings, not a full-suite speed claim. Raw commands
and timings are retained in `.tmp/plan/evidence/phase-12/stopped-speedup.json`
and its adjacent `stopped-{before,after}-command-times.jsonl` files.

The Phase 15 default run, `.tmp/plan/evidence/phase-15/default-speed-final.xml`,
took 955.552 seconds of suite wall time: 120 testcase rows, 119 passed and the one
opt-in internet case skipped (the header's `tests` count is not the row count).
That exceeds the 900-second rule, so Phase 16 removes more redundant smoke work
without removing any boot, stop, replay, hash or guest check:

- Identity-only lookups use a fresh read of the independent read-only catalog
  process instead of CLI `info`: the source in each `stopped.fork` distinctness
  check, the two-child test's final three-machine uniqueness check, the expected
  machine in `overlay.metrics`, and the log path and terminal machine ID in
  `overlay.shutdown_watch`/`orderly_guest_shutdown`. Both sides of every
  comparison are normalized with `UUID`. The child's own `info` state, run and
  readiness assertions stay. In the six stopped fork/exact-boot cases this
  removes 22 `info` calls. The common `vm` fixture takes its ID from its own
  `wait_ready` response, one fewer `info` for each of its 11 default cases.
- `overlay.evidence` returns `Evidence(observation, metrics)`. Overlay
  persistence uses that already validated frame as its pre-restart agent
  identity instead of collecting a second one. Evidence now samples metrics
  before its read-only diagnostics. Each `metrics` call still sets its own
  new freshness cutoff and compares against independent guest statvfs, and the
  post-restart frame is still collected fresh.
- The common `vm` fixture seeds its fresh Home from a session-local BASIC-only
  catalog. That catalog is prepared like the overlay/stopped catalogs, in its
  own preparation Home and never merged with them. The fixture asserts the seed
  carried exactly the BASIC reference, then runs its unchanged create, start and
  readiness. The general `workspace`/`silo` fixtures, lifecycle, image-cache and
  malformed-image tests stay unseeded.
- In each two-child fork case, the first child's machine-ID read and the
  source's final `/second-only` absence check join the existing guest-copy
  batch, with a second textual boundary and exact-byte checks. That is two fewer
  guest sessions per case, eight in the default selection.

Overlay `info` removals are counted from command evidence, not listed here.
None of these removals has a measured elapsed-time effect until Main runs a
controlled before/after pair of complete suites.

Command timing is recorded so the before/after pair can be compared. Every
`Silo.run` appends one monotonic duration line to the workspace's
`evidence/timing.log`: an `operation` (`silo <label>`), an `outcome`
(`exit-<code>`, `timeout` or `spawn-error`) and `seconds`. Readiness polls use
the `wait-ready` label, so the remaining `info` count does not depend on boot
time. `wait_ready`, `overlay.metrics`, each `root_metrics` attempt,
`stopped.backing`, `image_cache.seed`, catalog preparation and the exact-boot
private-runtime copy are timed at their harness callsites, with an exception
recorded under its type name. Successful cleanup deletes that log, so teardown
publishes a summary of count, total and maximum seconds per operation/outcome,
plus the cleanup time itself. The summary's size does not grow with the
number of calls. It goes into the JUnit `silo-smoke-timings` testcase property
for the `workspace` and `stopped_silo` fixtures, and into the
`silo-smoke-timings-prepare-<catalog>` suite properties for session
preparations. Use `--junitxml` to keep them.

The Phase 9 complete default baseline is
`.tmp/phase09-corrected-default.xml`, with its command and call-only durations in
`.tmp/plan/evidence/phase-09/full-smoke-bg618.log`: 87 passed in 988.84 seconds.
The four two-child fork calls took 49.51 seconds (clean-flat), 48.64
(dirty-replay-flat), 45.75 (clean-raw) and 44.01 (dirty-replay-raw); the two
exact-boot snapshot calls took 45.57 and 45.20 seconds. JUnit testcase times also
include setup/teardown, so compare them separately from pytest's call durations.

Stopped tests now batch each guest-copy proof's same `cat`, absence `test` and
two `stat` invocations into one fail-fast guest exec. A textual boundary keeps
the complete `cat` result available for the same host-side exact-byte assertion;
the original hardlink inode/link-count comparison remains host-side too. Source
setup invokes the same durable-write probe before the same hardlink/machine-ID
writes and `sync`, but within their existing shell session. Snapshot children
read their common file and kernel command line in one exec, still checking exact
common bytes and the captured argument separately before the Data mutation.
This removes ten CLI/agent round trips per fork case and three per snapshot
case, 46 in the default selection, without caching any guest or disk result.
All logical disk hashes, child/source inode checks, cold boots, run identities,
dirty replay, lifecycle cleanup and existing deadlines remain in place.

The probe source is `virt/vmm/tests/guest/overlay_probe.rs`. Pytest's session
fixture compiles it with rustc for Linux musl and embeds that new executable in
the OCI layer; use a new pytest session after changing it, not a retained image.
This does not rebuild the production initramfs. `make smoke` stages production
binaries automatically. For the after measurement, retain
the same kernel/config qualification, fault monitors, system-image fixture,
host filesystem, resource conditions and environment as the Phase 9 baseline,
and run the complete unchanged selection:

```sh
make smoke SMOKE_ARGS='-m "not slow and not live" --junitxml=../.tmp/phase10-default-qualified.xml --durations=20'
```

Compare the full wall time and the six affected call durations against the
retained Phase 9 baseline, and compare the same testcase identities/counts and
outcomes in both JUnit reports. Native/runtime changes in the same integration
are a timing confounder; attribution requires a paired run with the same staged
native bytes and only the smoke batching changed. These changes remove known
redundant sessions, not assertions or default cases. No elapsed-time improvement
is established until the complete selection runs.

Phase 11 additionally batches fourteen Data-device transport lookups and the
two persistence setup/readback clusters without crossing lifecycle boundaries.
The reserved-encoding positive controls reuse the session's immutable OCI body;
each control machine and malformed image remains private to its test. This
removes 19 guest sessions and three redundant image constructions.

The complete 87-case selection passed before and after with identical staged
monitor, kernel, initramfs, agent and netd bytes: 943.32 seconds before and
931.16 seconds after (12.16 seconds lower, still above 15 minutes). The after
run used an isolated Phase-10 source checkout plus the smoke changes, preserving
fault-fixture source-hash checks while native implementation continued elsewhere.
One earlier comparison was invalidated by those checks and is retained as a
failure, not timing evidence. Reports and input hashes are under
`.tmp/plan/evidence/phase-11/`; this single pair does not establish a general
performance guarantee.


## Isolation and evidence

Every test creates a short workspace under `/tmp/silo-smoke-*` on Linux or
`/private/tmp/silo-smoke-*` on macOS. It gets private `HOME`, `SILO_HOME`,
`XDG_CONFIG_HOME` and `SILO_RUN_ROOT`. Subprocesses receive an explicit environment,
not the developer's daemon configuration. Socket paths stay within the Unix
socket path-length budget. A session guard records the live daemon's default
control socket inode and modification time and asserts they remain unchanged.

Concurrent sessions serialize shared registry CA creation and OpenSSL serial
updates with a close-only file lock; a thread-local lock cannot protect
independent pytest processes.

Teardown stops/removes registered VMs and terminates tracked daemons. Failed
runs and runs with `--keep` retain the workspace and print its path; successful
runs otherwise remove it. Command transcripts and daemon output are in
`/tmp/silo-smoke-*/evidence/*.log` (or the macOS equivalent), command and
harness durations in `evidence/timing.log`. Keeping evidence does not keep the
VMs running.

## Images and registry

The first run downloads the architecture-matched Alpine 3.21.3 minirootfs and
verifies its pinned SHA-256. Verified cached archives are reused offline. The
base tar plus an overlay forms one gzip-compressed OCI layer, with a config and
manifest served by a session-local HTTPS registry bound to `127.0.0.1`. BASIC
adds `/etc/proof` and the unprivileged silo user/home. The agent is injected by
the initramfs, not included in the image.

To add an image, define an `ImageSpec` in `silo_smoke/images.py`, build it once
in a session fixture, then publish it through the registry:

```python
from silo_smoke.images import GuestDir, GuestFile, ImageSpec, build, fetch_alpine

spec = ImageSpec(
    name="example",
    files={"etc/example": GuestFile(data=b"example\n", mode=0o644)},
    dirs={"opt/example": GuestDir()},
    remove=frozenset(),
    append={},
)
image = build(spec, fetch_alpine(config.cache_dir))
reference = registry.publish(image, spec.name)
```

Paths are relative to the guest root. Overlay entries replace matching base
members; `append` adds bytes to existing text files and `remove` drops base
members. This fixture-authoring API requires relative paths and rejects traversal
and duplicate normalized paths; this is not the OCI reader's admission policy.
The OCI reader also accepts absolute tar entry and hardlink paths relative to
the layer root.
Keep scenario-specific additions in separate specs rather than changing BASIC.
BASIC also removes Alpine's busybox `/sbin/init` so the agent stays PID 1
(the agent hands off to any executable init it finds).

Specs can pull real Alpine packages: `ImageSpec.packages` lists
`ApkPackage(name, version)` entries fetched from the v3.21 `main` repository and
verified against the per-architecture hashes in `APK_SHA256`, and their payload
is laid down before `files`. `CA_TRUST` is BASIC plus `ca-certificates`, which
gives the guest the `update-ca-certificates` trust backend the agent needs when
a private network policy installs a certificate authority. Adding a package
means pinning its hashes for both architectures. `IPROUTE` adds `iproute2-ss`
(with `libmnl` and `libcap2`) so a guest can list vsock listeners with
`ss --vsock`; pins come from the v3.21 APKINDEX `P`/`V`/`D` fields and the
SHA-256 of the downloaded archives.

Linux trusts the registry through the workspace's `SSL_CERT_FILE`, which points
at `<workspace>/ca-bundle.pem`: the host's CA bundle plus the suite CA, because
that variable replaces (not extends) the trust store for Go and rustls consumers
and `netd` still has to verify public upstreams. On macOS,
the Rust OCI client's platform verifier ignores that variable. Trust the stable
suite CA once in your login keychain after it has been generated (preflight
prints the instruction):

```sh
security add-trusted-cert -r trustRoot \
  -k ~/Library/Keychains/login.keychain-db <cache>/registry-ca/ca.pem
```

Here `<cache>` is the resolved smoke cache directory. Changing that directory
or replacing its CA requires trusting the new certificate. The registry's leaf
certificate is issued per session with localhost/127.0.0.1 subject alternatives.

## EROFS-overlay and VMDK qualification

`tests/test_overlay.py` drives the normal staged CLI/libvm/monitor/worker path.
OCI creation now defaults to EROFS overlay on libkrun, with no profile selector.
Managed overlay requires Linux 6.6 or newer; compatibility is a kernel-config
property verified by the kernel track's gate at build time, not by per-boot
artifact qualification. Custom kernels are not rejected for having new hashes.

`make smoke` automatically builds both host consumers and stages the runtime.
The repository Rust toolchain includes the guest musl targets.
The smoke session builds `virt/vmm/tests/guest/overlay_probe.rs` directly with
`rustc`, using the existing self-contained musl linker convention. It includes
the exact production init effective-options verifier by source path. No Cargo
test launches a VM. `debugfs`, `e2fsck`, `unshare`, `mount`, `umount`, and GNU
`cp` are needed by the corresponding Linux qualification fixtures.

### Initial candidate, then production acceptance

Before there is a positive tuple, run only the controlled candidate:

```sh
make smoke SMOKE_ARGS="-k overlay_candidate_qualification --keep"
```

For a locally built kernel, Make automatically uses its adjacent emitted config:

```sh
make smoke KERNEL_PATH=/absolute/kernel/build/vmlinux SMOKE_ARGS="-k overlay_candidate_qualification --keep"
```

This uses the `overlay_candidate_lower` libvm example to acquire an authenticated
EROFS composition with exact fsmeta and ordered pack occurrences, the real
`format_upper` implementation for its upper, and the shipped monitor in
foreground mode, which starts its real krun worker. It does not call libkrun
directly and does not insert a database/home/environment qualification grant.
Kernel, base initramfs, composite and monitor/worker are private snapshots;
evidence hashes the exact bytes consumed, so restaging cannot silently change
the recorded tuple.

Retained `overlay-candidate-tuple.log`, candidate serial/trace/output logs and
formatter output contain exact artifact digests, host lane, actual guest kernel
version, UUIDs, measured serials/geometry/RO, mountinfo, current module defaults,
and accepted verifier/profile evidence. The staged manifest must bind the
kernel, base-initramfs and **native executable** digests to those private
snapshots. The actual worker `/proc/PID/exe` hash must match the consumed
monitor/worker snapshot. The candidate records the real binary's
`capabilities --backend krun --json` build identity and corrected signed native
revision; these are provenance, not a feature grant. For an authenticated OCI
kernel, its artifact metadata supplies the resolved-config digest. A local
`KERNEL_PATH` uses its adjacent emitted `.config`; `SILO_SMOKE_KERNEL_CONFIG`
overrides that location. Retain independent build provenance associating those
bytes with the exact tested kernel; hashing an arbitrary config is not proof.

Main reviews the observed compatibility evidence and the kernel track's build-time
configuration gate, then exercises the real production path without rebuilding an artifact allowlist:

```sh
make smoke SMOKE_ARGS="-k 'vmdk or overlay' --keep"
make smoke SMOKE_ARGS="-m slow -k 'vmdk or overlay' --keep"
```

The candidate is not the production-path positive gate. Full normal acceptance
includes >2 GiB production mapping against an independent whole-file linear
oracle and a sector-record oracle, an explicit reader-offsets-as-bytes negative
control, actual worker FD access modes, spaces/relocation, metadata/hardlinks/
index/EXDEV/whiteouts, `/tmp` policies and restoration of hidden disk contents,
fresh public metrics compared with independent guest statvfs, real block/inode/
copy-up ENOSPC, isolated host ENOSPC, recovery and replacement growth, >65k
directories, discard/zero lengths, and raw regression. The historical 4.5 GiB
`a`, empty occurrence and repeated 1 MiB `b` fixture retains seed 14 and its
independent concatenation negative control; it does not replace production
mapping evidence.

The Linux FD gate observes `IN_OPEN` events on the actual immutable lower,
including an open/close positive control, before launching a fresh CLI with
soft=hard=256. It requires the typed preflight error naming both limits and no
backing open. A separate soft=256/hard=512 launch must raise and boot, and the
actual worker's inherited `/proc/PID/limits` must show 512/512.
The bounded attachment edge also boots two roots plus fourteen real raw Data
disks with the raised limit and checks all sixteen guest identities, actual
lower RO handles, upper RW handle and fourteen actual Data RW handles. The
`records + 256` check is numeric admission, not a reservation of free FDs;
concrete native resource/open failures remain failures with their diagnostics.

### Controlled guest validation

Serial identity/order/access and effective-overlay-option validation are covered
by the production init's `root_checks` and `overlay_verify` unit tests. Routine
smoke does not rebuild mutated native monitors or a mutated init to repeat
these checks. The real scratch no-export-handle gate still measures
`name_to_handle_at` EOPNOTSUPP, successful OverlayFS mounting, effective
index=off, and the production verifier's downgrade rejection, alongside a
production positive control. Failed mounting or an unrelated parser error
does not pass.

The owned-stage replacement test uses private, byte-identical runtime copies
with distinct monitor inodes. It removes the retained source inode at the
actual launch boundary, requires the pre-exec identity recheck to refuse, then
boots the successor inode normally. No fault-monitor build is required.

The slow controlled historical native fixture uses the same real monitor/worker
and guest verifier with `[a, empty, b, b]`: a valid flattener-produced ext4 prefix
inside sparse 4.5 GiB `a`, repeated 1 MiB `b`, and five FLAT records. The guest
gets only bounded read positions/lengths. Whole-occurrence and record oracles,
the deliberate byte-offset negative, and actual three-a/two-b RO worker handles
are checked independently. This controlled repeated-extent proof does not
claim libvm's current semantic single-stream profile accepts repeated closures;
the separate >2 GiB positive gate still uses the full normal production path.
Journal authority has two actual-disk reader controls: a valid active inode 8
with deliberately wrong `s_jnl_blocks` must boot; an invalid active inode/map
with its initially matching valid backup preserved must reject before replay,
leaving the entire failed upper unchanged. These are real production-init
reads over a real virtio disk, not only pure inode parser cases.


### Exhaustion, recovery and slow cases

The host ENOSPC fixture creates a bounded tmpfs inside a private unprivileged
user/mount namespace and bind-mounts only a disposable upper file. DB, logs,
immutable lower and evidence remain outside. It first proves actual host errno
28 and ample guest space, then requires actual guest write/fsync EIO or ENOSPC,
run-bound worker diagnostics retaining host ENOSPC, and sticky checked guest
shutdown failure. The original upper is revealed unchanged when the namespace
ends. A namespace mount feasibility probe is not VM qualification; missing KVM
access or namespace support is a failed prerequisite, never skip-as-pass.
While stopped, the same exhausted disposable directory also exercises real
replacement-growth ENOSPC: the old bytes/path/capacity record must remain
unchanged and failed staging must leave no published private generation.

Dirty recovery retains immutable source bytes and two private copies before
either replay. Growth checks old-prefix identity before boot, stable UUID,
preserved committed contents, independent copies, exact backing/span/tail,
GDT consumption across 16 GiB, and sparse growth to 1 TiB. No host repair or
public flat snapshot/export is used. Directory scale, full range-operation
matrix, host exhaustion, >2 GiB mapping and clean/dirty growth are marked slow.
Range-operation cases include 512-byte sector-aligned middle and tail requests
that are deliberately not host-4KiB aligned, in addition to aligned middle,
tail and whole-device cases. Both discard and zero must actually read zero,
preserve every outside byte and preserve capacity after close/reopen. No-op
discard and host-block edge rounding are failures, not acceptable outcomes.
`BLKZEROOUT` supplies a real guest zero-range request; these behavior receipts
do not by themselves claim which native opcode a kernel fallback selected.
`fstrim` compares upper length to a baseline captured before trimming.
Orderly persistence/recovery gates use normal CLI/libvm stop and the run-bound
guest handshake, exercising real writer drains, storage shutdown and poweroff.
They require a current-run native terminal artifact with actual status0, no
signal/force reason, terminal owners and the three established storage facts
on the qualified Linux Raw profile. Persistence/clean-recovery gates retain
raw serial evidence and still require RECOVER clear, restart identity,
persistent bytes and unchanged lower content. Explicit dirty SIGKILL
recovery cases remain separate.
Unexecuted HVF, KVM arm64 and VZ lanes remain pending.

On Linux, `Workspace` honors a process-local `TMPDIR`; choose a short durable
parent for large growth/copy gates, rather than the host's 32 GiB `/tmp` tmpfs.
For example, after creating `$HOME/sm` as a private directory:

```sh
TMPDIR="$HOME/sm" make smoke SMOKE_ARGS="-m slow -k 'vmdk or overlay' --keep"
```

Large growth cases explicitly reject a tmpfs workspace. Unix socket paths
must still fit the harness's existing 100-byte budget, so keep the parent
short. Replacement evidence records both logical length and actual
`st_blocks * 512` allocation; comparisons to the original 64 MiB source remain
bounded to that original prefix even for a 1 TiB target. Fault-build copies
also belong on durable storage, not `/tmp`. The dedicated host-ENOSPC tmpfs
remains separately bounded and does not exhaust the workspace filesystem.

### Native range operations and unsupported-hole-punch fallback

Run `test_overlay_native_range_and_real_fallback` against the staged production
runtime:

```sh
TMPDIR="$HOME/sm" make smoke SMOKE_ARGS="-m slow -k overlay_native_range_and_real_fallback --keep"
```

The 30-case Linux matrix covers discard, BLKZEROOUT and block-device
`fallocate(PUNCH_HOLE|KEEP_SIZE)` over aligned middle/tail/whole ranges and
sector-aligned 512-byte middle/tail ranges. Each case creates a private
user/mount namespace and either bounded 8 MiB tmpfs or ramfs containing one
controlled 4 MiB Raw Data file. Database, root storage, copies and evidence stay
outside that mount; ramfs itself is not size-bounded.

Actual owned-FD controls measure PUNCH_HOLE/KEEP_SIZE and ZERO_RANGE/KEEP_SIZE
and require real EOPNOTSUPP on ramfs, with original bytes intact on refusal.
The unchanged shipped CLI/libvm/monitor/worker must hold that Data inode
writable, zero exactly the requested bytes, preserve every outside byte and
logical length, and retain capacity and guest-visible zeros after stop/reopen.
Failures are not skipped or relabelled as successful fallback.

This is a product-behavior gate, not native opcode/flags attestation: a guest
ioctl name or zeroed bytes cannot identify the selected virtqueue opcode.
Source-patched native observers and their separate builds are not part of
routine smoke. `native-range/` retains host errno/FD controls, worker identities,
case evidence and a child-workspace pointer.

Foreign-effective-UID host metadata remains the documented F3 P2 fixture gap;
mode/hardlink/ACL tests must not be reported as having exercised that branch.

### Whole private-stage replacement with owned boot files

`test_overlay_owned_stage_replacement_rechecks_monitor` uses private complete
runtime clones, never Main's stage. A child-only Linux x86_64 syscall tracer holds
the first write to the private `.launch-<uuid>.tmp` file, before kernel or
composite publication. Pinned launches publish the kernel before the descriptor;
the gate requires an empty temporary and absent final kernel/initramfs files.
It checks that pinned kernel/base pool objects and
the monitor are held as read-only CLOEXEC descriptors with independent inode and
content evidence, then atomically swaps the stage and unlinks the retired tree.

The pre-exec metadata recheck must refuse the changed monitor before spawning it,
without hashing or reopening the replaced executable path. Pinned guest assets
remain owned independently of the stage. A fresh start must then boot with the
successor monitor; changing a Silo-managed monitor does not require an artifact
admission record. The controller retains EXITKILL and bounded descendant cleanup.

```sh
make smoke SMOKE_ARGS="-k overlay_owned_stage_replacement_rechecks_monitor --keep"
```

Retained `overlay-stage-*` and `boundary-*` evidence includes the held syscall,
source and destination descriptor identities, retained asset hashes, CLI refusal
and actual successor monitor/worker identities after the fresh successful boot.

Machine/run identity assertions compare parsed UUID values, not compact versus
hyphenated serialization spellings. Malformed or different identities still
fail. Storage-key/path spellings remain unchanged; the private-stage gate
shares the same metrics identity check through `overlay.evidence`.

Filesystem identity checks use numeric kernel statfs magic (`stat -f %t`),
including OVERLAYFS_SUPER_MAGIC `0x794c7630` and TMPFS_MAGIC `0x01021994`.
BusyBox/GNU human-readable filesystem names are not an acceptance ABI.

The metadata guest oracle first requires the lower's exact fixture bytes:
2750 literal `x` user-xattr bytes, the named UID1234 read-only access ACL with
mask/read-only group/other entries, and the v2 effective CAP_NET_BIND_SERVICE
capability blob. It then independently requires those bytes to survive the
specified copy-up operations. Missing xattrs report actual path/name/errno;
presence or preservation alone cannot hide a wrongly rendered lower.

`test_overlay_native_symlink_4095_and_flat_4096_refusal` checks the 4KiB ext4
symlink boundary through real production creation and the guest kernel:
4095 target bytes must survive exact native `readlink`, while an otherwise
identical fixture with a 4096-byte target must fail flat materialization
without publishing a machine. Raw failure output is retained; no incidental
error wording or Cargo-launched VM supplies this oracle.

The maintenance-path and real host-ENOSPC shutdown faults now use the same
normal CLI handshake. They require the host's exact-run COMPLETED/FAILED
receipt (numeric result2 with its diagnostic), a current native terminal
record with unforced status0, false guest/host-flush facts and a nonclean
reconciled outcome. Old guest terminal-log wording and a cancelled invoking
exec are not the failure oracle. Actual backend errno and storage/byte
oracles remain mandatory; guest ENOSPC is not the retained host-fsync-EIO gate.

F10 command scripts use ordinary `exec sh -c`, not an interactive shell left
waiting at its prompt after input EOF. Silent successful guest operations
such as `syncfs` use the ordinary exec result; JSON decoding is reserved for
probe commands whose output contract is JSON.

Reserved metadata rejection is causal coverage across layers: core
`acl_mode_capability_and_reserved_metadata_are_validated`,
`socket_pax_and_device_profiles_have_no_payload_and_no_host_extraction` and
`production_flat_materialization_rejects_malformed_layers_and_forward_links_atomically`
cover typed metadata/device rejection and failed-staging cleanup. The native
CLI gate first admits the otherwise equivalent valid image, then requires
mutated reserved-xattr/char0 images to fail without machine or rootfs-artifact
publication. Raw CLI errors are evidence, not pinned display text. Guest
candidate rejection similarly keeps explicit workload/rescue prohibition and
the active-journal no-write oracle, not incidental diagnostic substrings.

Exact-tail growth uses the existing public Rust `storage_acceptance` consumer,
built automatically by `make smoke`. Its
`set-root-capacity MACHINE BYTES` action calls `Machine::update` with the exact
byte count against the same private Home/runtime and checks the returned
published capacity. No parser expansion or production shim is involved.
Whole-MiB growth retains the accepted CLI `disk=NMiB` grammar.
The fixture records runtime output. Dirty recovery captures the exact run's
SIGKILL terminal artifact and waits for both owned monitor/worker PIDs to be
gone; a terminal Error label is not confused with a live process or rewritten
to Stopped. Directory-scale inspection follows actual guest PID1 shutdown and
RECOVER clear, and checks numeric EXT4_INDEX_FL/link-count fields without host
journal replay or whole-line wording assertions.

The host-ENOSPC replacement lane retains its actual errno28 receipt and full
bounded filesystem, then checks real public-update refusal, unchanged semantic
record/old file bytes and absence of a partial generation. Hidden CLI error
chains are recorded, not matched as an errno oracle.

The sixteen-total-disk gate keeps two roots plus fourteen Data disks. Exact
serial IDs select each Data block device; fourteen guest threads synchronize
eight rounds of distinct 64KiB writes and flushes, invalidate each dedicated
Data cache, and perform real readback. It records actual sysfs virtio identities
and `/proc/interrupts` routing/counter changes to prove shared routed-line
delivery beyond dedicated transports, not enumeration alone. After stop, a
separate host oracle checks every byte of every 8MiB backing (including all
untouched outside bytes) and unchanged length. Cold reopen repeats concurrent
reads/capacity checks and host-byte verification; immutable lower hash and
actual lower-RO/upper-RW/Data-RW evidence remain mandatory. This is not Phase5
host-flush certification.

The byte-exact Rust consumer also covers shrink, overlimit and non-sector-aligned
capacity refusals after a successful same-size stopped-update calibration.
Those values cannot be represented by the CLI's integer MiB/GiB grammar, so
parser rejection is never counted as storage-admission proof. The existing
hot-update CLI gate retains an accepted `128mib` request.

The bounded host-ENOSPC refusal record includes exact before/after scratch
directory inventories (name, device/inode, type/mode, size, links, ownership and
symlink target) before any refusal/integrity assertion. This preserves cleanup
diagnostics after the private mount namespace is gone without relaxing the
unchanged-directory oracle.

Before replacement exhaustion, the fixture holds the actual original
`node-state.lock` FD and creates only an empty bounded-filesystem mount target.
After the ordinary whole-directory bind, it explicitly file-binds that retained
original onto the visible lock path using `/proc/self/fd/N`, inherited only by
the mount child with source canonicalization disabled. It verifies and records
visible dev/inode equality with the pre-bind original. A directory bind is not
assumed to clone nested mounts. Cleanup removes the owned nested lock mount,
parent bind, original upper bind and scratch mount in order, then closes the FD.
The required production lock is never copied, unlinked or filtered from the
unchanged-directory oracle; DB/log/lower/evidence stay outside the bounded FS.

## Run-bound shutdown, retained inodes and generation leases

The existing fast lifecycle smoke now also observes Linux's actual
monitor/worker identities, their root/lease FD inode identities, terminal
process state, independent lease release, ext4 RECOVER clear, the exact-run
three-fact exit record and the atomically reconciled storage outcome. It
reuses its existing boots rather than adding VMs to the default selection.
This keeps the default lane bounded; Main records actual elapsed time and
must keep the complete default selection below 15 minutes.

The extended controllers are all explicitly `slow`, use normal staged
CLI → libvm → monitor → worker launches:

```sh
make smoke SMOKE_ARGS='-m "not slow" -k lifecycle'
make smoke SMOKE_ARGS='-m slow -k shutdown'
```

`storage_acceptance` is a standalone consumer of the public Rust image
remove/prune API. It boots no VM itself and is not a Cargo test. Smoke uses the
matching-profile `examples/storage_acceptance`, built automatically even with a
custom Cargo target directory. Helpers and CLI are rebuilt together after schema
changes because they embed the same checksum.
An old helper must refuse a new-format Home, not bypass schema admission.

`test_shutdown_cli_clean_independent_facts` keeps two real guest writers
active at stop and checks persisted acknowledged content after restart.
The outcome matrix covers healthy managed EROFS overlay, forced termination,
actual worker SIGKILL, an actual guest kernel panic (retained serial evidence),
image-owned PID1, unmounted externally writable Data and writable host shares.
Unsupported shapes remain supported VM launches but cannot certify clean.
Their external files/directories must survive ordinary machine removal.

The worker-crash regression distinguishes read-only observation from durable
reconciliation: `info` must report the observed forced result without changing
the persisted storage outcome or launch-operation roots. An explicit public
CLI stop then commits that terminal result and retires the operation.
Manager-forced exit records may omit `storageShutdown`: they are durable
forced run fences, not invented monitor-finalizer certificates. The forced
gate checks actual terminal owners, independent lease release and persisted
forced classification without inferring attachment closure from missing facts.

The netd-lifetime monitor-crash gate captures the registered monitor/worker
identities and lease before SIGKILL. Within one 20-second bound it requires
every holder to become terminal, monitor/netd reaping and an independent
exclusive lease probe to succeed before requiring `info` to report stopped.
Monitor/netd disappearance alone never proves writable attachment closure.

The guest-panic case deliberately uses the controlled **image-owned PID1**
fixture, not the agent-owned PID1 healthy-shutdown profile. Its `/sbin/init`
installs a USR1 trap that exits77. Before signalling it, the controller
requires the observed agent boot report to identify a child agent, actual
`/proc/1` PID/TGID and init command, and the kernel's `SigCgt` bit proving the
USR1 handler is installed. Absent prerequisites fail the gate with retained
diagnostics. Ordinary root guest exec sends USR1 to PID1; stdout/stderr and
the result are preserved. Only new current-run serial output with the actual
kernel panic prefix and `Attempted to kill init! exitcode=0x00004d00`
satisfies the panic oracle. This tests a genuine Linux init-death panic on
the unchanged production kernel, not an agent-owned-PID1 crash or surrogate
worker termination. No SysRq/debug kernel feature is required or enabled.

The orphan gate enables a scoped child subreaper, captures pidfds and stable
start identities, sends SIGSTOP to the **entire actual native worker**, and
kills **only its monitor**. Before any worker kill or group cleanup it requires
the stopped worker to remain live, its exact lease OFD to block an independent
EX|NB probe, real image prune to preserve closure bytes/operation roots, and
start/removal/replacement to refuse destructive reuse. SIGCONT then runs the
unchanged watchdog; `waitpid` must observe exit 125 and actual reap before a
new lease probe succeeds. Removing the machine's remaining semantic root and
pruning must finally collect otherwise-unreachable lower bytes. Survival
while the machine root remains is not, by itself, claimed as operation-only
GC proof; focused storage tests cover that independent case.

The retained-inode race gate replaces original pathnames after native
attachment construction for opaque root, overlay upper and external Raw
Data. It checks actual monitor/worker FD inode identities, writes through
the guest, requires the replacement inode's digest to remain unchanged,
then restores and reads the pinned generation. No original-path reopen is
used as the final sync oracle.

`test_shutdown_real_retained_host_fsync` starts the CLI under a child-only
Linux x86_64 ptrace controller. It follows only that launch's forks and
monitor threads, detaches the actual native worker at exec, and observes
post-worker-reap fsync on every writable Raw backing, including external
Data in an explicitly unsupported shape, plus checked close on **every
retained monitor attachment**, including read-only VMDK lower and Raw disks.
The test binds the actual ready monitor's unique FD/device/inode for each
current disk after launch generates the lower descriptor, publishes a bounded
run-bound target snapshot and waits for tracer admission before requesting
stop. Close-only targets have no fabricated sync result. Earlier transient
opens/closes and later reuse of an already-closed FD cannot satisfy the gate.
The healthy case leaves syscalls unmodified. The negative case replaces
only the exact retained target FD's sync return with `-EIO`; evidence labels
this **injected syscall EIO, not physical media failure**. Guest ENOSPC,
failed output publication and fabricated evidence JSON cannot satisfy it.
The guest fact remains independently successful for managed-root cases;
host-flush becomes false on injected failure, closure stays independently
observable and the final storage outcome cannot be clean. For external
Data the real sync/close observations remain required even though its guest
fact is already noncertifying.

The trace request and `retained-fsync-receipt.json` retain actual device,
inode, monitor/thread/worker identities, native terminal state, syscall
number/FD, sync return and close return. The tracer has a 240-second total
deadline and pidfd-only owned-process cleanup; it does not change ptrace
policy or production binaries. Missing ptrace/kernel permissions are a
failed/pending qualification gate, not a skip relabelled as a pass.
Darwin/HVF/VZ qualification is not inferred from Linux observations.

`ptrace-lifecycle.jsonl` separately records early exit events, actual terminal
wait statuses and exec former-TID/sibling retirement. A kernel `ESRCH` after
an already observed ptrace stop is a lost-stop transition, not terminal
proof: the thread remains tracked until its actual terminal wait or the
kernel's exec-collapse event accounts for it. Early exit events are resumed
to allow real termination. Any missing retained-fsync/close return remains a
hard gate failure, even when a thread later dies; lifecycle evidence never
fills in a storage syscall result.

Standalone candidate launches now supply a real shared lease and the strict
current storage context/start request; they have no no-lease foreground path.
The macOS Rosetta helper similarly requires an explicitly owned 0700
`--storage-directory` with the worker-input arguments, retains a close-only
FD8 lease and publishes durable holders through the production publisher
before releasing config. Those standalone fixtures do not substitute for
the production CLI/SQL operation-retention gates above.

## Stopped fork, snapshot and restore gates

`tests/test_stopped.py` is the maintained production CLI controller for Phase 7.
Its presence is not a qualification result. Main must run it against the staged
production runtime after the implementation owners hand off:

```sh
cargo fmt
make clippy
cargo test -p libvm --lib machine::stopped_storage::tests:: -- --nocapture
cargo test -p libvm private_copy -- --nocapture
cargo test -p libvm snapshot -- --nocapture
cargo test -p libvm storage::stream -- --nocapture
make smoke SMOKE_ARGS='tests/test_stopped.py -m "not slow" --keep'
make smoke SMOKE_ARGS='tests/test_stopped.py -m slow -k "not host_ext4" --keep'
```

No Cargo test boots a guest or queries KVM/HVF. The `machine::stopped_storage`
unit tests use actual private raw files and SQLx catalogs with never-started
machines, including nonbootable byte fixtures. They use the existing test-only
real-store constructor, not `Runtime::new`'s native host discovery, and retain a
real monitor component without invoking its native query. `SILO_TEST_MOCK_VMM_BINARY`
may select the prebuilt mock-enabled monitor, as for the other libvm unit tests.
The native controller boots two distinct raw/flat children,
checks source and sibling hashes before each intentional boot, observes actual
dirty ext4 recovery independently, and checks preserved filesystem UUIDs,
guest machine-id/hardlinks, fresh host IDs/runs and actual socket namespaces.
Network intent is explicitly `none`; this does not qualify a network/MAC lane.

`tests/test_native_capabilities.py` owns real machine-less native queries,
including invalid launch descriptors, immutable build binding and mutable-grant
refusal. It creates no VM, but the linked query may open/query the system KVM fd
or resolve optional HVF symbols, so it belongs to smoke rather than Cargo tests:

```sh
make smoke SMOKE_ARGS='tests/test_native_capabilities.py -m "not slow"'
```


The raw snapshot fixture installs current-schema managed Data and complete
nondefault configuration before its first launch, under the actual source
lifecycle lock. This is test construction, not an ownership-import API:
ordinary `--disk PATH` still declares an external resource. The fixture compares
root/Data bytes, geometry/order, null versus empty process settings, Unicode
environment/labels, userdata, hardware and kernel arguments. Each child's full
boot binding must equal the source binding, including its ABI, and independent
hashes verify exact pinned kernel/base-initramfs/agent objects. Both default-selected
and source-private custom boot paths are covered. Only a private copy of the
staged runtime is replaced, never the shared staged installation. Children
must restore/boot after source deletion, unrelated OCI root removal/GC, old
runtime boot-byte replacement and snapshot name and record removal.

Commands are explicit about intent:

```sh
silo fork VM --name CHILD
silo snapshot create VM --name SNAPSHOT
silo snapshot inspect SNAPSHOT
silo snapshot list
silo restore SNAPSHOT --name CHILD
silo snapshot rm SNAPSHOT                # name; record goes with its last name
silo snapshot rm sha256:HEX             # record and all its names
```

Ordinary fork and snapshot capture require a stopped source and admit opaque raw
and EROFS-overlay roots subject to their boot/backend admission. Layered
snapshot/restore artifacts retain the exact fsmeta, ordered pack and metadata
graph, not a flattened lower or a requirement to regenerate from OCI. Obsolete
flat profiles are rejected before effects. Live execution operations require
their native backend/host primitives, not implicit stop/cold-boot fallbacks. An
exact snapshot preserves configured secrets, guest credentials, dirty journals
and deleted-data remnants. It is neither sanitization nor application-consistency
certification.
External disks/shares require explicit `--external-requirements` at snapshot
capture; snapshot records never store destination host mappings. Fork/restore
may instead supply complete `--map-disk ORDER=PATH` / `--map-share TAG=PATH`
destination mappings. An unresolved requirement blocks start; an intentionally
shared mapping is not independent private storage.

`stopped.py` uses a separate bounded SHA-256/raw reader and records device,
inode, mode, logical length and allocation independently from the production
StreamHasher. Logical SQL/schema snapshots use independent read-only sqlite3
processes; WAL/SHM physical bytes are deliberately not compared. Catalog reads
allow SQLite to wait up to five seconds for a concurrent writer, within the
existing 15-second subprocess limit; persistent contention still fails.
Rejection gates
compare the complete logical catalog and owned persistent/runtime inventories.
`stopped-refusal-delta.log` retains changed table rows and file entries before
assertion/teardown, including both values. Lifecycle status and error fields
remain part of the logical catalog oracle, not exempt telemetry.
Positive mock-capability refusal is covered by the maintained hypervisor-free
`live_capabilities` and CLI `early_rejection` tests, not relabelled native proof.

The slow gates reuse Phase 5's real pidfd/holder/OFD evidence: SIGSTOP the entire
actual worker, kill only its monitor, and require fork/snapshot/start/resize/
remove to remain fenced while real GC preserves its closure. Resize and removal
run first and must leave the exact running source row unchanged, including its
run ID, monitor PID and null error, while the orphan worker is still stopped and
its OFD lease remains busy. Stopped mutations perform holder/old-operation
preflight before node-state lock allocation or reconciliation writes; they do
not persist a synthetic stopping/error observation as a refusal side effect.
Resuming the unchanged watchdog must produce actual exit125 before capture is
admitted.
`stopped_trace.py` is a child-only Linux x86_64 ptrace controller. Its retention
and cancellation gates alter no syscall returns or bytes. One gate holds the
real immutable source FD read while the normal CLI removes the snapshot name and record and
runs GC, then resumes the real restore and boots its child. Another stops actual
source fsync, cancels only the async fork waiter via `storage_acceptance`, checks
the surviving blocking owner's lifecycle/OFD/operation fences, resumes the
worker and requires complete publication before GC retirement. Requests,
exact syscall FD/inode/TID and source-identity receipts, command output and return
statuses are retained in `boundary-*.json`/`boundary-*.log`. The controller waits
on SIGCHLD rather than imposing a polling sleep on each syscall, inspects FDs
only for boundary-relevant syscall numbers, and stops syscall tracing after the
held boundary's release and checked injected return (if any). Lifecycle tracing
and pidfd/EXITKILL cleanup remain active. `boundary-trace.json` retains syscall
entry counts and the last 32 boundary candidates even on cancellation, so a
timeout does not lose all selection evidence. `boundary-lifecycle.jsonl` records
ESRCH from any stop inspection or resume, including disappearing `/proc` status
or memory, as a lost stop awaiting an actual terminal wait, never as exit proof.
Only a kernel exec event can account for collapsed former TIDs without a
terminal wait. Wait order is not creation order: an auto-attached child can stop,
run and be reaped before its creator's fork/vfork/clone event stop is dequeued.
Each `child-event` announcement is therefore balanced per TID against that
TID's terminal wait, exec collapse or manager detach, in either order, and
records `ended_before_announcement`; a reaped TID is never re-owned, and an
announced TID still owing an end fails the gate. No lifecycle path supplies a
missing checked injected return. Host-only
regressions in `test_native_live_api.StoppedTraceLifecycleTests` schedule real
SIGKILL between a stop and ptrace inspection, without replacing syscall or wait
results. A separate real-subprocess clone-race probe reproduced the late
announcement failure before correction and passed afterward. It is not a
permanent suite requirement: observing that ordering depends on kernel
scheduling, even when a child's exit is already waitable.
These are process/syscall evidence, not a power-loss simulation. The controller's
240-second deadline and helper's
60-second boundary wait are unchanged; missing ptrace permission is an unresolved
gate.

The negative syscall matrix injects exactly one EIO/ENOSPC/EACCES at actual
source sync, child copy/FICLONE, child file sync, no-replace rename or
post-publication directory sync. Scope is the held source inode or the newly
owned child `.copy-UUID/file-0`/parent FD, never an arbitrary path or read result.
The coalesced file-sync gate follows that first attachment to its final
`root.raw`/`upper.raw` name. At this barrier the SQL-visible child is already
complete but `constructed`; independent hashes and inode checks still apply.
An injected barrier failure must be reported, and fresh-runtime reconciliation
must retire that stopped, non-durable child before the retry.
`boundary-injected.json` labels the exact errno as injected syscall failure,
not physical media/power-loss evidence. The source's complete bytes/config/
semantic storage must remain unchanged, no partial child may be catalog-visible,
and a subsequent real retry must produce a complete independent copy. The
runtime owner's dedicated real SQLite trigger-abort test complements these
OS boundaries; no fake commit-success response is admitted.

### Actual mounted filesystem inputs

`SILO_SMOKE_STOPPED_DIR` selects an existing writable **host-mounted** directory
for persistent state, private disks, immutable artifacts and evidence. Its
generated runtime sockets/locks use a separately owned short `/tmp/silo-run-*`
tree, recorded in `runtime-placement.log` and retained/cleaned with the workspace.
That socket placement does not move disk bytes off the requested filesystem.
`SILO_SMOKE_STOPPED_FS` optionally requires its exact `findmnt` filesystem type.
Every native create records process-visible target/source/type/mount options,
kernel and actual state `st_dev` in `stopped-host-mount.log`. A path's name,
an ext4 image sitting on Btrfs, or a mount visible only in another namespace
does not qualify the ext4 lane. Never use `/boot` or overmount a system path.

After Main independently sees the owner-authorized isolated mount:

```sh
MOUNT=/absolute/owner-mounted-ext4
findmnt --target "$MOUNT" --output TARGET,SOURCE,FSTYPE,OPTIONS
SILO_TEST_COPY_DIR="$MOUNT" cargo test -p libvm private_copy -- --nocapture
SILO_TEST_COPY_DIR="$MOUNT" cargo test -p libvm --lib machine::stopped_storage::tests:: -- --nocapture
SILO_SMOKE_STOPPED_DIR="$MOUNT" SILO_SMOKE_STOPPED_FS=ext4 \
  make smoke SMOKE_ARGS='tests/test_stopped.py -m "not slow" --keep'
SILO_SMOKE_STOPPED_DIR="$MOUNT" SILO_SMOKE_STOPPED_FS=ext4 \
  make smoke SMOKE_ARGS='tests/test_stopped.py -m slow --keep'
SILO_TEST_COPY_DIR="$MOUNT" SILO_TEST_COPY_CROSS_DIR=/actual/other/filesystem \
  cargo test -p libvm private_copy_real_cross_filesystem -- --ignored --nocapture
```

`test_stopped_host_ext4_fork_requires_actual_mount` skips at collection when
`SILO_SMOKE_STOPPED_DIR` is unset. Configured lanes must still provide a real
process-visible ext4 input and `SILO_SMOKE_STOPPED_FS=ext4`; invalid inputs fail.
Copy-provider output must separately show the actual sparse/streaming fallback
method on that mount; native byte equivalence alone does not prove the strategy.
The owner-authorized image/mountpoint is not assumed usable until `findmnt`
inside the executing process observes ext4. The Linux qualification run used
an isolated loop-mounted ext4 image and observed `SparseCopy` for both children;
all 26 native stopped cases passed there. `/tmp` tmpfs and `/home` Btrfs results
do not substitute for that ext4 evidence. On a small test filesystem, run
bounded batches: preserve text logs and reports outside the mount, then remove
successful disposable payloads before the next batch. `--keep` retains full
workspaces, so an entire retained suite requires substantially more capacity.

If a writable reflink-enabled XFS mount becomes available, rerun the same
copy/integration and native cases there with the required `xfs` type, excluding
only the specifically ext4-named test; record the actual successful reflink
method and isolation evidence. Otherwise record `pending-lane:xfs`, with its
real availability reason. APFS/fclonefileat and native macOS remain
`pending-lane:macos`, owned by the actual-host Phase 25 matrix, not inferred
from Linux. Preserve and rerun Phase 4's existing opcode/unaligned-range,
pre-operation backing length/reopened-capacity, unsupported-punch fallback and
maintenance-upper fstrim/sentinel oracles unchanged alongside these new gates.

## Public native capture/restore API proof

`silo_smoke/native_live_api.py` drives the standalone
`native-live-api` example through the real Silo engine and libkrun Rust API.
It is an explicitly invoked Linux x86_64 KVM proof, never a Cargo VM test.
It does not deliver the monitor's public live commands or qualify other host
lanes. Native diagnostic controller modules supply guest transport and
independent validation, not the native operations under test.

Snapshot compatibility uses the native live-state schema and guest architecture,
not producer build identity. Keep source and input identities as reproduction
evidence, and keep diagnostic native features separate from production captures.
This standalone forensic CLI is separate from pytest and still takes explicit
native-provider guest inputs; they are not prerequisites for `make smoke`.

```sh
make smoke-prereqs KERNEL_PATH="$PRODUCTION_KERNEL"
python3 smoke/silo_smoke/native_live_api.py \
  --native-root "$NATIVE_CHECKOUT" \
  --entry target/debug/examples/native-live-api \
  --netd "$STAGED_RUNTIME/bin/netd" \
  --guest-init "$GUEST_INIT" --register-fixture "$REGISTER_FIXTURE" \
  --kernel "$PRODUCTION_KERNEL" --kernel-config "$KERNEL_CONFIG" \
  --evidence "$NEW_EVIDENCE_DIRECTORY" --case api
```

Use absolute input paths and a new evidence directory for each invocation.
`--guest-init` and `--register-fixture` are the retained real-provider guest
programs from the native standalone proof, not Silo's normal guest agent.
Keep the exact executable, kernel, configuration and guest input bytes needed
to reproduce the cohort, together with the source and input identities.

Run bounded cohorts sequentially. `positive` exercises generation on the
production kernel; `api` exercises capture and fresh-process restore;
`incremental` checks baseline and dirty-union behavior. `faults`, `late`,
`absent`, `expiry` and `restore-timeout` use the separately built generation
diagnostic kernel. `partial` requires the distinct fixture in
`virt/vmm/examples/native_live_api/native_generation_partial.{patch,h}`,
applied after the production driver patch, instead of the earlier generation
fault patch. Preserve the ordinary kernel configuration and keep these
diagnostic kernels separate from production inputs.
For the guest-protocol driver-absence control, also run `--case absent` with
an otherwise identical kernel built with `CONFIG_VMGENID=y` and
`# CONFIG_VIRTIO_SILO_VMGENID is not set`. Verify the emitted configuration
against the image's embedded configuration. The device must remain present,
with no processed acknowledgement and a failed five-second deadline, followed
by acknowledged stop and process reap. A diagnostic driver refusing probe is
separate evidence, not a substitute for this driver-disabled build.
The pending-generation cohort captures and resumes the exact source request
within its original deadline. It authenticates and seals the immutable capture
outputs after the source's exact ACK, before restoring the child. Output identity
and writer-closure checks guard that deferred seal; the deadline is not renewed.

`restore-failures` uses the production kernel. `failures` additionally needs
`--enospc-directory` naming a new empty mountpoint inside a private user/mount
namespace (`unshare --user --map-root-user --mount`). Its bounded tmpfs
exercises actual ENOSPC; do not substitute host disk exhaustion or `/dev/full`.
Run `capabilities` last, with `--monitor "$STAGED_RUNTIME/bin/silo-vmm"`.
On KVM x86_64, every live operation with a native primitive must report
`supported`, independent of the workspace's libkrun pin. Standalone native
proofs do not alter capability declarations. Snapshot compatibility uses the
native state schema and guest architecture, never exact producer builds.

`api-report.json`, per-process logs, captured manifests and input identities
are the evidence. Ordinary successful cohorts require acknowledged native
cleanup. OS reaping is a separate fact, not a native stop acknowledgement;
the explicit worker-death case instead requires the expected SIGKILL status
and released ownership. Cleanup success never turns an unexpected restore
failure into a passing proof. Keep failed payloads for diagnosis.
Completed candidates must close writers before reporting success. Failed RAM
attempts instead retain their output descriptors until explicit abandonment;
the failure cohort checks writer closure after that resolution, without
mistaking retained failure ownership for a completed candidate.
Remove successful bulk RAM/disk outputs only after preserving their evidence
and confirming that every owner and retained consumer has terminated.

## Capture-side multiple writable disk gates

After staging the runtime, run:

```sh
make smoke SMOKE_ARGS='tests/test_capture_multidisk.py -m slow --keep'
```

The eight cases cover raw and flat roots, each with two additional real
managed-writable ext4 disks installed before first launch under the existing
stopped-fixture lifecycle-lock convention. Ordinary `--disk` remains external;
this is fixture construction, not a new ownership-import API. The guest mounts
only its original source devices. It races ordered direct numbered writes,
dirty shared page-cache pages and unsynchronized metadata churn against capture.
Independent readers compare the exact pinned RAM GPAs with sealed disk files,
require an observed unsynced cache difference and ext4 journal/recovery feature
bits, and never mount, fsck or replay a sealed disk. Recovery bits establish the
mounted dirty-journal state, not a claim about which journal transactions need
replay. Later source writes overwrite the same numbered/cache offsets on both
disks while hashes and inode identities establish independent immutable copies.

Six failure cases inject a checked `ENOSPC` syscall return into the second Data
copy after the other included disks copied successfully. This faults actual
FICLONE or destination writes, not fsync or a fabricated success. They require
a producer-written failed record, no new snapshot or capture provenance,
policy-correct source continuation (acquired resume, acquired preserve and
borrowed user pause), unchanged run/boot/reseed identity and final staging
retirement. This is injected syscall-error evidence, not physical exhaustion or
power-loss evidence.

`capture-copy.json` records actual successful copy syscall returns.
`capture-multidisk-copy.log` retains those observations alongside the monitor's
actual Clone/SparseCopy method and planned logical lengths. Successful FICLONE
returns zero; its logical length is never reported as physical transferred
bytes. Host filesystem/device/mount options are observed with `findmnt` in
`stopped-host-mount.log`. `SILO_SMOKE_CAPTURE_FS` may require an exact filesystem
type; durable `TMPDIR` selects the workspace parent. An image filesystem or a
directory name never establishes a host storage lane. These tests do not
establish the APFS/non-reflink matrix, restored children, sibling divergence,
restore-time journal ordering or recapture.

## Hibernate and wake qualification (ADR 0023)

```sh
make smoke SMOKE_AREAS=hibernate SMOKE_MARK=
SILO_SMOKE_HIBERNATE_SLEEP=180 make smoke SMOKE_AREAS=hibernate SMOKE_MARK= \
  SMOKE_ARGS='-k wall_clock'
```

The `hibernate` area is Linux-only and slow. Its child-only syscall crash
controller additionally requires x86_64, like the existing capture controller.
It uses the real CLI, ordinary private Homes, existing execution witnesses,
managed/external disk fixtures and pidfd process ownership. No fault result or
saved state is fabricated. Collection never starts guests.

| ADR conformance item | Scenario in `tests/test_hibernate.py` (unless noted) |
| --- | --- |
| 1 | `process_memory_pid_boot_and_startup_survive_two_cycles`: existing native execution witness preserves PID, memory address, CPU/register/timer progress and boot id; the boot-started PID 1 keeps its PID, `/proc/1/stat` start time and command line. Idle `create`/`start` does not execute OCI CMD, so no image-command counter is assumed. Uses two vCPUs because its CPU/register threads pin themselves to CPU 1. Runs on raw and layered roots, twice, then snapshots and restores the woken guest. |
| 2 | `identity_is_preserved_including_image_machine_id`: id/name, actual guest MAC/IP, hostname, image-owned machine-id distinct from Silo id, and SHA-256 fingerprint of guest SSH host trust are unchanged. |
| 3 | `wall_clock_is_corrected_after_configurable_sleep`: default three-second sleep and 1.5-second tolerance; set `SILO_SMOKE_HIBERNATE_SLEEP=180` for the several-minute qualification and optionally `SILO_SMOKE_HIBERNATE_CLOCK_TOLERANCE`. |
| 4 | `paused_hibernate_wakes_running`: no inherited user pause after wake. |
| 5 | `stop_hibernated_then_cold_start`: clean stop retains a deliberately unsynced file; force discards without wake; both next starts have a new boot id. Raw/layered matrix. |
| 6 | `protected_operations_leave_save_disks_and_config_unchanged`: disk/live snapshot and fork, CPU/memory/disk/network/kernel/boot/name settings, raw flatten/export, pause and resume each refuse with the ADR diagnostic; actual disk/save bytes and catalog config bytes stay identical; each machine subsequently wakes. Handoff refusal is covered by the libvm host test only: its CLI requires a running source daemon before machine admission, unlike these daemon-free scenarios. |
| 7 | `every_saved_file_tamper_refuses_without_boot_then_plain_stop_discards`: delete, truncate and same-byte replacement of every discovered saved file. `each_writable_disk_tamper_refuses_without_boot`: writes to the root and every managed/external writable data disk. Exact refusal reasons, no monitor, plain-stop discard and successful cold boot are required. |
| 8 | `tests/test_hibernate_crash.py`: CLI/manager killed while native saved-RAM write is held, then bounded guest-access retries drive recovery (read-only info deliberately does not); monitor/worker killed while native saved-RAM mmap is held before consume, then retry the untouched save. |
| 9 | Explicitly skipped: no existing rootless bounded-filesystem Home fixture. Filling the shared host filesystem is unsafe; injected ENOSPC would not prove this scenario. |
| 10 | `twenty_concurrent_accesses_share_one_wake`: twenty exec/cp/shell callers, identical new run id, preserved boot id, clean exec stdout/copied contents and complete shell output lines despite PTY echo/prompts, at least one wake notice and at most one exact notice per caller. |
| 11 | `hibernated_fresh_cli_without_silo_processes` simulates process disappearance in the private workspace and uses a fresh CLI. This is not a host reboot, filesystem remount, Btrfs device-number reassignment or ext4/Btrfs reboot matrix. |
| 12 | `exec_session_ends_and_configured_forward_reconnects`: old exec, shell and session-forward clients end, configured forward disappears, then accepts a fresh connection after wake. The long-lived shell uses the existing PTY helper with `TERM=dumb`, like the workspace's normal shell environment, so it does not wait for an unanswered cursor-position query. |

Additional cases cover stopped/already-hibernated/temporary-machine admission
(an unnamed `silo run`, with stdin held open and guest readiness witnessed),
observational list/info/logs/forward-list commands, and each access command
individually waking with exactly one `Waking NAME` line on stderr, except
`shell`, which wakes without any line.
All happy-path saves require every discovered saved file to be read-only.

`silo_smoke.hibernate.report()` is the only adapter for public info fields:
`hibernation.hibernated_at` (Unix seconds),
`hibernation.saved_state_bytes` (positive allocated bytes), and
`hibernation.memory_capture.{mode,full_reason,stats}`. Native camelCase counters
`fullBytesWritten`, `baselineBytesWritten` and `overlayBytesWritten` are summed
for perf's bytes-written evidence. Mode is `full` or `incremental`; incremental
capture has no full reason.

Remaining manual crash coverage: post-durable/pre-release, post-consume, discard
checkpoint and true host-power-loss boundaries, plus deliberate PID reuse.
The existing controller does not expose those exact row boundaries for
hibernate. All destructive process signals here use pinned pidfds, never a
reused numeric PID. Incompatible CPU/kernel/schema saves and metadata-preserving
silent corruption are outside this module's tamper cases.

