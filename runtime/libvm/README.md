# libvm

`libvm` is the Rust library boundary for managing Silo virtual machines.
It gives callers a `Runtime` entry point, then returns `Machine` handles for
lifecycle operations.

Use it when you need to create, resolve, inspect, start, stop, restart, or
remove Silo VMs from Rust code. The crate keeps database rows, runtime state
files, image materialization, and monitor processes behind the API boundary.

Choose an operation by intent, not by whether its output looks like a terminal:

| Rust API | Transport | Purpose | Result |
| --- | --- | --- | --- |
| `exec` / `exec_with` | Agent RPC | One program with literal argv | Collected `ExecutionOutput` |
| `spawn` / `spawn_with` | Agent RPC | Streaming program, optionally a PTY | Owned `ExecutionSession` |
| `exec_script` / `exec_script_with` | Agent RPC | `/bin/sh -l -c SCRIPT` convenience | Collected `ExecutionOutput` |
| `shell` / `shell_with` | SSH over vsock 22 | Login shell, local or caller-supplied I/O | `SshExitStatus` |

Go uses `Exec`, `Spawn`, `ExecScript`, `Shell`; Node uses `exec`, `spawn`,
`execScript`, `shell`. `shell` never accepts a script string. Use `spawn` with
`tty(true)` for an interactive **program** over the agent, not an SSH login.

```rust,no_run
use libvm::{Memory, Runtime};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), libvm::LibVmError> {
    let runtime = Runtime::from_env().await?;
    let machine = runtime
        .machine()
        .image("docker.io/library/alpine:latest")
        .name("devbox")
        .cpus(2)
        .memory(Memory::mebibytes(1024))
        .create()
        .await?;

    // A normal start boots an idle machine.
    machine.start().await?;
    let data = machine.inspect().await?;
    println!("{} is {:?}", data.name, data.status);

    machine.stop().await?;

    Ok(())
}
```

The main shapes are:

- `Runtime`, the service entry point.
- `MachineBuilder`, the durable image-first creation request.
- `Machine`, an operable handle for one VM.
- `MachineData`, an owned snapshot returned by inspect and lifecycle calls.

## Creation And Lifecycle

`MachineBuilder::image` always accepts an OCI reference. Use
`image_source(ImageSource::disk(path))` for a local disk. `create` materializes
the selected root disk and persists a stopped machine; it never starts the VM.
Every new machine pins a complete kernel, base initramfs and explicit optional
agent tuple, plus its canonical bundle object. Start authenticates only these
owned objects and regenerates launch-only bootstrap data. Package upgrades,
removed source files and changed defaults never silently change an existing VM.

`MachineBuilder::platform(Some(LinuxPlatform { .. }))` selects OCI userspace
before materialization. Native kernels must match the host architecture; there
is no CPU emulation. Rosetta intent is tri-state: `rosetta(None)` omits an
optional request, `Some(false)` explicitly disables it, and `Some(true)` requests
it. Foreign amd64 userspace on an arm64 macOS host derives required translation,
which cannot be explicitly disabled and requires actual installed host support.
Trusted init prepares both required and optional Rosetta before any workload
execution, independently of guest-agent injection.

The frozen effective backend governs both admission and the monitor request.
Direct OCI creation on VZ refuses before materialization and names explicit
OCI-to-raw conversion; VZ also refuses managed overlay roots. Stopped snapshots
and forks admit raw whole-disk and GPT/MBR partition roots and retained layered
roots, subject to their boot/backend admission. Live capture keeps its narrower
whole-disk/layered-overlay root set. Neither lane is qualified merely by boot
admission; public live lanes remain unqualified.

Managed aliases resolve to typed immutable targets. Image roots are copied from
their authenticated stream capability. A snapshot source uses full snapshot
restoration, preserving captured configuration and included disks rather than
copying only its root. Snapshot creation accepts a new name; other nondefault
create settings are refused and require explicit stopped updates after restore.

`LiveSnapshotOptions` defaults to `CapturePolicy::Full`. Explicit incremental
capture (including live-fork capture) accepts `dirty_crossover_percent` in
`1..=60`, with 60 as the default. Normal capability admission still applies.
Successful capture summaries carry actual mode, baseline identity, fallback
reason, affected identity chunks and separate native I/O/whole-file hashing
facts. Each checkpoint owns a complete canonical RAM map and complete closure;
its predecessor is not a replay dependency.

Execution restore reports `LibVmError::CheckpointPortability` with the exact
failed pin and captured/destination values at `restore-preflight`, before a
child is allocated. Compatibility is not required to import or retain an
authenticated artifact. `Runtime::recover_checkpoint_disks` is a separate,
explicit operation with `RecoverDisksOptions`: it authenticates storage and
captured boot, creates new private disks and a stopped machine with unknown
stop outcome and source-checkpoint provenance, and installs no RAM. An
ordinary explicit start cold-boots it. Restore never falls back to recovery.

Use `Machine::update_boot_assets(BootAssetsUpdate { selection })` for an explicit
stopped replacement. It requires exclusive stopped-generation ownership and
atomically commits the complete tuple, dependent agent configuration and next
storage generation. `Packaged`, a complete `Files` tuple and an owned `Exact`
bundle are distinct selections; omitted members never inherit old assets.
Fresh custom file tuples currently require the base initramfs to match the
locally packaged schema-2 bootstrap bytes. Unknown custom base ABIs receive
`BootBundleAbiUnsupported`, not an unsupported boot claim. Previously admitted
exact bundles remain usable after packages change. Ordinary configuration
replacement cannot change kernel/initramfs or agent selection behind the pin.
Inspection reports the current tuple and, when it can be locally admitted, a
different packaged replacement without publishing or applying it.

Raw roots admit their kernel by its own bytes, never by a declared or recorded
architecture alone. While the selected kernel is hashed, libvm keeps its first
4 KiB and requires the host's native direct-loader format for the pinned
kernel architecture: an x86-64 little-endian ELF64 executable `vmlinux` with
in-file loadable segments, or a little-endian arm64 `Image` whose declared size
covers the file. Import, creation, updates, exact bundles, replacement
reporting, capture and every pinned start apply this check to the
authenticated bytes before publication or launch. Arbitrary data and
wrong-architecture kernels fail with `DirectKernelRejected`, carrying the
kernel digest and exact reason. Admission deliberately does not inspect kernel
configuration: custom kernels need no embedded IKCONFIG, and a kernel missing a
required filesystem, partition, device or Rosetta capability fails at boot.
Overlay roots keep their exact reviewed tuple admission instead.

The mandatory schema-2 root bootstrap carries the named root attachment,
effective geometry, concrete disk-local selector, ext4 filesystem and effective
Rosetta mode. Kernel `root=`, `rootfstype=` and `rootflags=` overrides are
reserved for trusted bootstrap selection, and `rdinit=` is reserved because
the trusted `/init` is the only initial executable; create, configuration
replacement and start refuse them in any spelling the kernel recognizes,
quoted or not. `init=` remains the image init handoff. Partitioned roots do
not receive automatic partition or filesystem resizing.

`Machine::start` and `Machine::stop` manage a persisted machine. A normal start
creates an idle VM. `Machine::start_with` can instead set one
`Entrypoint`; startup succeeds only after that guest program launches, and
`silo-vmm` stops the VM when the program exits:

```rust,no_run
use libvm::Runtime;

# async fn example(runtime: Runtime) -> Result<(), libvm::LibVmError> {
# let machine = runtime.machine().image("docker.io/library/alpine:latest").create().await?;
let start = machine
    .start_with(|options| {
        options.entrypoint("/usr/bin/printf", |entrypoint| {
            entrypoint.arg("hello from silo\\n")
        })
    })
    .await?;
let exit = machine.wait().await?;
println!("run {} ended: {:?}", start.run_id, exit.outcome);
# Ok(())
# }
```

`MachineRetention::Persistent` keeps a machine until removal.
`MachineRetention::Ephemeral` permits a lifecycle owner to attempt removal after
the run exits. Cleanup is best effort and is not persisted or retried.

Each launch registers one retained storage operation for its exact machine, run
and storage generation before reading backing contents. Its shared lease follows
the monitor and attachment-owning worker; cancelling startup does not remove the
durable pins. Restart, removal and private-disk replacement require every
registered holder to be terminal, an independently opened exclusive lease, and
transactional lifecycle/storage reconciliation. A missing monitor or free lease
alone is not permission to reuse the disks. Missing or malformed admitted holder
records fail closed; only a provably pre-attachment startup failure can retire
without one.

Startup failure cleanup also waits for actual registered-holder termination and
exclusive-lease reconciliation before recording the terminal failure. A bounded
timeout retains the operation pins and reports incomplete cleanup; it never
converts a still-owned generation into reusable storage.

Startup and failed-start cleanup identify the monitor only through the exact
run's durable holder record: machine, run, operation and process birth identity.
On Linux the authenticated pidfd carries later signals; the emergency
process-group kill uses it on Linux 6.9 or newer and otherwise falls back to a
leader-checked numeric group signal. A pidfile number, another run's holder or
a reused PID never authorizes a signal. Without an authenticated monitor, the
closed startup pipes cancel a pre-holder monitor and cleanup still waits on
holder/lease evidence alone.

Machine-owned directories are derived from the current catalog home and typed
machine ID, not persisted absolute directory authority. Moving an entire
current-format stopped home therefore changes the owned path without prefix
rewrites or data migrations. Explicit external disks and shares remain external
resources and are not rebased.

`MachineData.storage.stop_outcome` is independent of lifecycle status. Storage
is `clean` only for the expected run's clean outer exit record with all three
version-1 shutdown facts: guest protocol completion, host flush completion and
attachment closure. Valid forced/error exits remain `forced`; missing, stale,
malformed or incomplete evidence becomes `unknown` after liveness is ruled out.
Writable external disks/shares retain their existing VM support but do not gain
all-writer certification merely from a Silo operation lease. The exact launch
inventory, including read-only generated shares, is injected into the guest and
sent to the monitor as one trusted context.

Read-only inspect projects terminal lifecycle and storage outcome together from
the same expected-run exit evidence after registered holders are terminal. This
does not write lifecycle/storage rows or retire operation pins. Destructive
operations still require exclusive-lease admission and atomic durable
reconciliation. Force stop waits within its timeout for that complete
holder/lease reconciliation after monitor termination, rather than treating the
monitor's death as completion or reporting a live retained generation as absent.

## Managed Raw Images

A managed image is an immutable creation source, not a captured machine or an
OCI filesystem-cache row. Its schema-1 `ImageRecord` includes the opaque raw
root stream and map, 512-byte geometry, disk layout, concrete root selector,
ext4 filesystem, Linux userspace platform, complete pinned direct-boot bundle
and process defaults. `ImageId` is SHA-256 of `silo:image:v1\n` followed by the
RFC 8785 canonical record. The record's ordinary byte-object digest is separate.
Changing boot or process semantics changes the image identity even when the
root bytes do not. Source paths, container encoding and original OCI spelling
are appendable provenance, not image identity or retained source-container bytes.
Partition provenance encodes the full GPT attribute bitmask as sixteen lowercase
hex digits in JSON, preserving DPS flags above the exact JSON integer range.

Images and snapshots share one `image:NAME` alias namespace. Each name targets
exactly one typed image or snapshot; collisions, corrupt dependencies and
ambiguous cross-kind digest lookups fail closed. Explicit image retention is
independent of aliases. Releasing retention leaves aliases rooted; removing an
alias does not release explicit retention. Catalog removal never recursively
unlinks shared content. Stream and object collectors account for image maps,
canonical records, bundle records and every exact boot member.

A retained stream can have a verified complete chunk representation in canonical
`objects/` independently of its flat `streams/` materialization. Explicit pruning
may evict that flat file only when no operation, machine, OCI cache artifact or
layer result needs it. Eviction journals `present` → `evicting` → `absent`; missing
flat bytes without that authority are corruption. A managed consumer reconstructs
from the exact canonical map and retained encoded chunks into fresh sparse
staging, verifies both chunk identities and StreamId, then joins the shared
immutable stream publication. Reconstruction never contacts a registry. Canonical
sole-copy chunks have no TTL.
Publication retains the selected exact encoding and its writer profile, including
zstd's legitimate all-raw fallback, for subsequent pushes without recompression.
Whole boot-object stream encodings remain rooted by their semantic object owners;
representation-only self references never become permanent retention roots.

Source blobs expire after seven days and redundant transport bytes after thirty
days of recorded use. Explicit cache pressure may remove them sooner, but never
while the existing operation's one closure lease pins them. Expected cache
identities are registered before lookup/download; no lease descriptor is opened
per chunk. Machine dependency indexes are committed with their exact storage
generation, and collectors reject missing or surplus indexed edges.

An imported live checkpoint retains its exact portable provenance and source seal
separately from a local capture reservation. A local acquisition receipt binds
the approved immutable index, repository, policy and selected provenance through
the exact metadata child/config descriptor chain. Restore selects matching
authenticated local or imported provenance, rather than trusting the first row.
Digest approval establishes integrity and permission to import, not an
authenticated publisher or proof that a local monitor performed the source cut.


`Images::import_disk` imports a quiesced caller-owned regular file. The path is
opened once with `O_NOFOLLOW`; a final-component symlink, directory, FIFO or
device is rejected, and every later read uses that held descriptor. Format is
classified by bytes, never by name: qcow2 v2/v3 is admitted by the bounded
`disk-image` decoder (no backing, external data, encryption or zstd); VMDK,
VHD/VHDX, VDI, QED, LUKS and compressed archives need offline conversion; any
other content is raw and must be a positive 512-byte multiple up to 1 TiB. Raw
bytes copy directly into the pool; qcow2 decodes into sparse operation staging
with the exact virtual length. Partition, root and filesystem facts come from
those owned bytes: the shared `disk-partition` parser in strict import mode,
Linux direct-table admission (128-byte GPT entries), then exactly one root. A
whole-disk selection requires no table; `auto` takes the single DPS root for the
declared userspace (never no-auto or read-only); a GPT unique GUID or original
MBR slot 1..4 names one partition. Refusals carry every disk-local candidate.
The selected range must hold an ext4 superblock the pinned kernel mounts
writable: revision 1, 1-4 KiB blocks, admitted feature allowlist, clean state,
valid metadata checksum and a size inside the range. Nothing is mounted or
traversed. A source fingerprint change at any point fails the import. Raw and
qcow2 imports of the same decoded bytes and semantics produce the same
`ImageId`; provenance records the container SHA-256, spelling, lengths and the
observed selected partition.

Import admits its pool-space peak before decoding or copying, through the same
cross-home resource ledger as capture and restore. Raw charges the immutable
publication copy plus map staging; qcow2 also charges the simultaneously retained
decoded staging file. Charges use conservative logical lengths, not sparse
allocation, deduplication or reflink assumptions. Insufficient capacity reports
required and available bytes independently of the unchanged 1 TiB format bound.
The real blocking worker retains the operation lease and reservation even if its
caller is canceled; completion releases the peak, and abandoned-operation
recovery retires charges left by process loss. Machine creation separately
reserves the later private root copy on its destination filesystem through
publication, including an explicitly enlarged root disk. Ordinary failures
after reservation roll back the private machine directory before releasing
capacity and retiring the copy operation; they do not require a later runtime
open to reclaim the charge. Uncertain publication keeps its recovery authority.

`DiskImportRequest::admit` returns an opaque `AdmittedDiskImport` retaining the
single source descriptor and fingerprint. Local and daemon adapters use this
prepare/consume boundary before writable runtime initialization, so structurally
invalid geometry, containers and special files cannot trigger initialization or
recovery effects. `Images::import_admitted_disk` consumes it without reopening
the source; `Images::import_disk` performs both steps for an existing runtime.

The conversion catalog maps the canonical `(manifest digest, Linux platform,
flattener ABI)` key to an immutable image. The manifest binds its config, so the
config digest is checked provenance, not another key dimension. Conversion is
explicit (`Images::convert` on an already selected OCI identity); creation and
start never convert implicitly, on any backend. Conversions serialize on the key
and recheck the mapping under that lock, so identical concurrent requests yield
one image. A miss reuses the one OCI flattener and rootfs cache for the selected
platform, publishes that exact immutable stream as a whole-disk ext4
`LinuxDirect` root, pins the then-packaged kernel, base initramfs and agent, and
preserves the OCI entrypoint, command, environment, working directory and user
as process defaults. A retained hit authenticates the original complete
closure, including its original bundle, rather than flattening again after a
runtime upgrade; a new alias names that same image. Missing or corrupt hit
content is an error, not a cache miss. Collection of the image removes the
conversion mapping.

Import/conversion work registers the existing operation journal and original
shared OFD before protected reads. Prepared stream/map and boot-member outputs
remain rooted until publication completes. The actual blocking publisher owns
the lease and writable catalog capability even if its caller is cancelled.
It authenticates content outside roots coordination, records the exact image
candidate before an uncertain commit, then atomically commits image identity,
exact dependencies, retention, provenance, optional alias and conversion key.
Consumers resolve and recheck the typed public target and register its entire
closure in one roots-coordinated transaction before opening artifact bytes.
Inspection is not a lease. Abandoned operation recovery and GC use the existing
journal and lease machinery; there is no second cleanup or alias namespace.

## OCI VM Artifact Transport

`Images::inspect_artifact` resolves and checks bounded remote metadata without
retaining content or booting it. `acquire_artifact(ArtifactAcquireRequest)`
requires an exact immutable index digest via `ArtifactTrust::ApproveDigest`;
the resulting publisher is explicitly unauthenticated. `RequireSignature`
fails closed because no signing provider is integrated. A VM artifact is
recognized before OCI container platform selection; ordinary container
creation refuses it and requires explicit acquisition.

`publish_artifact(ArtifactPublishRequest)` exports the complete managed image
or checkpoint, including pinned boot bytes and all included disks. Checkpoints
require acknowledgement naming the exact destination. Live checkpoints also
carry their execution state, device state, RAM and portable source seal.
Acquisition does not grant live-restore compatibility or capability admission.

The OCI index has a metadata child and bounded payload children. Every
descriptor preserves exact bytes in the destination repository; source OCI
manifests and referrers are not payload dependencies. Raw/zstd transport
encodings and pagination do not change semantic or decoded stream identities.
Publication uploads payloads before child manifests, then the index, then the
optional tag. Retry reuses retained exact encodings and skips existing registry
blobs. Pull rehashes completed cached bytes, refetches invalid/missing chunks,
and reconstructs streams into fresh zero-filled staging before publication.
Concurrent cache publishers serialize by digest; a contradictory descriptor
cannot delete another acquisition's valid cached input.

Acquisition reserves its conservative simultaneous download, decoded-staging
and immutable-publication peak through the shared cross-home import ledger
before bulk effects. Detached operations retain their lease and capacity
through blocking work even if the caller disappears. Complete semantic
verification precedes atomic catalog publication; failed operations retain
recovery authority, not partial public images or aliases.

## Stopped Snapshot Retention And Identity

Stopped-storage snapshots are immutable opaque-raw or layered-root checkpoints,
not execution checkpoints. Their current schema-1 record includes complete
configured semantics, ordered included disk streams and maps, exact pinned
next-boot assets, external resource requirements, and the actual `clean`,
`forced`, or `unknown` stop outcome. Capture preserves guest bytes, including
credentials, filesystem identities, journals and deleted-data remnants; it does
not sanitize or repair them. Host machine identity, source paths, display names
and timestamps are not identity inputs.

A layered snapshot retains the exact composition recipe/result and fsmeta,
every occurrence of the layer recipe/result/index closure and payload-pack
stream, plus the upper. Layer order and repetition are identity-bearing; no
single materialized flat lower substitutes for this graph. Exact retained
artifacts are the portability boundary. Original OCI regeneration is only a
digest-gated fallback, never a requirement to restore a portable snapshot.

The snapshot ID is SHA-256 of `silo:snapshot:v1\n` followed by the RFC 8785
canonical record. The serialized byte-object digest is separate. Canonical
records reject duplicate or unknown properties, floating point, unsafe integers,
and malformed Unicode. Property ordering uses UTF-16 code units, including user
configuration keys, without Unicode normalization.

`SnapshotStore` resolves immutable `image:sha256:HEX` references and shared
`image:NAME` aliases. An unnamed snapshot has its own persistent retention root.
`remove_alias(NAME)` removes only a name; `release_retention(reference)` releases
only explicit retention. Either an alias or explicit retention keeps the artifact
rooted. Neither operation recursively deletes shared objects. A restore registers
its complete consumer closure before reading artifact bytes, so removing the last
public root cannot race away an in-flight restore's disk maps, raw backing, or
boot objects. After child publication, only its actual boot/read-only dependencies
remain; its private writable disks do not depend on the source snapshot.

Catalog reads fetch only immutable row/dependency facts inside the read
transaction. JSON decoding, canonicalization and identity authentication occur
after it ends; mutation and consumer admission then recheck the same facts under
short coordination.

Abandoned child recovery binds its exclusivity proof to the acquired operation
OFD's indexed device/inode, not merely the lease pathname. An uncommitted child
transitions from `committing` to `cleaning` before an atomic no-replace detach to
`machines/.retiring-<operation>`. Recursive deletion, parent synchronization and
fresh destination credential cleanup run outside roots and SQL while retaining
the exclusive OFD and catalog capability. Recovery recognizes the original or
quarantine name after interruption, then rechecks durable absence before retiring
pins. Traversal stays bound to the verified open directory, with no-follow parent
entry identity checks before traversal and final directory unlink; it never
reopens a mutable quarantine name to select the tree. Each enumeration opens
`.` relative to the retained directory FD to obtain an independent cursor and
fresh filesystem enumeration state, including Btrfs's open-time entry boundary.
Quarantine entries are not
configurable resources, including a reserved spelling that symlinks outside the
catalog. Reservation is checked lexically before resource symlink resolution.
New disks/shares or containing mounts cannot intersect a cleaning candidate; an
existing external reference instead defers cleanup before detachment.

## Live Capability Admission

`vm_spec::live` defines five fixed operations (`pause`, `capture`, `restore`,
`fork`, `incremental`) and the closed typed refusal reasons. Host reports describe
the frozen prospective backend selection; machine reports describe the actual
backend of a specific machine/run/monitor/topology. Missing fields, unknown
enums, invalid scopes and malformed typed subjects are errors, not old-monitor
defaults.
Tagged JSON alternatives must also reject extra fields: `supported` cannot carry
a reason, and unit device subjects cannot carry a guest-profile or other payload.
Durable machine IDs keep their existing compact display; live reports and
monitor IDs use canonical hyphenated UUIDs. Durable-to-live machine fencing
compares UUID identity, while monitor outer IDs and live run/monitor fencing
remain exact.

`LiveCapabilityQuery` performs discovery without opening writable runtime state.
`LiveObservationReader` performs explicit read-only catalog lookup and run status
observation. Observation may take read-coordination locks and send `GetStatus`.
Read-only means unchanged logical database contents and persisted machine/runtime
state; ordinary SQLite-native WAL/SHM coordination is permitted, so sidecar bytes
and existence are not the read-only invariant. The SQLx observer uses read-only,
query-only, no-create-main access with a shared native catalog guard and a close
barrier. It must not initialize missing state, invoke writable application
recovery or migrations, mutate logical records, or reserve operation resources.
Planning uses the same logical read-only SQLite mode but retains an exclusive
catalog guard to exclude cooperating writers; WAL presence alone is not refusal.

Machine live operations consume an opaque `MachineLiveObservation`; restore
consumes prospective host evidence. Their first step refuses unsupported
operations before new operational locks, leases, budget permits, workspace/child
allocation or lifecycle RPC. This release's endpoints are typed refusals, not
checkpoint-success placeholders. Positive scenario reports cannot grant a
successful undelivered manager operation. Production qualification belongs to
the compiled, actual-revision-bound monitor, never `SILO_HOME`, SQLite or an
environment grant.
Observable build-input fingerprints and declared feature fingerprints are not
gate evidence or actual dependency-feature observations. Until the native
provider supplies actual compiled build facts, qualification is categorically
ineligible, even if a record otherwise matches.

## Durable Storage Model

This storage release is a hard break. Reinstall Silo and explicitly wipe all
previous Silo state before using it. An incompatible database is refused with
a reinstall/wipe diagnostic; the runtime never deletes user state to make it fit.
There is no upgrade, root conversion, or old-cache adoption path.

By default new machines own a private `root.raw` disk. SQLite records closed root,
boot, storage-profile and backend variants, relative private paths, geometry,
ownership epoch and storage stop outcome. `MachineData::storage` exposes that
typed meaning; `MachineData::storage_stop_outcome` also carries the observed
outcome through daemon inspection, without fabricating a complete local storage
record. Source manifest/config references are provenance; retained lower
stream identities, not source tags or descriptor text, are GC dependencies.

Private machine directories are derived from the currently opened catalog home
and typed machine ID (`<home>/machines/<id>`). Machine configuration does not
persist an absolute `machineDir`; configuration, inventory, rootfs and read-only
observation lookups all use that same current-home derivation. Moving a closed
current-format home therefore requires no catalog rewrite. Absolute external
resources remain external dependencies, not relocation hints.

`MachineData::external_resources` derives typed external-disk and share mappings
from the current durable VM specification. They are never promoted to owned
storage or evidence that a machine is self-contained; active operations retain
their exclusion constraints independently of the machine row.

Each managed launch durably pins its resolved storage generation before backing
verification or attachment work. One operation UUID and one shared-flock open
file description protect the entire closure, including retained streams,
boot objects, semantic layer dependencies and private/external attachment
constraints. Parent and child duplicates close independently without explicitly
unlocking; the stable `images/locks/leases/<operation-id>.lease` inode is never
removed by cleanup. Cancellation leaves the durable root for recovery rather
than attempting asynchronous database work from a destructor.

Image and layer producers register their operation before slow work, then add
each published stream/object dependency while still owning that publication's
roots guard. A staging operation row alone never retains unregistered published
outputs. Disposable per-file staging uses publication locks solely to protect
unpublished temporary directories; these are not generation leases or GC roots.

Local collection discovers at most 256 immutable candidates per batch, then
rechecks semantic reachability, external-resource constraints and nonblocking
lease state under roots coordination. Its blocking owner retains the catalog,
deletion authorization and directory descriptors through unlink, directory sync
and commit, even if the async caller cancels. Unknown busy leases and missing,
unsafe or replaced operation lease inodes block destructive recovery. A free
lease alone never retires a launch: exact-generation holder terminality and
lifecycle/storage-outcome reconciliation are required first.

### Layered EROFS OCI roots

OCI creation on libkrun defaults to `linux-erofs-overlay-v1`: immutable per-layer
payload packs and merged EROFS fsmeta, plus a freshly formatted private
`upper.raw`. There is no `MachineBuilder::root_profile`, CLI `--root-profile`
selector or template `root_profile` field. The old development flat profile is
removed; obsolete profiles receive typed rejection, not a compatibility shim or
raw fallback. VZ requires explicit `silo image convert REF --disk-format raw`.

`root_disk_size(bytes)` selects upper backing capacity, defaulting to 4 GiB;
the admitted envelope is 64 MiB through 1 TiB, aligned to 4096 bytes. Backing
length, achieved ext4 span, unusable short-group tail, filesystem overhead and
usable bytes are distinct.

Every upper has a new UUID. Creation holds the materialization lease until the
machine and lower retention root commit together. Pruning image references does
not remove a machine's retained lower. Start never resolves the image source
again. It regenerates a bounded read-only `lower.vmdk` for the current home,
preflights descriptor/record/FD bounds before authenticating lower bytes, and
retains closure ownership through startup or completed failure cleanup. The
running machine's semantic root remains the durable retention root. Worker-FD
lease transfer and certified storage shutdown remain separate lifecycle gates.

Only an exactly admitted kernel/init/native-monitor/profile/architecture/krun
tuple may launch. VZ, mock and unqualified artifacts fail before materialization
or launch effects. Admission retains opened
boot artifacts. Launch copies and hashes the kernel and base initramfs from those
same descriptors, never reopening the original paths. On Linux it rechecks and
executes the retained native ELF through `/proc/self/fd/N`, keeping the descriptor
CLOEXEC in the parent and owned through startup acknowledgement. Worker reexec
uses `/proc/self/exe`, so atomic runtime restaging cannot switch the already-loaded
monitor's worker binary. No native executable copy is made per start. Managed
staging publishes a complete sibling tree by atomic rename/exchange, rather than
rewriting the live ELF. These guarantees do not promise protection against hostile
same-UID in-place writers. Root bootstrap is appended independently of agent injection;
the overlay root marker and fixed serials cannot be replaced by root arguments.
There is no automatic raw fallback.

Stopped `MachineUpdate::root_disk_size(bytes)` publishes a replacement private
upper generation, preserving its old byte prefix, UUID and journal state.
The host changes no ext4 metadata; init replays and grows upperfs at next boot.
Shrink and active attachment resize are refused. `/tmp` remains disk-backed;
`temporary_directory(TemporaryDirectoryPolicy::Tmpfs { capacity_bytes })` selects
a sized tmpfs at create or stopped update, and `DiskBacked` removes that selection
on the next boot without deleting previously hidden disk contents.

After stop removes a machine's runtime tree, stopped storage or `/tmp` policy
updates recreate it through the same owned-directory admission used by start,
with mode `0700` before opening the lifetime lock. Lock-file opening never creates
parent directories using ambient umask permissions. An existing unsafe directory
is refused unchanged; settings updates do not repair its permissions or user data.

Private copies use exclusive destination creation through every reflink/copy
fallback; an existing destination is never truncated or removed. Before catalog
publication begins, dropping a replacement removes only its unpublished file.
Immediately before the asynchronous SQLite write, ownership changes to
conservative retention: requester cancellation or runtime shutdown may leave the
COMMIT outcome unknown, so both complete generations remain. A returned failure
removes the candidate only after a completed semantic reread, under the retained
machine/lifetime locks, proves that the catalog does not reference it. Confirmed
success removes the old generation. Creation uses the same preserve-before-write
boundary for its machine directory. This favors retained unreferenced bytes over
a catalog root pointing at a deleted file; no uncertain publication is silently
treated as a confirmed rollback.

### Stopped raw export

`Machine::export_raw_disk(RawDiskExportOptions)` is the API behind
`silo storage export VM DEST --disk-format raw [--flatten-filesystem] [--format json]`.
It requires an already-stopped source with Linux direct boot, exports only its
root, and never implicitly stops, repairs or snapshots the machine. EFI/macOS
roots receive typed unsupported rejection. Attached data disks and shares are
not included.

Opaque roots are copied byte-exactly, including dirty journals, unused bytes and
deleted-data remnants. Layered roots require explicit `flatten_filesystem` and
a strictly audited, supported, clean on-disk ext4 upper. A recorded clean stop
cannot bypass that check. Recovery-required state returns
`RawExportRecoveryRequired`; unsupported/corrupt layout or OverlayFS index state
is rejected rather than approximated. No host journal replay occurs.
Flattening authenticates the retained lower, preserves the visible namespace
and surviving hardlink groups, removes OverlayFS controls and writes a fresh
whole-disk ext4 filesystem with a new UUID/identity, not an exact checkpoint.

The existing destination parent must be outside the runtime state root.
Neither destination nor its `.json` sidecar is overwritten. `RawDiskExport`
records geometry, boot requirements and `opaque-exact` or `flattened-filesystem`
kind, with the latter's new filesystem UUID. Both the sidecar and CLI JSON report
serialize `path` and `metadataPath` as raw Unix pathname byte arrays. No
sanitization, EFI synthesis or cloud-provider bootloader is supplied.

### Stopped forks and checkpoints

`Machine::fork_stopped(ForkOptions)` creates a new **stopped** machine from an
opaque raw root or an admitted `linux-erofs-overlay-v1` root.
`Machine::snapshot_stopped(SnapshotOptions)` captures an immutable opaque-raw
or exact layered-root checkpoint.
`Runtime::restore_snapshot(SnapshotRef, RestoreOptions)` dispatches
by the checkpoint's capture kind: stopped storage produces a new **stopped**
machine, while a live checkpoint continues execution through paused construction
and fenced activation. Neither path stops a source, replays a journal, repairs
a filesystem or resizes captured bytes. A stopped source's reconciled
Clean/Forced/Unknown outcome remains unchanged by synchronizing files now.

All managed writable Data disks are included and become independent private
files with fresh host disk IDs. Read-only and pinned boot dependencies remain
retained. Hardware, process (including unset versus empty commands), guest/user,
userdata, environment, temporary-directory policy, labels and network intent
are preserved. Host machine/name/lock, SSH CA, run and network endpoint identities
are new; source runtime files and external secret scopes are not copied.

External disks and shares are refused by default. `RequireMappings` explicitly
omits their bytes and records required destination resources; such a child
cannot start until those resources have explicit mappings. Fork/restore accept
`Map { mappings }`, keyed by full attachment ordinal or share tag, without
claiming ownership or self-contained storage for the mapped host resources.
Snapshot creation accepts omission-as-requirements, not destination mappings.
No host directory tree is implicitly imported.

Stopped child publication requires catalog-owned secret-scope recovery.
An explicit `Runtime::with_secret_store` override is refused before fork/restore
effects because an arbitrary external store has no durable child-scope recovery
contract. This does **not** reject the existing guest secret-provider feature:
`with_secret_provider` and configured policy/secret-slot intent remain supported,
and the normal CLI FileStore/provider path is unchanged. Ordinary create/start
support for custom stores is unchanged. Snapshot creation allocates no child
secret scope and is not subject to this child-publication restriction.

Private copies use an operation-local qualified clone when available, otherwise
fixed-length, sparse streaming with independent destination verification.
The blocking worker retains source descriptors, writer fences, catalog access,
operation pins and staging through real completion even if its async waiter is
cancelled. File and directory durability precede catalog visibility. An uncertain
SQLite result preserves the owned candidate and its recorded operation identity
for exact reconciliation, not speculative rollback.

Checkpoints preserve credentials, guest keys, dirty journals and deleted-data
remnants exactly. They are not automatically generalized or safe public
templates. Prepare a separate private fork explicitly before publishing prepared
bytes. `fork_live` remains separately capability-gated.

### Live local forks

`Machine::fork_live(observation, LiveForkOptions)` admits the complete batch
before freezing the exact source run. The caller supplies a nonnil operation
UUID and ordered unique child names. The default maximum is 16, not a request
for sixteen children. A higher explicit maximum does not bypass resource
admission. Replaying an operation ID requires exactly the original inputs.

One authenticated operation-owned local cut supplies all children. RAM is not
published as a named checkpoint or copied once per child: every child maps the
same immutable inode privately. Writable disks remain independent qualified
private copies. Empty destination options inherit no forwards, publications,
network credentials, mount grants or secret scopes. Captured NIC presence and
execution/device identities are preserved.

`Runtime::inspect_fork(UUID)` and `Runtime::cancel_fork(UUID)` do not require the
source to exist. Results name every preselected machine/run identity, including
children never constructed, and report capture, source continuation and each
child independently. Wait expiry is not cancellation. Cancellation prevents new
submissions but does not stop a child that completed activation. Running is a
historical outcome; use ordinary machine observation for later liveness.

Fork and execution-restore calls record Running before joining each child's
independent durability barrier, and do not return with barriers still pending.
The returned child durability is `durable` after a successful barrier or remains
`constructed` on barrier failure; persistence failure does not stop a Running
child. Startup recovery adopts and completes barriers for constructed children
with live monitors or retained run leases. Adoption reconstructs the original
barrier's private-copy and launch-artifact inventory, excluding runtime lock
files and other unrelated machine-directory entries. It removes an incomplete
child only after ordinary run-liveness reconciliation proves that no live owner
remains.

Capture dispatch and the durable cancellation fence share the source machine
lock, so cancellation committed before dispatch also rejects capture retries.
Shared monitor preparation failures before child submission become construction
failure outcomes for the reserved children; normal reconciliation releases their
unused consumers, names and budget while source continuation settles independently.

After manager death, recovery reconciles exact submitted generations and
deterministically abandons never-submitted child slots. Unknown ownership keeps
its cut and resource charges until positive retirement. Child generation roots
and stable budget ownership survive source deletion and parent cancellation.

The original construction or activation failure is retained before destructive
failed-start cleanup. A reserved import cannot indefinitely block that child's
terminal result after its worker lease ends. Manager-death recovery releases an
unsubmitted child's name for cleanup only while owning the parent and consumer
exclusively, with no linked/submitted launch or active exact-generation holder.
The child outcome and resource charges remain pending until cleanup retires its
exact storage operations. A live detached worker therefore still blocks reuse
and abandonment.

The native source may retain the accepted RAM baseline after releasing capture
result ownership. Its exact run lease therefore keeps the cut and baseline
charge alive until that run ends; stopping only the last child is not sufficient
for collection while the source still maps the cut. Every child independently
retains its own generation roots and charges. Same-filesystem relocation keeps
one RAM inode; a qualified cross-filesystem publication charges both actual
source and final baseline inodes.

Capture, snapshot restore and live-fork batches share cross-home admission.
The entire batch reserves memory, disk construction peaks and manager-local
descriptor capacity before capture dispatch. Stable reservation ownership moves
to exact child generations atomically with their launch dependency closure.
Construction is parallel within that pre-admitted inventory, not subject to a
fixed concurrent-restore cap. Metadata readers use independent descriptors of
the authenticated immutable roles rather than rehashing RAM for every child.
Seal verification derives each writable disk's canonical stream map in the same
traversal that checks its evidence SHA-256; the fork loop that retained the cut
hands those held inodes and maps directly to its cut opening, and every child
copies from its own descriptor sharing that map. A cross-filesystem or
uncertain relocation authenticates the resulting inode again (SHA-256 plus map)
during retention; a restart or another process lacks the handoff and does the
same for every cut disk before any child uses it.

Seal verification (publication and local-cut retention) first admits every
role's geometry, hardlink, cross-role and writable-source alias bounds, then
authenticates in exactly two lanes: RAM on one extra thread with an explicit
1 MiB stack and 1 MiB read buffer, every other role in inventory order on the
caller. The capture reservation charges that 2 MiB delta on top of the general
16 MiB capture scratch before any effect; monitor staging verification uses
the same delta and never overlaps libvm's, which needs the sealed evidence. A
lane that fails or unwinds stops its sibling at the next read or role
boundary; both are joined before verification returns (a panicked RAM lane is
a typed error), so no lane outlives the caller's
descriptors, staging or lease. Results keep the evidence inventory order.
Restore consumer verification stays one serial lane: it precedes the restore
ledger reservation, so a second 8 MiB stream lane would be unadmitted.

### Execution restore

`silo restore <checkpoint> [--name CHILD]` accepts an `image:` reference or a
checkpoint alias and uses the same typed API locally and through the daemon.
Live restore first checks the selected host capability without initializing a
writable runtime. A leased verification consumer authenticates the complete
closure and locally recorded capture seal, holding each hashed stream and
non-map object inode; descriptor admission for exactly that set precedes the
first open. Restore and stopped-snapshot construction take fresh independent
descriptors bound to those held inodes by fingerprint instead of reopening and
rehashing them, then close the held set before resource reservation; the lease
keeps the closure pinned. State object digests are their whole-file SHA-256;
RAM still receives one whole-file SHA-256 pass for its evidence binding, and
private copies still verify their completed output. The exact selected monitor
executable then inspects inherited state/lower descriptors and the real host
profile before any child directory, private disk or network reservation is
created.

Raw roots and writable Data disks become isolated private copies. A streaming
copy from an authenticated closure or cut reuses that source map instead of
recomputing it, but still scans the completed output and compares its complete
map and length, rechecks source stability and syncs before publication; stopped
machine disks, which carry no map authority, are scanned while copying. Layered
EROFS lowers remain read-only VMDK devices with an explicitly retained fsmeta/pack
closure; the generated descriptor is moved into the child without changing its
inode. Source device IDs, order, format, access and geometry are preserved.
The pinned kernel, base initramfs and agent remain retained; a destination
composite initramfs is generated for provenance only, never loaded by restore.
No cold boot, replacement assets, filesystem repair or resize is a fallback.

The generation journal transaction pins every verification dependency before
retiring the consumer and retains the exact checkpoint/run/activation intent,
native inspection result, inspected executable digest and resource charges.
Destination network bindings and a fresh child public SSH CA are persisted
before submission. Source private CA material and external secret scopes are
not copied. An optional bounded activation hook is selected with
`RestoreOptions::activation_hook` or `--activation-hook` JSON containing
`argv`, `environment`, `workingDirectory` and `timeoutMs` (at most 30,000).
Stopped snapshots reject activation hooks rather than ignoring them.

Memory admission reserves the immutable RAM baseline once per device/inode and
private writes per child (25% by default), rounded up to the captured native
granule, plus a separate page-table/native-state allowance. Select a per-child
integer allowance from 0 through 100% with `RestoreOptions::resources` /
`PrivateWriteAllowance::try_from(percent)` or `--private-write-percent PERCENT`.
Zero explicitly reserves no private writes, not zero baseline or overhead.
`RestoreMemoryPolicy::AllowOvercommit` / `--memory-overcommit` explicitly opts
this restore into memory overcommit; the default is `Reserved` (no overcommit).
The exact allowance and memory policy are retained and validated in the journal
and shared ledger, including across reconciliation. Actual memory overcommit is
also reported in the manager log. Nondefault resource policies, like activation
hooks, require a live execution checkpoint.

Full private-copy/provenance disk peaks are reserved even when a clone may
succeed. Explicit memory overcommit never bypasses disk, descriptor, closure
authentication or compatibility checks. Memory and disk reservations are
serialized across runtime homes under one authenticated user's private
`/tmp/silo-restore-budget-<euid>` ledger (`/private/tmp` on macOS). This is not
cross-user or host-global authority. There is no fixed concurrent-restore limit,
and admission never implicitly overcommits. Charges survive caller loss.
Each ledger record is published by private staging, file fsync, atomic rename
and directory fsync, after its SQL owner is committed. Readers see only complete
old/new charges; abandoned `.atomic-write` staging is non-authoritative and is
reclaimed under the admission lock. Malformed authoritative records still
refuse admission. An interrupted construction-completion update conservatively
retains the old disk peak until the owning home reconciles its committed charge.
Construction disk peaks are released only after the exact run's durable Running
receipt; shared-baseline and private-write charges remain until existing
operation/lifecycle reconciliation proves holder and lease retirement.

`restorePrepared` is not success. The manager waits for `started` only after
fresh-generation acknowledgement, destination activation/thaw and final fence
release. Failure uses the existing exact-generation stop/reap and holder/lease
reconciliation, retaining uncertain ownership rather than launching again.
An execution-restore child cannot be cold-started with `silo start`; retry the
checkpoint with a fresh restore run. Inspection exposes `Restoring`, `Activating`
and `ActivationFailed` without declaring readiness.

After launch-request handoff, the restore manager waits for startup outside the
machine mutation lock, while retaining its lifetime lock and storage lease.
Normal stop can therefore signal the exact monitor during activation; final
storage retirement still waits for all owners, including a suspended manager,
to release their leases. Startup retains its original absolute deadline and
owns its acknowledgement pipe until completion or cancellation. Before readiness
or failed-start cleanup, the manager reacquires the mutation lock and
reauthenticates the published run; a concurrent stop or replacement run cannot be
overwritten by a late startup result.

Production restore remains lane-gated; public live lanes are unqualified.
Stopped layered snapshots preserve the exact fsmeta/pack graph, while live
capture/restore preserves its admitted read-only VMDK representation. Existing
state still requires an explicit user wipe. Phase 22's independent umoci
namespace observations matched actual readonly EROFS traversals for all six
published positives. Exact stable 7.2.2 and longterm 6.18.48 tuples passed
production boot/lifecycle and guest-mutated flatten export followed by raw boot.
Stopped portable artifacts and ownership return cycles passed independently.
Performance remains deferred to the mandatory Phase 24 sweep.


The initial stream hash of a private root describes its creation bytes only.
It does not certify current contents after writable execution or resizing.
Cached source streams are separately verified immutable files. Creation already
owns the exact complete next-boot tuple; stopped fork and snapshot capture retain
that closure without reselecting installed defaults. Capture does not change
source boot selection or claim the assets used by an earlier run. Captured
children launch from authenticated pinned objects even if source-private files
or installed defaults are replaced or removed; missing or incompatible pins
fail rather than selecting new defaults. Authenticated source descriptors remain
owned through qualification and checked kernel/composite generation; launch
never reopens a verified pool pathname to read its kernel, base initramfs or
agent. Each launch regenerates the composite bootstrap with the child's fresh
machine/run configuration, never copies the source composite. Capture retains
its independently admitted same-host Linux krun direct-boot profiles. General
raw/cloud boot support does not qualify EFI, macOS, translation or partitioned
roots for stopped/live capture.

Acknowledged catalog writes use SQLite WAL with synchronous `FULL` and
`fullfsync` enabled. Database identity checks use path metadata, never a raw
database/WAL/shared-memory descriptor. Writable pools retain a shared
`catalog.lock` guard; SQLite also owns it through native connection teardown,
including cancelled connection setup and asynchronous worker shutdown. A
reserved collation carries that ownership, and database-touching PRAGMAs run
only after it is installed. No-write planning retains exclusive catalog access
and uses ordinary SQLite read-only/query-only/no-create-main connections. SQLite
may coordinate its WAL/SHM files; their presence alone is not an error. Planning
does not delete sidecars, invoke writable application recovery, or fall back to
another reader mode. Native guard ownership survives connection teardown.
Driver/SQLite upgrades must requalify this ordering.
Machine publication and configuration updates acquire SQLite write admission
with `BEGIN IMMEDIATE` before reading cleanup dependencies. Concurrent fork
children therefore wait before taking a catalog snapshot instead of racing a
deferred read-to-write upgrade. VM construction itself remains concurrent.
Store and detached filesystem workers also own an explicit clone of the writable
catalog capability. Closing the SQL pool or cancelling the awaiting task does not
authorize a no-write opener while that worker can still mutate or clean up files.

Writable startup attempts cache recovery. Safely retained work blocked by an
active lease or explicit external dependency is reported as deferred cleanup;
those bytes and pending jobs remain intact without stranding private roots.
Corruption, unsafe publication state and failed durable recovery transactions
remain typed startup failures. Explicit image pruning reports dependency or
cleanup failures to its caller.

## Immutable Storage Primitives

`storage::identity::ObjectDigest` identifies exact byte objects;
`storage::identity::StreamId` identifies decoded logical streams. Both accept
only `sha256:` plus 64 lowercase hexadecimal characters, but are deliberately
different Rust types. A raw ext4 image is a stream, not a byte object.

`StreamHasher` reuses one 8 MiB buffer. It hashes every nonzero chunk in full,
including its zero regions and the shorter final chunk. Only an entirely zero
chunk becomes `zero`; holes and allocated zeros have the same identity. Stream
IDs hash `silo:stream:v1\n` followed by the exact RFC 8785 serialization of the
closed v1 stream schema. The writer emits sorted ASCII keys and validated
ASCII strings, with bounded exact integers, without a general-purpose JSON
canonicalization dependency or an intermediate whole-map JSON allocation.

`StoragePool::open` accepts the `images/` directory. Publication copies a
quiesced regular source into private staging, preserves logical zero tails,
verifies source metadata stability, synchronizes the read-only bytes, publishes
under a stable identity lock and synchronizes the containing directories.
Publication uses an atomic no-replace rename (`RENAME_NOREPLACE` on Linux,
`RENAME_EXCL` on macOS), with no replacing-rename fallback.
Existing same-ID content is verified rather than overwritten. Byte objects
live in `images/objects/sha256/`; streams live in `images/streams/sha256/`.
Managed directories are `0700`, staging files `0600`, and immutable bytes
`0400`. Publication does not itself commit a catalog retention root.
Catalog callers use `publish_stream_for_catalog` or `publish_object_for_catalog`
and keep the returned root guard through the SQLite retention commit. Copying
and full content verification happen before root coordination; final publication
rechecks the verified inode so concurrent pruning cannot create a dangling row.

`open_existing` and `verify_stream` support read-only reuse without creating
directories or lock files. Verification opens relative to the validated stream
directory and enforces immutable permissions, ownership, link count and exact
stream identity, not merely readable bytes at a pathname.

Registered operations hold their one shared generation lease before creating
`tmp/<operation-uuid>`. Disposable pool and OCI staging instead use
`tmp/stage-<uuid>` and the close-only publication lock
`locks/publication/stage-<uuid>.lock`; they never acquire canonical generation
leases or root published outputs. Recovery recognizes these two current roles
directly and streams directory entries outside roots coordination.
`scan_streams` discovers published files, including crash orphans, but never
deletes them: catalog reachability, external dependencies and the GC journal
decide deletion. `abandoned_temporary` returns only real directories whose
corresponding existing lock can be acquired exclusively without waiting. Each
candidate holds that lock through external-dependency preflight and optional
`remove`; dropping a candidate without removing it leaves bytes for a retry.

Root coordination and operation leases are explicit capabilities, not global
state. Lease duplicates retain the open-file-description lock until the final
descriptor closes; normal cleanup must never remove stable lock files. Database
file identity uses path metadata only, without opening or closing a SQLite file
descriptor. These are local storage building blocks, not snapshot or transport
APIs. See [ADR 0014](../../docs/adr/0014-layered-oci-image-storage.md) for the
normative identity, ownership and admission limits.

`storage::limits` separates v1 format bounds from host capacity. Its pure
`check_fd_budget` reserves 256 descriptors in addition to the `FLAT` records and
reports required, soft and hard limits on failure. It neither queries nor raises
process limits. The smaller laptop support envelope is not a format rejection;
actual host reservations and start-time limit adjustment are separate concerns.

## Lossless OCI Layer Artifacts

Fresh OCI ingestion and explicit OCI-to-raw conversion use the same bounded,
normalized changesets and ordered namespace composition. Layered creation
retains the exact payload packs, indexes, composition recipe/result and fsmeta;
there is no legacy tar applier, default full-ext4 renderer or flat OCI cache.
Explicit conversion authenticates that same retained graph and renders only its
merged namespace into a new opaque ext4 image. Conversion is not an implicit
fallback for a rejected root/backend profile.

Flat encoding preserves raw pathname, symlink and xattr bytes, shared-inode
hardlinks, source ownership/mode/mtime, directory/root metadata and admitted
special inode/device types. Linux POSIX ACL xattr values are converted to ext4's
on-disk ACL representation only at the filesystem codec boundary; capability and
other opaque xattr values remain byte-exact. Sparse payloads stream only stored
ranges, without reading or allocating their logical holes.

The requested flat size is a minimum, defaulting to 512 MiB. Checked geometry
accounts for unique live inode data, directory names, xattrs and the formatter's
inode/extent/GDT/bitmap/journal overhead; a real dense image may therefore produce
a lower larger than 2 GiB. Logical sparse-file length alone does not enlarge the
artifact. The complete image remains bounded to 1 TiB. The current conversion
identity is `flat-ext4-v3:erofs-composition:minimum-size=536870912`, so an earlier
development artifact is never reused under this conversion. There is no
old-state migration, cache repair, compatibility reader or automatic wipe.

`oci::changeset::ingest_layer` returns an owned `StagedChangeset` only after
independent transport size/digest checks, complete decoded `diff_id` verification,
bounded tar/PAX/GNU/sparse parsing and structural validation. It never extracts
onto the host filesystem. Local structural acceptance keeps hardlinks and parent
symlink traversal unresolved; `namespace::compose` validates them against the
ordered lower namespace. The same immutable layer can therefore succeed under
different parents, or fail a particular composition without invalidating the layer.

`storage::LayerStore` owns durable meaning:

* `publish` consumes staged bytes, reuses the existing `StreamHasher`/pool for the
  pack, and publishes canonical index and identity-record objects.
* One insert-or-verify catalog transaction retains the recipe, result and exact
  object dependencies. Different results cannot silently replace one recipe.
  `retain_occurrences` separately preserves positions and duplicates.
* `find_recipe` and `load` authenticate retained records, the complete pack stream
  and index closure without source blobs. They use `open_existing`, never creating
  missing directories or trusting catalog IDs without byte verification.
* `load` returns a `HeldLayer`; `compose` returns a `HeldNamespace`. Their
  metadata is accessible through `Deref`, but callers retain the owning value
  through the last payload read. Composition pins all ordered inputs under one
  operation lease, independent of layer/chunk count.
* `compose` consumes authenticated results in occurrence order and returns neutral
  inode/name/body-origin facts, not a host-extracted tree. Recipes, results and
  occurrence sets are subordinate cache facts: explicit prune retires them when
  neither a retained owner nor an active consumer needs their closure.

The [normative changeset ABI](../../docs/adr/0014-layered-oci-image-storage.md#changeset-byte-abi)
fixes exact JCS fields, domain-separated recipe/result IDs and deterministic
entry/sparse descriptor trees. The index root and regular-body sparse top lists
have at most 256 descriptors, with indirect nodes for larger valid indexes.
This is not a 256-page layer limit or a fixed per-file sparse-map cap.
OCI's `StreamIdentity` wire newtype has no byte-hashing constructor or implicit
object-digest conversion; libvm remains the stream identity implementation.
Applicable format limits have one authoritative OCI definition reused by libvm.
The representation-neutral xattr admission charge is not actual ext4/EROFS size;
resource preflight/allocation failures remain distinct from hard-format rejection.

Encoding/copying/hashing run outside SQL/root critical sections. After publishing
complete objects independently, `publish` rechecks every member under shared
roots before committing its catalog closure. Recovery may remove an uncommitted
member during the unlocked interval, forcing publication to fail rather than
register a partial layer. Its blocking worker retains root/lease capabilities
through registration and filesystem-bearing staged values through cleanup;
only plain facts cross to async SQL work. Catalog access survives actual cleanup,
including cancellation. Large composition and durability/removal are offloaded.

Object recovery scans bounded batches with a reverse dependency index. It checks
all persisted external resources, not just layer foreign keys, under exclusive
roots and SQL deletion authorization. Those protections survive a cancelled
caller until deletion finishes. A protected object defers its entire current
batch and stops the remaining startup recovery pass, including subsequent stream
cleanup; already completed independent batches may have been reclaimed.
Startup reports the known-safe dependency deferral; explicit prune reports the
dependency. Unsafe `0444` bytes fail immutable-path validation rather than being
treated as valid `0400` content corruption or silently sanitized.

Writable startup initializes empty pool coordination directories under its catalog
capability before recovery scans immutable objects. A current-schema catalog and
immutable-pool snapshot therefore need not copy `images/tmp`, `images/locks` or
private machine/operation state. This does not relax `load`/`find_recipe`:
read-side authentication never creates missing directories or bytes.

The [changeset conformance guide](../oci/testdata/changesets/README.md) describes
committed full-byte goldens, independent identities/oracle, real publication tests,
pinned containerd extraction and producer-original metadata evidence. Synthetic,
published-corpus and producer-original reports are separate. Pinned provenance for
six builders is not a claim of admission or equality for all six: rejection,
unavailable device/metadata extraction, root-policy differences and other
non-equality remain explicit evidence. These reports do not waive the later
default gate. The owner-approved source-profile exception admits an effective
entry named **exactly `/` only when it is a directory**, preserving its root
metadata and ordinal while storing the same explicit root form as `.`.
Both spellings in one layer still fail duplicate normalized-path validation.
The exception is not a broader absolute-path normalizer: non-directory `/`,
`//`, `/./`, absolute children such as `/nix/...`, and absolute hardlink targets
remain rejected. Qualification does not strip those paths or silently substitute
another producer archive. Retained reports from before this source-profile
correction remain historical evidence, not a current Kaniko admission verdict.

## Process Configuration

`ProcessConfig` is durable desired process configuration stored with the
machine. It preserves OCI `Entrypoint` and `Cmd` separately, including the
distinction between omitted and explicitly empty values, plus the environment,
working directory, and user selector. Configure it at creation with
`MachineBuilder::process`, or with the individual process builder methods, and
read it from `MachineData::process`.

The process configuration does not turn an ordinary `start` into a workload
launch. It lets higher-level callers retain and resolve their intended process
without reconstructing image metadata.

## Root Capacity Metrics

`Machine::metrics().await` retains the existing agent identity, observation
timestamps and freshness frame. For a verified managed overlay root,
`metrics.report.snapshot.root_storage` contains one writable upper's actual
accounting. `upper_backing_bytes` is the exact private-device length;
`upper_filesystem_bytes` is the observed ext4 span; their difference is the
explicit `unusable_tail_bytes`. Filesystem overhead is the span minus statvfs
usable bytes, not workload usage. Used plus free equals usable; available can
be lower than free because of reserved blocks. Total, free and available inode
counts expose inode exhaustion independently of byte exhaustion.

`shared_lower_logical_bytes` is the immutable lower's logical length, not its
physical host allocation. Neither it nor the maintenance mounts should be
added to root filesystem capacity. Maintenance lower/upper mounts are omitted
from the ordinary filesystem array to avoid counting the overlay's upper twice.

The nested `temporary_directory` samples the actual `/tmp` filesystem each time,
including image-owned changes after boot. Upper-backed `/tmp` shares root
capacity and persistence. Tmpfs reports separate capacity, non-persistence and
guest-memory charging. An unclassified image-owned mount reports `Other` with
unknown persistence/memory charging rather than inferring them from the boot
request. Malformed retained observations or inconsistent capacity arithmetic
fail metrics collection/relay instead of publishing invented values.

## Execution

The following examples operate on an already-running machine. None creates,
stops or removes it. Resolve by name or immutable ID:

```rust,no_run
use libvm::{MachineRef, Runtime};

# async fn example() -> Result<(), libvm::LibVmError> {
let runtime = Runtime::from_env().await?;
let machine = runtime.get_machine(&MachineRef::parse("devbox")?).await?;
let output = machine.exec("/usr/bin/printf", ["%s\n", "$HOME"]).await?;
assert_eq!(output.stdout_bytes(), b"$HOME\n");
# Ok(())
# }
```

`exec` sends explicit argv. It does not expand variables, pipelines, wildcards
or redirections. A nonzero guest exit is an `ExecutionResult`, not a transport
error; inspect `output.result()` as well as the returned Rust `Result`.

### Scripts are explicitly interpreted

```rust,no_run
# async fn example(machine: &libvm::Machine) -> Result<(), libvm::LibVmError> {
let output = machine
    .exec_script("printf '%s\\n' \"$HOME\" | /usr/bin/tr a-z A-Z")
    .await?;
println!("{}", String::from_utf8_lossy(output.stdout_bytes()));
# Ok(())
# }
```

`exec_script` is the existing `/bin/sh -l -c SCRIPT` convenience. Login startup
files may affect its environment and output. The script is executable code:
do not construct it by concatenating untrusted input. Prefer literal argv when
interpretation is unnecessary. The script wrapper preserves the existing argv
ordering, including builder arguments; it is not a new positional-argument API.

Collected `exec` and `exec_script` apply their `timeout` **after startup**.
`spawn` does not acquire a deadline from that option. Own your deadline around
streaming work and explicitly cancel or drop its session on timeout.

### Streaming execution owns its request lifetime

```rust,no_run
use libvm::{ExecutionEvent, ExecutionResult};

# async fn example(machine: &libvm::Machine) -> Result<(), Box<dyn std::error::Error>> {
let mut session = machine
    .spawn_with("/bin/cat", |options| options.stdin_pipe())
    .await?;
let mut received = Vec::new();
let result = loop {
    match session.recv().await?.ok_or("missing terminal result")? {
        ExecutionEvent::Started => {
            let input = session.stdin().ok_or("stdin unavailable after Started")?;
            input.write(b"streamed input\n".to_vec()).await?;
            input.close().await?;
        }
        ExecutionEvent::Stdout(bytes) => received.extend(bytes),
        ExecutionEvent::Stderr(bytes) | ExecutionEvent::TerminalOutput(bytes) => {
            eprintln!("{}", String::from_utf8_lossy(&bytes));
        }
        ExecutionEvent::Terminal(result) => break result,
        ExecutionEvent::Accepted => {}
    }
};
assert_eq!(received, b"streamed input\n");
assert_eq!(result, ExecutionResult::Exited { code: Some(0) });
# Ok(())
# }
```

Receive `Started` before obtaining stdin, writing, resizing or sending
process controls. `Accepted` only acknowledges host admission. Pipe stdin
supports explicit EOF; PTY input does not. Consume output through the terminal
result, which distinguishes exit, signal, launch failure and execution loss.

For large bidirectional transfers, receive events concurrently with input using
`session.control()` or `session.stdin()` after `Started`; otherwise both sides
can fill their bounded queues. A control handle does not keep a dropped session
alive. Terminal outcome, error, cancellation and drop invalidate surviving
handles. `session.close_requests()` closes the request side; continue receiving
if you need the terminal outcome. `session.cancel()` or dropping the session
also releases its response stream, so no further result can be received.
Neither operation is a reconnect API.

The CLI drains execution responses when sending pipe EOF races process exit.
A received terminal result remains authoritative; a closed request stream
alone is never evidence of successful execution.

```rust,no_run
# async fn example(machine: &libvm::Machine) -> Result<(), libvm::LibVmError> {
let mut session = machine.spawn("/bin/sleep", ["60"]).await?;
session.close_requests();
let outcome = session.wait().await?;
println!("{outcome:?}");
# Ok(())
# }
```

`wait()` consumes and discards subsequent output. `collect()` buffers it in
memory. Use `recv()` for bounded streaming or external sinks.

### Local SSH login

```rust,no_run
# async fn example(machine: &libvm::Machine) -> Result<(), libvm::LibVmError> {
let status = machine.shell().await?;
println!("login exited with {}", status.code);

let status = machine.shell_with(|options| {
    options.user("root")
        .term("xterm-256color")
        .cwd("/tmp")
        .env("EDITOR", "vi")
        .forward_agent(false)
}).await?;
println!("configured login exited with {}", status.code);
# Ok(())
# }
```

SSH needs the current Running/non-stopping VM generation, a reachable vsock-22
listener, an existing immutable host-key pin, a matching server key and accepted
user certificate. It does not call the guest identity/process RPC or require
fresh aggregate agent readiness. First provisioning and pin establishment
still need their normal flow; interactive login never trusts a first-use key.
Agent outage access requires an independent listener, such as systemd OpenSSH.
An agent-owned listener cannot survive its owner stopping. Listener ownership
remains first binder wins.

Without `attachment`, `shell` owns the local terminal for the call: safe
demand-driven stdin, raw-mode restoration, local resize and signal forwarding,
and the configured detach keys (default Ctrl+]). Local output is presented on
the terminal. Do not run concurrent local-terminal shells in one process.
`local_signals` lets an embedding runtime own process signal subscriptions.
SSH always allocates a guest PTY.

Without cwd/env, SSH requests a login shell. With cwd/env it preserves the
quoted exec-wrapper behavior; it does not depend on sshd `AcceptEnv`. Agent
forwarding is explicit and confined to this connection. A normal exit preserves
its code; the current signal-exit representation is code 128, and local detach
returns success. Transport loss, missing exit status and cancellation are errors.

### Supplied SSH attachment

```rust,no_run
use libvm::{SshShellAttachment, SshShellControl};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

# async fn example(machine: &libvm::Machine) -> Result<(), Box<dyn std::error::Error>> {
let cancellation = CancellationToken::new();
let (controls, receiver) = mpsc::channel(8);
let attachment = SshShellAttachment::new(
    std::io::Cursor::new(b"printf 'embedded:%s\\n' \"$USER\"; exit 7\n".to_vec()),
    tokio::io::stdout(),
    tokio::io::stderr(),
    37, 119,
).controls(receiver);
// Queue a resize. An embedding application's signal handler can instead send:
// SshShellControl::Signal(libvm::SshShellSignal::Term).
controls.send(SshShellControl::Resize { rows: 37, columns: 119 }).await?;
drop(controls);
let status = machine.shell_with(|options| {
    options.term("xterm-256color")
        .attachment(attachment)
        .cancellation(cancellation.clone())
}).await?;
assert_eq!(status.code, 7);
assert!(!cancellation.is_cancelled());
# Ok(())
# }
```

Supplied attachment owns its streams and consumes them exactly once. It never
queries host terminal dimensions, changes termios, subscribes to process signals
or intercepts detach bytes, including Ctrl+]. Both dimensions must be positive.
The example explicitly chooses host output writers; library code does not
implicitly select them. Service callers supply their own per-session writers.
Combining supplied attachment with `local_signals` or explicit `detach_keys`
is rejected before connecting. TERM belongs to the shell options, not the
attachment. A closed controls receiver disables controls, not the session.
The typed signal set is HUP, INT, QUIT, ILL, ABRT, FPE, KILL, USR1, SEGV,
USR2, PIPE, ALRM and TERM; resize is a separate control.

Input EOF sends SSH channel EOF once, then drains output and terminal status.
It is not a terminal Ctrl-D byte and need not exit an interactive shell: send a
finite command with `exit`, terminal EOF bytes when appropriate for your
protocol, or cancel. Cancellation is not clean input EOF. Stdout and SSH
extended stderr remain separate, although a guest PTY normally merges them.

Setup has one 30-second deadline. After remote EOF/status, a two-second
peer-message budget detects a missing close; delivering already-received
output does not consume that budget. Success drains output before returning.
Awaited completion performs bounded graceful teardown, then if necessary
cancels transport and waits for acknowledgement that the actual wire was
released. That acknowledgement has no wall-clock guarantee under a stalled
executor. Dropping the Rust future only requests cancellation; it cannot await
task joins. The caller's cancellation token is observed, never canceled by
libvm. A blocked caller sink must cooperate with cancellation in SDK adapters.

Run `cargo run -p libvm --example execution -- <vm> <mode>` with `exec`,
`script`, `spawn`, `shell` or `embedded-shell` for runnable versions. The
example preserves nonzero exit codes and never changes VM lifecycle.

### Execution architecture and extension points

```text
Machine conveniences
  exec / exec_script / spawn
    session.rs: RPC session owns events + one shared request control state
      VmExecutionService.Execute: machine/run fence, Accepted/Lost
        GuestProcessService.Execute: agent/boot fence, process lifecycle
  shell
    session/ssh.rs: pin + certificate, setup, one relay, one teardown owner
      VmAccessService.OpenSsh: opaque bytes and half-close
        guest vsock 22: independently selected SSH listener
    session/host.rs: optional local input/resize/signals/detach policy
      host_input.rs + utils::terminal: byte reader and raw-termios ownership
SDK adapters: bounded native byte/control pipes, cooperative caller I/O
CLI RPC terminal adapter: spawn events + CLI-owned input/terminal policy
```

New RPC controls belong in session/control ownership and the appropriate
host/guest protocol envelope. Common payloads do not erase distinct identity
fences. SSH features belong in the shared SSH client, not a second SDK client.
Local terminal policy belongs in the host adapter, not in the SSH transport or
caller-supplied streams. SSH must not emit agent execution events; wire DTOs
must not become a universal domain model. SDK adapters own cross-language
buffers and task lifetimes, not a second authentication/relay implementation.

This API cutover requires all consumers and native libraries to restart
together. It introduces no compatibility aliases, version bump, state reset or
database migration.

## Runtime Roots

A local runtime has two roots (see
[ADR 0017](../../docs/adr/0017-single-host-state-root.md)):

- The **home** holds all persistent state. It defaults to `~/.silo`;
  `SILO_HOME` overrides it and must be absolute. Pass an explicit home with
  `RuntimeConfig::local(home)` or `RuntimeBuilder::home(..)`, and read the
  resolved value back with `Runtime::local_home()`.
- The **run root** is always `/tmp/silo-<effective-uid>` (spelled canonically as
  `/private/tmp/silo-<effective-uid>` on macOS) and holds generated
  sockets, pidfiles, and locks. A fixed short root keeps Unix socket paths under
  the `sun_path` limit regardless of the home path. Its final directory must be
  a non-symlink directory owned by the effective user with exact mode `0700`.

Configuration is separate: `libvm::HostPaths` resolves the config directory
`${XDG_CONFIG_HOME:-~/.config}/silo`, with `<home>/config.yaml` as a fallback
config file read only when the XDG one is absent. No other XDG variable is
consulted.

`db_config` is a singleton row with `id = 1` that records only the host `os`,
`created_at`, and `modified_at`. No root path is stored in the database. The
derivation is:

| Path           | Derived from             |
| -------------- | ------------------------ |
| `state.db`     | `home/state.db`          |
| `machines/<id>/` | `home/machines/<id>` (launch config, disks, initramfs) |
| `keys/`        | `home/keys` (legacy TLS import inputs only) |
| `secrets.json` | `home/secrets.json`      |
| `images/`      | `home/images`            |
| machine logs and exit records | `home/logs/machines/<id>/` |
| private-network logs | `home/logs/machines/<id>/network/` |
| `locks/`       | `run_root/locks`         |
| `machines/<id>/vm.pid` | `run_root/machines/<id>/vm.pid` |
| `machines/<id>/vm.sock` | `run_root/machines/<id>/vm.sock` |
| `machines/<id>/vm.lock` | `run_root/machines/<id>/vm.lock` |
| `machines/<id>/<uds>` | enabled public vsock mux |
| `machines/<id>/<uds>_<port>` | extension-owned guest-to-host listener |
| `networks/`    | `run_root/networks`      |

### State Database Reset

This release has one new state and image-cache baseline and does not upgrade old
migrations or cache metadata. With every Silo process stopped, remove all local
Silo state from the previous release, including `state.db`, machine directories,
logs, and the image cache, before opening the new runtime. Silo does not adopt old
database, machine, runtime, or cache files.

## TLS Interception Trust

The first start with a TLS-terminating policy resolves a single CA pair under
`SecretScope::Home` in the runtime's `SecretStore`. The default store is
`<resolved-home>/secrets.json`; `Runtime::with_secret_store` selects the actual
store for both CA entries, including an external FileStore or custom filename.
The reserved names are `silo.tls_ca.certificate` and `silo.tls_ca.private_key`.
Non-intercepting starts do not create or import a TLS CA.

Resolution, validation and paired writes share one atomic scope transaction.
Partial, malformed, mismatched, expired or not-yet-valid material fails without
replacement. Each input contains exactly one PEM block. Certificates require
CA basic constraints; KeyUsage may be absent, but when present must allow
certificate signing. The same resolved certificate goes into guest trust and
the same pair reaches netd through its bounded `--secrets-fd` payload. Reserved
entries are never included in provider grants, and count toward the total
16 KiB transport limit. Only the public certificate enters the guest.

`NetdRuntimeConfig::with_tls_ca(cert, key)` supplies operator import inputs.
The first intercepting start imports them into the selected Home store;
repeated imports must equal the stored pair. Conflicts fail without changing
existing trust. CLI `networking.drivers.netd.tls_ca_cert` and `tls_ca_key` have
these same import semantics.

If no stored or operator pair exists, an intact legacy pair in
`<runtime-home>/keys/ca.pem` and `ca-key.pem` is validated and imported once.
The import is logged after persistence; legacy files are left untouched.
Fresh homes generate in memory and create no separate CA files. Machine
removal never deletes the Home CA. Rotation requires replacing the pair
atomically and restarting all affected guests/netd processes to install the
new trust snapshot.

The old exported `ensure_certificate_authority` and path-bearing
`CertificateAuthority` API are removed. Callers configure the runtime's store
or operator import instead. netd no longer accepts TLS CA file flags or session
file paths; TLS-terminating sessions validate their Static source before
opening listeners.

## Runtime Components

`Runtime::new` resolves `silo-vmm`, `netd`, `kernel-default`, `initramfs`,
and `agent` once, validates them as absolute paths, and retains that immutable
set for the runtime lifetime. `SILO_VMM_PATH`, or
`RuntimeConfig::with_supervisor_path` / `RuntimeBuilder::supervisor_path`,
replaces only the `silo-vmm` path. Opaque raw starts launch that absolute path;
qualified Linux overlay starts use the retained native executable FD described
above. For the krun backend,
silo-vmm re-executes itself with `argv[0]` set to `krun` to run libkrun in a
private worker, so there is no separate krun component to resolve (see
[silo-vmm architecture](../../docs/architecture/silo-vmm.md)).
Private networking launches the resolved absolute `netd` path directly.

`make build` and `make stage` package the standalone guest agent with
`llvm-objcopy --strip-debug` from the Rust toolchain's already-declared `llvm-tools`
component, resolved through the active compiler rather than PATH. Packaging
operates on the unpublished assets tree only.
The original Cargo binary under `target/<guest-target>/<profile>/silo-agent`
remains unmodified, retaining any DWARF emitted by the selected profile for
host-side debugging. The guest copy retains executable code, unwind data and its
symbol table. Both debug and release runtime payloads follow this rule.

This is a guest resource requirement, not a change to the selected RAM or root
profile. Before early init can free the supplied initrd, the kernel must unpack
the agent into its initial root. Managed overlay boot uses the kernel's initial
tmpfs default budget; embedding a large host debug ELF can exhaust it before
`silo/rootfs.json` is extracted. Removing non-runtime debug sections avoids that
footprint without weakening fail-closed bootstrap handling. The base initramfs,
kernel and native monitor bytes are not changed by this agent packaging step.

## Hybrid Vsock Paths

`Machine::vsock_socket()` returns the public host-to-guest mux path when
`VmSpec.vsock.enabled` is true. `Machine::vsock_listener_socket(port)` returns
the path an extension can bind for guest-to-host traffic. Both methods read the
current stored configuration, use the default `vsock.sock` filename or the
configured `uds`, and return `None` when vsock is omitted or disabled. Listener
paths also return `None` for Silo's reserved host port 1027.

Resolving an enabled path creates the owner-only machine runtime directory so an
extension can bind a listener before VM startup. The extension owns that
listener and must close it during shutdown. silo-vmm cleans up its mux and private
backend sockets, then libvm removes the complete machine runtime tree; extension
unlink attempts must therefore tolerate an already-removed path. See the
[hybrid vsock guide](../../docs/hybrid-vsock.md) for protocol examples, retries,
security, limits, and shutdown behavior.

Creation-time kernel, initramfs and agent selections are resolved together from
one installation and pinned before publication. Subsequent changes require the
explicit complete boot-assets update; launch does not repeat selection.
`libvm` performs component environment and controlled PATH resolution while
opening the runtime; launched helpers do not repeat discovery.

## Lifecycle States

`libvm` treats VM lifecycle mutations as lock-owned transactions. Commands
that change a VM, such as start, stop, update, and remove, serialize on the
machine lock. Observing commands, such as inspect and list, prefer returning the
last persisted state over blocking when another process owns the machine lock.

The persisted machine states mean:

- `stopped`: no live `silo-vmm` is associated with the VM.
- `starting`: a start transaction owns the VM and is waiting for the host-side
  `silo-vmm` startup handshake to finish.
- `running`: `silo-vmm` is alive and the host-side startup handshake succeeded.
- `stopping`: a stop signal was sent to `silo-vmm` and Silo is waiting for the
  monitor to exit.
- `error`: the VM is not usable until an explicit lifecycle command repairs or
  replaces the state.

Guest-agent readiness is not part of the host-side lifecycle lock. A VM can be
`running` while the CLI is still waiting for the guest agent to register.

See the generated Rust docs for the full method and field-level API.
