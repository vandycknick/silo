# Changelog

## Unreleased

- Layered OCI storage is the Linux/libkrun default: shared immutable payload
  packs and EROFS metadata with a private ext4 upper per machine. Raw/qcow2
  import, explicit raw conversion, stopped snapshots, publication and handoff
  use the content-addressed storage model. See [ADR 0014](docs/adr/0014-layered-oci-image-storage.md).
- Live pause/resume, snapshots, restore, forks and incremental capture on
  libkrun (`kvm-x86_64`; libkrun `7b61232`). A live operation is available
  whenever the backend provides it. Checkpoint compatibility is a format
  contract: every captured record carries a magic and schema (`silo.live-state/1`)
  and restore refuses a checkpoint whose live-state schema or architecture
  differs. See [ADR 0021](docs/adr/0021-live-snapshots-and-forks.md).
- Corrected live capture, fork and restore admission: writable disk copies,
  including each fork child's private disks, are charged by allocated bytes
  rather than logical length. A plain capture reserves only scratch host RAM,
  not a resident guest-RAM baseline.
- Linux/KVM reclaims guest-reported free RAM from capture-tracked boot VMs
  and restored or forked private mappings without changing checkpoint files.
  `silo info` and daemon status report reclaim state and mapping-limit skips;
  macOS/HVF behavior is unchanged.
- Live snapshots refuse occupied names before pausing the guest. If a name
  is taken after admission, the checkpoint is retained without that alias
  and capture continuation completes; the CLI prints its checkpoint ID and
  exits nonzero. Reconciliation also settles sealed captures blocked by a
  conflicting name instead of retrying publication on every command.
- Catalog cleanup defers deletion rather than failing commands when another
  reader holds the WAL, and skips checkpoints when there is nothing to delete.
  Required durability boundaries retry nonblocking checkpoints on a dedicated
  connection without starving catalog writers. After five seconds they report
  a typed committed-but-durability-pending error that is safe to retry.
- Cross-home resource admission now reclaims charges from deleted or replaced
  Silo homes using versioned home anchors, preventing orphaned reservations
  from permanently consuming the same user's RAM and disk budget.
- Live checkpoints of machines created without `--vsock` (the default) now
  restore and fork. Restore required the public hybrid vsock surface instead
  of only the internal agent channel; each remaining launch mismatch now
  refuses with the item it names.
- Machine names made only of hex characters (`def`, `cafe`) resolve by name:
  references resolve exact ID, then exact name, then a unique ID prefix, and
  name availability checks exact names and IDs only.
- **Hard breaking release: fresh state required.** Existing `~/.silo` or other
  Silo home state is not migrated. The initial schema
  (`runtime/libvm/migrations/0001_initial.sql`) was edited in place, with no
  upgrade migrations. Opening a database with a mismatched initial-migration
  checksum or a recorded migration missing from this build closes the pool and refuses it with
  an incompatible-state error instructing the user to reinstall and explicitly
  wipe state. Silo never automatically deletes that state. Recreate the home
  explicitly after reinstalling, or select a new empty home with `SILO_HOME`;
  do not reuse the old state. See the [store open path](runtime/libvm/src/store/store.rs#L70-L89).
- Overlay boot admission requires Linux 6.6 or newer instead of an exact
  kernel/initramfs/monitor boot-tuple qualification; kernel configuration is
  checked by the kernel track's build-time gate.
- Performance: all eight live-budget gates pass on Btrfs and fresh ext4.
  Cold/warm gated capture is 1.09/1.09 s and 2.04/0.58 s respectively; fork4
  is 2.21/2.14 s and 5.80/3.50 s. The
  [performance tracker](docs/architecture/live-operation-performance.md)
  records all raw/gated measurements and allowances. Original ingest and large
  prepared-create targets missed and were revised in ADR 0014.
- Not in this release: macOS/VZ guests, KVM arm64 and HVF lanes, GHCR
  publication, and the retiring Node/Go SDKs.
