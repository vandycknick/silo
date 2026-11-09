# Changelog

## Unreleased

- Layered OCI storage is the Linux/libkrun default: shared immutable payload
  packs and EROFS metadata with a private ext4 upper per machine. Raw/qcow2
  import, explicit raw conversion, stopped snapshots, publication and handoff
  use the content-addressed storage model. See [ADR 0014](docs/adr/0014-layered-oci-image-storage.md).
- Live snapshots, restore, forks and incremental capture are delivered with
  exact-build production qualification for all five live operations (including
  pause) on `kvm-x86_64`, using libkrun `0d21bf7`. Other native lanes remain
  unqualified. See [ADR 0021](docs/adr/0021-live-snapshots-and-forks.md) and the
  [qualification record](docs/architecture/silo-vmm.md#qualification), including
  its retained suite failures and `.tmp/plan/evidence/phase-24/` evidence.
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
  is 2.21/2.14 s and 5.80/3.50 s. Evidence:
  `.tmp/plan/evidence/phase-24/batch4d-btrfs/` and
  `.tmp/plan/evidence/phase-24/batch4d-ext4/`. The
  [performance tracker](docs/architecture/live-operation-performance.md#batch-4d-final-live-budget-closeout-2026-11-09)
  records all raw/gated measurements, reused cohorts and allowances. Original
  ingest and large prepared-create targets missed and were revised in ADR 0014;
  those revisions are not passing qualification claims.
- Owner Phase 25 retains macOS/VZ (Phase 23), fork/Silo pushes, CI, foreign
  lanes (KVM arm64, HVF/macOS and GHCR), and disposition of the retiring Node/Go
  SDKs and retained `make clippy` SDK drift.
