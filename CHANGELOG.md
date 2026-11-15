# Changelog

## Unreleased

- Document Phase 30's agent-ready latency gates, capacity-independent live
  operations, publication-trusted local restore with on-demand snapshot
  verification, explicit zero ranges and separately selected non-durable
  same-host fork. Performance budgets move to `make perf`; image init stays default.
- Incremental snapshot publication no longer rereads all RAM on owned reflink
  paths, so RAM identity cost follows changed chunks. The Phase 30 contract
  places local corruption detection in explicit verification, export or handoff;
  copy and existing-dedup verification remain.
- Monitor metrics use the same bounded inspection deadline as status, so
  `silo info` does not spend another 30 seconds querying an unresponsive VMM.
- System appliance activation waits for systemd boot completion, including
  degraded boots, before starting Docker instead of accepting an early bus probe.
- Stock image init now supports live pause, snapshot, restore and fork on
  supported libkrun hosts. Systemd, busybox and OpenRC run in a contained image
  cgroup namespace with delegated resource controls; exec, shell and SSH use a
  separate workload subtree. Escaped tasks refuse capture with
  `guest-containment-escaped` while the source stays running.
- Restore and fork rotate an existing non-empty `/etc/machine-id` and atomically
  replace `/run/silo/generation` with the child run ID before thaw. Images can
  watch that file to refresh cached identity after thaw; activation hooks must
  not call the frozen image init. Activation replaces image-managed network
  configuration, including DHCP state. Ordinary stop syncs guest filesystems
  before force-stopping an image-init VM.
- Resource admission ignores disk and descriptor charges whose producing
  process is gone (lease-backed charges), so a crashed restore, fork or import
  in an abandoned home no longer shrinks every other home's budget. Ledger
  anchors move to schema 2; running older builds concurrently is unsupported.
  Host tests use per-home ledgers instead of the user's real one.
- A live fork child cancelled before its launch reports `cancelled`, not
  `failed`. A resume refused for missing pause authority names the observed
  machine state.

- Guest bootstrap failures now print diagnostics, sync and power off for every
  root type. Explicit `silo.rescue=on-failure` and `silo.rescue=always` kernel
  arguments enable console rescue; exiting rescue powers off. Poweroff before
  first readiness is reported as a failed boot, with its reason and serial log
  path, rather than a normal stop.
- `silo set VM kernel-arg=ARG` appends repeatable direct-boot kernel arguments
  and `kernel-args=` clears user arguments on stopped VMs through normal host
  admission. `silo start --no-wait` skips guest readiness waiting so a serial
  rescue console can be attached immediately. Reserved kernel arguments return
  typed invalid-argument errors with their diagnostic through daemon management,
  rather than generic internal failures.
- Local CLI management keeps large native initialization, inspection and start
  futures off caller stacks, avoiding stack overflows during kernel-argument
  updates and subsequent starts.
- The lobby returns inside silod with the pure-Go `tsgate` gateway. Labels use
  `io.silo.lobby.*`, the capability key is `github.com/vandycknick/silo`, and state
  lives in `<Home>/lobby/` and `<Home>/tsgate/`. Lobby VMs use Machine-only policy
  secrets; metrics requires `vm.read` and the configured lobby tag. Tsgate log
  upload is disabled. Connections, SSH channels/authentication/inactivity and
  per-principal operations are bounded; audit uses fail-closed background group
  commits. The Go/Node SDKs and host-shutdown protection are removed; there is
  no migration from taild.
- Stopped restore and live-fork children can cold boot from their own disks after completed activation and holder reconciliation; the first admitted start retires their restore binding without deleting the independently retained checkpoint.
- Shared tracing setup keeps CLI diagnostics at warn by default, enables debug/trace with verbosity or `RUST_LOG`, and suspends stderr progress displays while writing logs; machine start timelines are debug-only diagnostics.
- PTY shell and exec sessions drain buffered final output and close promptly when their main process exits, without waiting for background jobs to release the terminal.
- Live snapshots and forks borrow an existing user pause without requiring `--preserve`, persist the resolved preserve policy, and no longer warn of uncertain acceptance after a definitive rejection.
- Guest agent status and metrics deadlines suspend during native pause and
  restart on resume without replacing the healthy stream. Delayed reconnect
  attempts no longer revoke an agent session restored by the resume handshake.
- Restore, fork and live capture no longer reserve or refuse host RAM. Lazy
  file-private RAM mappings use ordinary host virtual memory; private-write
  percentages, memory-overcommit flags and RAM policy/result fields are removed.
  Disk-peak, descriptor and fork-count limits and their cross-home ledger remain.
  The resource-only ledger uses a new namespace, so older builds' RAM-aware
  ledger documents cannot block admission in fresh homes.
- Live snapshots and live forks now prefer incremental RAM capture by default,
  including a restored child's first capture against its inherited checkpoint.
  Missing or invalidated baselines, topology changes and dirty crossover still
  select full capture automatically. Hosts without incremental capability use
  full capture, and `--capture-policy full` remains an explicit override.
- User-facing size errors use human-readable storage units. Resource refusals
  report required and available capacity plus the shortfall, including when
  rounded sizes would otherwise look equal.
- Layered OCI storage is the Linux/libkrun default: shared immutable payload
  packs and EROFS metadata with a private ext4 upper per machine. Raw/qcow2
  import, explicit raw conversion, stopped snapshots, publication and handoff
  use the content-addressed storage model. See [ADR 0014](docs/adr/0014-layered-oci-image-storage.md).
- Live pause/resume, snapshots, restore, forks and incremental capture on
  libkrun (`kvm-x86_64`; libkrun `662b359c`). A live operation is available
  whenever the backend provides it. Checkpoint compatibility is a format
  contract: every captured record carries a magic and schema (`silo.live-state/1`)
  and restore refuses a checkpoint whose live-state schema or architecture
  differs. See [ADR 0021](docs/adr/0021-live-snapshots-and-forks.md).
- Corrected live capture, fork and restore admission: writable disk copies,
  including each fork child's private disks, are charged by allocated bytes
  rather than logical length.
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
- Paused RAM capture reads guest memory in 32 MiB packs and hands non-zero
  data to two hashing and writing workers, with output bytes and checkpoint
  identities unchanged. On a 30 GiB guest with 8 GiB of dense data the pause
  drops from about 16 s to about 9.5 s.
- Cross-home resource admission now reclaims charges from deleted or replaced
  Silo homes using versioned home anchors, preventing orphaned reservations
  from permanently consuming the same user's disk and descriptor budget.
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
