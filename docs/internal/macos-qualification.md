# macOS qualification record

Evidence record for the macOS arm64 work that follows the ADR 0014, 0021 and
0023 merge (`47020161`). Every claim here comes from a run on the Mac named in
M0; Linux evidence does not qualify a macOS lane. Raw command logs are kept
outside the repository (`.tmp/macos-evidence/`); this file quotes the parts
that matter.

## M0. Environment and baseline

Recorded 2026-11-23 at `470201611d47` (`main`, merge of PR #19).

### Host

| Fact | Value | Command |
|---|---|---|
| macOS | 26.7.1 (25G241) | `sw_vers` |
| Chip | Apple M5, 10 cores, 24 GiB | `sysctl -n machdep.cpu.brand_string hw.ncpu hw.memsize` |
| Architecture | arm64 | `uname -m` |
| Hypervisor | `kern.hv_support` = 1 | `sysctl -n kern.hv_support` |
| Xcode | not installed (`xcodebuild` absent) | `xcodebuild -version` |
| Command line tools | 27.0.0.0.1, SDKs 26, 26.5, 27.0 | `pkgutil --pkg-info=com.apple.pkg.CLTools_Executables` |
| Checkout volume | APFS, 286 GiB free on `/System/Volumes/Data` | `df -h`, `diskutil info` |
| Dev shell | flake `default` via direnv (`use flake`); nix `apple-sdk-14.4`, `MACOSX_DEPLOYMENT_TARGET=14.0` | `env` |

Tools in the default dev shell: nix 2.35.1, cargo and rustc 1.96.1,
cargo-nextest 0.9.138, uv 0.11.25, go 1.26.4, GNU make 4.4.1, git 2.54.0,
oras 1.3.0, gh 2.103.3.

### First failures

CI on the merge commit failed before any test ran, on every arm64 lane:

- `Test` / `Core (macos)` and `Core (linux-arm64)`, step `Run Clippy`: the
  pinned libkrun fork (`065326aa`) does not compile for aarch64.
  `src/devices/src/legacy/aarch64/serial.rs:100` declares
  `Result<(), utils::state::Error>` against the module's one-parameter
  `Result<T>` alias (E0107, then E0308 and E0277 at `:102`, `:105`, `:114`).
  Fixed in the fork by `fix(aarch64): use std Result for PL011 state
  preflight` on branch `silo/v2-aarch64-fix`; awaiting publication and re-pin.
- With the fork fixed (temporary `--config patch` to a local checkout, not
  committed), `silo-rprobe-vz-harness` failed to compile on macOS (35 errors):
  the harness compiles `krun/` through `#[path]`, and `krun/worker` now needs
  `crate::virt::lifecycle`, `crate::restore::inputs` and `crate::guest`.
- `Kernel` / `stable ubuntu-26.04-arm`, step `Build OCI kernel artifact`:
  `configs/arm64.config requests CONFIG_ARM64_PAGE_SHIFT=12, resolved value is
  n`. Linux 7.2.11 has no `ARM64_PAGE_SHIFT`; the page shift is the generic
  `PAGE_SHIFT`. The fragment now requests `CONFIG_PAGE_SHIFT=12`.

### Guest kernel

| Source | Version | VMGENID | EROFS | Overlay |
|---|---|---|---|---|
| Published `ghcr.io/vandycknick/silo/kernel:stable` arm64 (revision `5f7ee8ea`, 2026-10-18) | 7.2.11 | absent | absent | `y` |
| Previously cached `target/*/assets/kernel-default` | 7.1.3 | absent | absent | `y` |

Neither kernel carries the configuration this work needs, so a local arm64
build is required until the `Kernel` workflow publishes again. `make kernel`
refuses on macOS; the build runs in an Arch Linux ARM guest started with the
pre-merge Silo release build (copied to `.tmp/old-silo/`):

```
.tmp/old-silo/silo create ghcr.io/vandycknick/archlinux:latest --name kbuild \
  --cpus 8 --memory 12gb --disk-size 80gb \
  --mount /Users/nickvd/Projects/silo:/Users/nickvd/Projects/silo:rw --provision-user
.tmp/old-silo/silo start kbuild
.tmp/old-silo/silo exec -u root kbuild -- pacman -Syu --noconfirm --needed \
  base-devel bc bison flex cpio curl git jq perl pkgconf xz gawk libelf openssl ccache diffutils findutils
.tmp/old-silo/silo exec kbuild -e HOME=/home/nickvd --workdir /Users/nickvd/Projects/silo -- \
  make -C resources/kernels kernel-image TRACK=stable TARGET_ROOT=/home/nickvd/silo-target \
  KERNEL_IMAGE_OUTPUT=/Users/nickvd/Projects/silo/.tmp/kernels/kernel-stable-arm64
```

The guest toolchain is Arch Linux ARM GCC 16.1.1, not the CI Nix toolchain, so
this kernel is a development artifact; the published kernel comes from CI.

Result (`.tmp/macos-evidence/m0-kernel-stable-arm64.log`): exit 0, 473 s.

| Fact | Value |
|---|---|
| `file` | Linux kernel ARM64 boot executable Image, little-endian, 4K pages |
| Version string | `Linux version 7.2.11 (silo@silo) (gcc (GCC) 16.1.1 20260430, GNU ld (GNU Binutils) 2.46.0)` |
| Resolved config | `CONFIG_VIRTIO_SILO_VMGENID=y`, `CONFIG_VMGENID=y`, `CONFIG_EROFS_FS=y`, `CONFIG_EROFS_FS_XATTR=y`, `CONFIG_OVERLAY_FS=y`, `CONFIG_ARM64_4K_PAGES=y`, `CONFIG_PAGE_SHIFT=12` |

The workflow's own build step was then reproduced in the same guest with
`oras` 1.3.0 (checksum-verified upstream release) installed:

| Command | Result |
|---|---|
| `make -C resources/kernels kernel TRACK=stable` | exit 0, `Created OCI kernel artifact …/kernels/stable/arm64:7.2.11` |
| `make -C resources/kernels test-kernel-resources` | exit 0 |
| `make -C resources/kernels kernel-config TRACK=longterm` | exit 0 (strict validation, 6.18.57) |
| `make -C resources/kernels kernel-config TRACK=longterm5` | exit 0, best effort as designed: `PAGE_SHIFT` (5.15 still has only `ARM64_PAGE_SHIFT`) joins the already unresolvable VMGENID, BPF_JIT, SELinux, legacy iptables and `PREEMPT_LAZY` requests in the raw-only warning |

Kconfig sources in the guest cache: `config PAGE_SHIFT` lives in
`arch/Kconfig` on 7.2.11 and 6.18.57; 5.15.223 has only
`config ARM64_PAGE_SHIFT` in `arch/arm64/Kconfig`.

## M1. Compile, lint and host tests

Until the fork fix is published and re-pinned, every M1 run builds against the
local fork checkout through a throwaway `.cargo/config.toml` `[patch]` that is
removed afterwards; `Cargo.lock` is restored after each run and never
committed. Commands are the `make clippy` and `make test` cargo invocations
for `darwin-arm64` (workspace minus `agent`, `init`, `rprobe`, `silo-portd`;
features `silo-vmm/mock-backend,forward-spec/tokio,disk-image/qcow2`).

### Results (2026-11-23, fork commit `ddc3464c` through the temporary patch)

| Run | Result |
|---|---|
| `make clippy` cargo invocation (`.tmp/macos-evidence/m1-clippy-11.log`) | exit 0; no Silo warnings (the remaining dead-code warnings come from the local libkrun path dependency, which a git dependency caps) |
| `make test` (`.tmp/macos-evidence/m1-make-test-2.log`) | 3512 run: 3511 passed, 1 failed (the environment-dependent `daemon_run` test below), 3 skipped |
| `cargo nextest run -p rprobe --lib --no-default-features`, same for `init` | 20 and 49 passed |
| `go test ./...` in `net/netd` and `app/tsgate`; `go vet ./...` in both | all pass after the `sshdoor` socket-path fix |
| `silo-vmm capabilities --backend krun --json` | `lane: hvf-arm64`, pause `supported`, capture, restore, fork and incremental `build-excluded` |

M1's acceptance also needs the `macos` CI job green, which waits for the fork
fix to be published and re-pinned (`Cargo.toml` still pins `065326aa`).

### Compile fixes

| Failure on macOS | Fix |
|---|---|
| `silo-rprobe-vz-harness` compiles `krun/` by `#[path]` and lacked the modules `krun/worker` now needs | Harness includes `virt/lifecycle.rs` and `restore/inputs.rs`; `krun/worker/restore.rs` takes the agent port from `protocol::DEFAULT_GUEST_CONTROL_PORT` instead of `crate::guest` |
| The harness test build also compiled every `krun/` test against its partial module tree | Production shims are `not(test)`; the harness test build covers only its `Args` (moved to `mod args`). The `krun/` tests still run once, in `silo-vmm` |
| `statvfs` block counts are `u32` on Darwin (`fsblkcnt_t`) | `u64::from(blocks_available())` at every product site, as `app/cli/lib/daemon/upgrade.rs` already did |
| `tsgate` `SocketPair` used `SOCK_CLOEXEC`, which Darwin lacks | Per-OS helper; Darwin sets `FD_CLOEXEC` under `syscall.ForkLock`, the standard library's own fallback |
| Test-only: unqualified `pipe()`, Linux-only imports, same-type casts, dead-code under macOS cfg | Qualified call, cfg-gated imports, per-OS `l_type`, scoped `expect(dead_code)` |

### Runtime defects found by the host suite

- **Every krun start failed** (plan 3.5 confirmed):
  `target/debug/silo-vmm capabilities --backend krun --json` printed
  `Error: required host capability checks were not evaluated`. Two causes:
  the HVF macOS floor was never evaluated, and libkrun's machine-less HVF
  query cannot observe VM admission or the actual GIC model (both need a VM).
  Fix, chosen by the owner: the floor is the real `kern.osproductversion`
  major against 26; host-scope HVF admission uses the machine-less facts only
  (framework loaded and `kern.hv_support` for the hypervisor, the six
  `hv_gic_*` state symbols for the lane). VM admission and the GIC model stay
  with the held arm64 live-operations work.
- **Spawns stalled for minutes**: the macOS pre-exec CLOEXEC sweep in
  `libvm` `install_child_inheritance` and `silo-vmm` `configure_reexec`
  issued one `fcntl` per number below `RLIMIT_NOFILE`. nextest raises the soft
  limit to the hard one (unlimited, clamped to `i32::MAX`), so every mock VM
  start in the host suite timed out. Both sites now share
  `utils::process::CloexecTable`, which lists the actual table with
  `proc_pidinfo(PROC_PIDLISTFDS)` into storage reserved before the fork.
- **Lobby keep-alive**: Darwin's `shutdown(2)` returns `ENOTCONN` once the peer
  has fully closed (Linux returns success); hyper's half-close turned that into
  a connection error. `TimedIo::poll_shutdown` treats it as already closed.
- **Hibernate memory estimate** (plan 3.6, done here rather than in M3
  because the mock hibernation tests exercise it): the paused worker's
  estimate read `/proc/<pid>/smaps_rollup` unconditionally, so every mock
  hibernation failed with `memory-estimate-failed … No such file or
  directory`. `populated_memory_estimate` keeps the Linux read and uses
  `proc_pid_rusage(RUSAGE_INFO_V4).ri_phys_footprint` on Darwin. Real HVF
  hibernation stays unreachable because capture is `build-excluded`.

### Filesystem facts that changed tests (not product code)

| Fact, measured on this Mac | Test change |
|---|---|
| APFS materializes zero ranges below roughly 16 MiB instead of leaving holes (4 KiB at offset 4096 then `ftruncate` to 8 or 16 MiB allocates the whole file; 32 MiB and up stays sparse) | `sparse_sink_skips_zero_blocks…` uses 64 MiB so the trailing run is a hole on both systems |
| Darwin reports the kernel-owned `FWASWRITTEN` bit (`0x10000`) in `F_GETFL` once a descriptor has written | `direct_copy_*` tests compare status flags with that bit masked; `F_NOCACHE` (`0x40000`) is still checked |
| The macOS temp dir is under the `/var -> /private/var` link, and the lobby document store refuses symlinked ancestors; it is also too long for `run/machines/<id>/vm.sock` within Darwin's 104-byte `sun_path` | The lobby fixture uses the canonical `/tmp` (`/private/tmp`), the daemon pause/hibernate route test uses `/tmp` as other libvm socket tests already do, and the `tsgate` layout test uses the canonical temp dir |
| Each test that copies the 117 MiB mock monitor creates a new executable inode, and macOS policy-scans its first exec (0.89 s alone for `silo-vmm capabilities`, 0.01 s after); parallel copies pushed the five-second capability query past its deadline | `test_utils::install_mock_vmm` copies and executes once, as `mock_vmm_binary` already did for the shared binary; used by every fixture that launches a copy |
| Accepted sockets inherit the listener's `O_NONBLOCK` on BSD, not on Linux | The OCI pull test's registry stub makes accepted sockets blocking |
| APFS fills small holes, so allocation-growth and sparse-copy tests saw full allocation | The live staging fixture source and the live harness root are 64 MiB; the staging sparse-copy test uses 8 chunks |
| The live harness polled "settled" on a terminal source continuation, but the source resumes before staged state seals; slower runs observed `InProgress` | `capture_settled` also waits for a final outcome |

### Tests gated or changed for macOS

| Test | Change | Reason |
|---|---|---|
| `machine::stopped::tests::restore_without_memory_turns_a_memory_snapshot_into_a_stopped_machine` | Linux only | Needs a memory snapshot (live capture) and boot capture, which `boot_assets::validate_captured_boot_lane` admits only on the Linux krun lane |
| `store::capture::tests::fork_owned_receipt_rejects_foreign_binding_replacement_and_surviving_writer` | `writer` fault Linux only, other six faults run | Darwin has no read lease, so `identity_file::reject_surviving_writer` cannot see a surviving writer; owned cuts come only from live capture, which HVF withholds. **Open item for the arm64 live plan.** |
| `runtime::core::tests::rosetta_eligibility_fails_before_launch_asset_completion` | Asserts the nested-virtualization refusal | The default-agent requirement it asserted was removed on this branch; the macOS-only test had never run |
| `cli::api::tests::snapshot_names_restore_machines_and_are_refused_as_creation_images` | Linux only | Takes a stopped snapshot, which `validate_captured_boot_lane` refuses off the Linux krun lane. Revisit in M2 with stopped snapshots on APFS |
| `store::storage::tests::layered_restart_survives_child_snapshot_prune_and_missing_invalid_baseline` | Takes the fixture's pinned platform with its binding | The fixture record pins an x86_64 bundle; on an arm64 host only the binding was copied, an invalid profile |
| `rprobe_vz_harness` `Args` tests | Moved to `mod args` | See compile fixes |

### Environment-dependent failure

`cli::daemon_run::lobby_failure_is_isolated_from_core_for_explicit_and_persisted_features`
fails on this Mac while the owner's launchd job `sh.silo.daemon` is loaded:
launchd labels are per user, so `silo daemon up --foreground` in the test's
temporary `HOME` finds the real daemon and reports `the running daemon has no
readable service definition`. Not reproducible on a CI runner; left as is.
