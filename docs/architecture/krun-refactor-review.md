# Krun integration review and simplification plan

## Scope and verdict

Reviewed the engine/worker/lifecycle changes from `0e727a6a` through `577338de`,
the adjacent daemon changes, and searched the runtime, specs, CLI, SDKs, netd,
packaging and scripts for older compatibility paths and historical tests.
This is a source review, not fresh native-HVF/Rosetta/release qualification.
The inventory below is the concrete debt found, not a proof that every possible
historical assumption in the repository has been identified.

**Keep the architecture; simplify the contracts.** Linking krun into vmm is
right. Running libkrun in a separate process is also right: its normal shutdown
can terminate the calling process. Removing that boundary would put supervisor
cleanup, exit metadata and services at risk. There is no reason to maintain a
second executable identity or a homemade command-line dispatcher.

Target shape:

```text
libvm -> vmm supervisor
           lifecycle, API, console, vsock and finalization
           |
           +-> vmm worker
                 inherited FD roles + one typed launch request
                 watchdog, native admission, synchronous krun engine
```

One owner reaps one worker. One VM object represents one launch attempt. Keep VZ
behind the existing backend boundary without pretending it has a child process.
Do not introduce a generic worker framework, transport plugin layer, event bus,
protocol negotiation, or a reusable/restartable libkrun VM abstraction.

## Changes made with this review

- `runtime/vmm/src/main.rs:91` and `krun_worker/mod.rs`: normal Clap `worker`
  subcommand. Removed the argv[0] disguise, magic marker, basename guards and
  their unit/integration tests. Worker dispatch still precedes runtime creation.
- `runtime/libvm/src/runtime/components.rs`: removed the obsolete executable
  environment-variable rejection and its dedicated test. An unused environment
  variable is simply not read.
- `runtime/vmm/src/virt/backend/krun/owner.rs:70`: launch the current executable
  with `worker`; removed environment scrubbing for the retired helper protocol.
- Updated the Rosetta qualification client, memory-report discovery and docs to
  use the same current invocation. No legacy invocation aliases were added.
- Removed test assertions about process-name tricks and parser diagnostic text.
  Kept real descriptor, framing, watchdog, cancellation and finalization tests.

The remaining sections are a prioritized backlog, not claims that the listed
code has already been deleted.

## Priority 1: remove historical-schema machinery

### VM-spec removed-field parser

`specs/vm-spec/src/lib.rs:94-210,475-619` is the largest clear offender.
`VmSpecVisitor`, `ParsedVsock`, `VsockVisitor`, `removed_paths`, recursive
`collect_removed_paths`, and `removed_fields_error` preserve knowledge of deleted
endpoint/plugin/lifecycle schemas just to give custom errors. Unknown unrelated
fields are ignored while specific historical ones receive elaborate treatment.
The tests around lines 1178 and 1336-1555 preserve this obsolete distinction,
including aggregation order, duplicate keys, nested paths, JSON and YAML cases.

**Replace with:** ordinary deserialization of the current shape, generic
`deny_unknown_fields` where configuration is strict, and one explicit current
validation path for mounts, forwarding and socket filenames. If validation must
happen during deserialization, use a small concrete raw struct plus conversion,
not a visitor that knows previous schemas. Keep duplicate/current-field and
semantic validation tests. Delete removed-field inventories and fixtures.

### Start-request compatibility and duplicated definitions

`runtime/vmm/src/start_request.rs:27,217,356` makes `startup_budget_ms` optional
and synthesizes a budget for older requests. The current writer in
`runtime/libvm/src/vmm/start_request.rs:25` always sends it. Both sides already
ship together. The reader also has `strict_reader_rejects_removed_host_reclaim_switch`
at line 407; that tests a retired setting, not current behavior.

**Replace with:** a required budget on the pipe. Construct a complete request
explicitly for foreground idle mode. Keep optional backend/Rosetta fields only
where absence has a current meaning. Remove the legacy-budget and retired-switch
tests; test actual budget bounds and the current writer/reader contract. Do not
add a version-negotiation layer. Consolidate the concrete wire definitions only
if that reduces duplication without introducing a broad new protocol framework.

### Inline network-policy tombstone

`app/cli/lib/machine_defaults.rs:44,302` still deserializes an inline `policy`
value solely to reject it as no longer supported.

**Replace with:** only the current network fields and normal unknown-field
handling. No remembered field, special rejection branch or migration message.

## Priority 2: delete historical tests, preserve current invariants

| Location | What to remove or rewrite |
| --- | --- |
| `app/cli/lib/commands/create.rs:739` | Remove assertions about deleted `--image`, `--start`, and `--initrd`; retain the current agent-option conflict test. |
| `app/cli/lib/commands/run.rs:676` | Remove deleted `--image` assertion; retain the detached/TTY conflict test. |
| `net/netd/internal/config/config_test.go:62,152` | Delete tests devoted to removed SSH/profile/audit flags. |
| `specs/agent-spec/src/lib.rs:621` | Delete the removed-forward-setting test. A generic unknown-field test is enough to cover the current strict schema. |
| `specs/agent-spec/src/lib.rs:569` | Test the current fixed Rosetta contract with generic invalid values; do not preserve a retired tag/path as a special case. |
| `runtime/libvm/src/machine/guest.rs:131` | Delete the test specifically requiring retired reclaim configuration to be silently discarded. Decide generic unknown-field policy separately. |
| `runtime/libvm/src/vmm/exit_status.rs:116-159` | Keep required identity and supervisor/worker identity tests. Remove the fabricated `futureField` compatibility promise and historical framing. `worker: None` is still valid for VZ/pre-spawn failures. |
| `app/cli/lib/system/docker.rs:225` | Test creation of the configured socket directory, not absence of a retired alias. Keep foreign-file preservation, expressed using an arbitrary unrelated file/symlink. |
| `app/cli/lib/boundary.rs` | Remove the empty transitional-file inventory. Prefer actual module visibility over substring policing of Rust source; do not retain a migration ratchet after migration has finished. |
| `runtime/libvm/src/vmm/mod.rs:195` | The actual test checks the current Rosetta contract; rename it without the obsolete label/assets narrative. |

Do not merely rename a historical rejection test and retain its old fixture.
Retain a test only when it expresses an invariant of the current product.

## Priority 3: remove persistent compatibility paths deliberately

These change handling of data on disk. Choose the current format and document
clean recreation or an explicit one-shot migration, rather than keeping fallback
readers indefinitely. Never silently reinterpret an old user disk as a new one.

| Location | Remaining compatibility behavior | Simplification |
| --- | --- | --- |
| `specs/vm-spec/src/lib.rs:321,367,779` | Named mount tags derive guest paths from host paths; absolute tags have a second interpretation. | Model host source, guest destination and backend tag explicitly. Keep only the current representation. Update creation and provisioning together. |
| `runtime/libvm/src/store/models/machine.rs:30` | Serde alias `instanceDir`. | Keep only the current field name; remove the alias. |
| `runtime/libvm/src/paths/machine.rs:19,68`; `runtime/libvm/src/runtime/core.rs:1155` | Retired `metadata.json` path and cleanup during current operations. | Remove the obsolete path API and historical-file cleanup from normal creation. |
| `runtime/oci/src/store.rs:94,1422-1508` | Private `Disk` source variant plus historical metadata/index fixtures. Current materialization writes registry sources. | Remove unused source variants. Test the current cache format; if old fixtures already equal that format, replace historical fixtures with current round trips rather than inventing migrations. |
| `specs/forward-spec/src/forward.rs:11` | `krun.vsock` remains reserved although the private transport is descriptor-based. | Reserve only actual runtime filenames. Update vm-spec/libvm tests and vsock docs together. |
| `runtime/libvm/src/runtime/components.rs:739` | Debian/RHEL-style native discovery paths despite archive-only Linux packaging. | Decide which layouts are actually supported. If only official packaging is in scope, delete unused layout constructors, search candidates and tests; keep explicit/portable/bundled layouts. |

`runtime/libvm/src/store/store.rs:137,417` and
`runtime/libvm/src/runtime/planning.rs:264` also preserve old-migration fixtures.
Do not remove schema-integrity checks indiscriminately: those protect current
SQLite state. Replace historical fixtures with tests for current schema mismatch,
corruption and read-only non-mutation. This is different from supporting old CLI
arguments.

## Architecture simplifications, independent of compatibility

1. **Represent lifecycle phases explicitly.**
   `runtime/vmm/src/virt/backend/krun/owner.rs:31,210` combines a
   `started/reaped/exit` snapshot with several independent booleans and deadlines.
   Reaped-but-draining is a real state, but combinations such as running with a
   final exit should not be representable. Use a small local enum for published
   phase and a concrete stopping state holding reason/deadline. Keep independent
   channel bookkeeping separate. Do not turn every flag into a new abstraction.

2. **Reduce duplicate launch representation and validation.**
   `runtime/vmm/src/krun_worker/protocol.rs:23` duplicates `KrunConfig` field by
   field. Rosetta is JSON encoded inside JSON, using the older standalone
   encoder in `virt/krun/src/rosetta.rs:97`. Configuration is validated before
   serialization, after decoding, and again in the engine. Prefer one concrete
   typed launch shape with a deliberately redacted Debug implementation. Validate
   wire bounds at decoding and native configuration at engine entry; retain
   caller-side checks only where they improve actionable configuration errors.
   Do not remove Rosetta provenance/digest checks as part of serialization cleanup.

3. **Trim dead API surface.**
   `virt/krun/src/engine.rs:20` accepts `protected_streams`, but every in-tree
   caller passes an empty slice. `runtime/vmm/src/virt/exit.rs:22` has an unused
   `OwnerClosed` force reason. `runtime/vmm/src/virt/backend/krun.rs:49` wraps
   just a mux in `RunningKrun`. Remove these unless a present caller needs them.
   Audit the broad `allow(dead_code)` on `virt` in main instead of adding more
   placeholder variants/hooks.

4. **Fix the dependency direction of terminal data.**
   `runtime/vmm/src/virt/exit.rs:3` imports `StartupStage` from the worker's wire
   protocol. Terminal domain data should not depend on a transport module.
   Put the concrete shared stage type in a small existing domain/exit module and
   let the private protocol use it. No new crate is needed for one enum.

5. **Keep finalization ownership obvious.**
   `runtime/vmm/src/main.rs:run`, `startup::PrimaryMachine` and `shutdown::run`
   distribute cleanup and terminal reporting across several paths. Preserve the
   retained primary machine through startup failure, but make one finalization
   path responsible for stop, forward/serial cleanup, terminal record and exit
   command. Preserve original errors while attempting every cleanup step. Do not
   replace explicit ownership with a generic asynchronous destructor framework.

6. **Do not treat the mock backend as native coverage.**
   `runtime/vmm/src/virt/backend/mock` is substantial older test infrastructure,
   exposed through a feature-gated backend and start-request scenario field.
   Inventory dependent tests before removal. Move pure state assertions to unit
   tests and runtime assertions to real-process/native tests. The new worker
   tests use actual processes and should remain that way.

## Complexity that is justified and should stay

- Exec FD allowlisting, role validation and CLOEXEC normalization protect actual
  descriptor ownership. Darwin pipe identities and Linux close-range handling
  are platform differences, not backward-compatibility adapters.
- The watchdog must work before launch decoding and while output is blocked.
- Bounded framing, diagnostic retention/redaction and independent output draining
  prevent hangs and leaks. They are not historical parser validation.
- Reaping, shutdown intent versus observed signals, and separate reaped/drained
  observations prevent false readiness and fabricated successful shutdowns.
- `_VM_STARTPIPE`, `_VM_SYNCPIPE`, `_VM_MACHINE_LOCK` and `_VM_MACHINE_LOG_DIR`
  are current libvm-to-supervisor inputs, unlike the retired helper variables.
- Rosetta's `CapturedCompatibilityV1` is an active experimental host ABI contract,
  not an old CLI shim. Removing it means removing or redesigning that feature.
- `COMPAT_NET_FEATURES` and its test in `virt/krun/src/engine.rs:46,524` describe
  live guest-visible device behavior. Rename them for the current virtio feature
  policy if helpful; do not silently change advertised features to erase a word.
- CLI convenience aliases such as `ls` are current UX, not evidence of migration
  scaffolding. Filesystem aliases in ownership tests test real symlink/FD safety.

## Delivery order and acceptance criteria

1. **This patch:** ordinary worker command, no process disguise, no retired-env
   handling, current process-discovery tests and docs.
2. **Historical-test cleanup:** remove the specific cases above while preserving
   current conflict, safety, identity and configuration tests.
3. **Schema cleanup:** replace the VM-spec visitors and start-budget fallback;
   update producer/consumer fixtures together. Use a uniform current-field policy.
4. **On-disk/layout cleanup:** decide clean-install/cache recreation boundaries,
   then delete aliases and unused layouts. Keep this separate from lifecycle work.
5. **Worker internals:** dead API removal, typed launch data and a small phase
   enum, each as an independently tested change.
6. **Native qualification:** close the existing documented power-off, signed
   macOS HVF/VZ/Rosetta, networking/vsock and release-artifact gaps. Green ordinary
   CI is not evidence that these ignored native gates passed.

For every deletion: remove the reader/branch, obsolete constant/type, historical
fixture, test and current documentation together. Do not add a test asserting the
removed spelling now fails. Test only the new contract and real ownership/error
paths. Avoid a permanent compatibility inventory in executable code.

## Validation of this patch

- `cargo fmt` and `make clippy` passed. Clippy still reports the pre-existing
  unused `status` argument in `app/cli/lib/system/supervisor.rs:701` on macOS.
- Worker integration suite: 8 passed, 2 explicitly ignored native tests.
- Worker protocol/FD unit tests: 7 passed.
- Runtime component resolution tests: 21 passed.
- Supervisor exit-command parsing test: passed; both supervisor and worker help
  were also exercised through the built executable.
- Memory-report Python unit tests: 6 passed.
- `git diff --check` passed. No new dependencies were added.

These changes are local and uncommitted. CI and native qualification have not
been rerun for this review patch.
