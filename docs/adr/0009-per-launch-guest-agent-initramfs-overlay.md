# 9. Per-Launch Guest Agent Initramfs Overlay

Date: 2026-07-11

## Status

Proposed

## The Problem

Silo needs its guest agent before ordinary guest services exist. The agent must
receive machine, network, mount, user, SSH, and provisioning decisions before
the guest has networking, before the target init system runs, and before any
ordinary service can fetch or interpret that state. A host-to-guest
configuration service would itself need a working early guest transport and
startup protocol. That is the dependency we need to avoid.

Those decisions are also specific to one launch. A reusable image cannot safely
contain a later machine's users, keys, mounts, network configuration, or
provisioning intent. Putting them in a shared boot asset would make one launch
able to affect another, and would force us to rebuild the asset for every
machine.

The agent evolves independently from the reusable initramfs. Baking it into the
base initramfs couples every agent release to a base rebuild. Publishing
agent-bearing and agent-free bases would duplicate artifacts and invite drift.
We need one reusable early-userspace image, one compatible standalone agent,
and a small launch-specific delivery mechanism.

This ADR owns pre-boot materialization and handoff to the agent. [ADR
0008](0008-vmmon-host-and-guest-http-api.md) owns everything after that handoff:
post-boot discovery, readiness, status, metrics, and control.

## Where Reusable And Per-Launch State Meet

We distribute a Silo asset bundle containing a kernel, a reusable base
initramfs, and a standalone agent binary. The base contains `silo-init`, but no
`/agent` payload. The agent is selected with that base as one compatible bundle,
not as an independently discovered neighboring file.

At launch, `libvm` resolves every machine decision, builds a complete typed
`AgentConfig`, and serializes it once. It combines that JSON and the selected
agent with the base initramfs. The result is a machine-scoped composite boot
artifact. It is derived state for this start, not a new reusable asset.

The agent and its configuration first appear in the early root under `/agent`.
`silo-init` validates them and copies them into the early `/run` mount. This ADR
ends with the prepared `/run/agent` payload. Preserving that mount across root
replacement, calling `switch_root`, starting the agent, and selecting or
starting a target init belong to a later handoff decision. ADR 0008 begins when
that later boot path has made the post-boot agent service available.

## A Typical Managed Boot

Consider one managed VM start.

1. `libvm` resolves one compatible Silo asset bundle. It resolves an explicit
   custom initramfs, when configured, only as a replacement for the base member.
   The agent still comes from the selected Silo bundle.
2. `libvm` resolves the final machine, network, mount, user, SSH, and
   provisioning inputs. Only after those decisions are complete does it build
   the typed `AgentConfig` and serialize one UTF-8 JSON document.
3. `libvm` copies the selected base bytes unchanged into a temporary composite
   file, appends a launch-specific archive containing the agent and that exact
   JSON, closes it, and atomically renames it into the managed machine path.
   It writes the resulting path into the generated launch specification and
   starts `vmmon` only once every generated input is complete.
4. Linux expands the base and appended archive members into the same early root.
   The base supplies `/init`; the appended member supplies `/agent/silo-agent`
   and `/agent/config.json`.
5. After mounting the target root, `silo-init` verifies both payloads and copies
   them into its early `/run` tmpfs. The persistent guest root receives neither
   file.
6. The overlay flow reaches its boundary with `/run/agent/silo-agent` and
   `/run/agent/config.json` prepared. The later handoff decision owns preserving
   `/run`, replacing the root, and starting processes.

The useful guarantees follow directly: the managed agent payload exists before
ordinary guest services; configuration is fixed for one boot; no guest network
or configuration server is required; and a malformed partial payload cannot
look like successful payload preparation.

## Determination

Silo distributes one reusable base initramfs and one standalone guest-agent
binary as members of one compatible Silo asset bundle. For every
`libvm`-managed launch, `libvm` appends an uncompressed raw `newc` CPIO overlay
to the resolved base initramfs. The overlay contains the agent binary and the
newly generated configuration.

The base contains `silo-init` but does not contain `/agent`,
`/agent/silo-agent`, or `/agent/config.json`. Asset production emits one base
initramfs and the standalone agent, never a second variant with the agent
embedded.

## Why An Appended Archive Works

An initramfs is a buffer, not necessarily one archive. Linux accepts a sequence
of compressed or uncompressed `newc` CPIO members, with optional NUL padding
between members, and expands them in order into one early root filesystem. We
can therefore preserve the reusable compressed base exactly and append a small,
uncompressed archive for this launch. There is no reason to unpack or
recompress the base.

The completed buffer is exactly:

```text
+-------------------------------+
| reusable gzip newc base       |
+-------------------------------+
| zero padding to 4-byte align  |
+-------------------------------+
| raw newc overlay              |
|                               |
| agent/                        |
| agent/silo-agent              |
| agent/config.json             |
| TRAILER!!!                    |
+-------------------------------+
```

`libvm` copies the base without decoding or modifying it, writes enough NUL
bytes to align the first overlay CPIO header to four bytes, then writes one raw
`newc` archive. The overlay owns an independent `TRAILER!!!` entry, so it has
no inode or hard-link dependence on the base archive. Linux expands both
members into the same early root, making `agent/config.json` available as
`/agent/config.json`.

## Asset And Archive Contract

### Asset Bundle

At minimum, one Silo guest asset bundle is:

```text
assets/
  kernel-default
  initramfs
  agent
```

`initramfs` is the reusable compressed base archive. `agent` is the standalone
Silo agent executable; its asset filename is not its guest path. The overlay
writes it as `agent/silo-agent`.

Managed resolution treats `initramfs` and `agent` as members of one bundle. It
must not select an initramfs from one fallback asset directory and an agent from
another. That preserves compatibility between the distributed `silo-init` and
agent releases.

An explicit machine initramfs overrides only the base initramfs member. `libvm`
still appends the same managed overlay using the agent from the selected Silo
bundle. The custom base must provide an `/init` that honors this ADR's guest
payload preparation contract. Root replacement and process startup are a
separate decision.

### Overlay Contents

The overlay contains exactly these entries before its independent trailer:

| Archive path | Type | Owner | Mode | Contents |
| --- | --- | --- | --- | --- |
| `agent` | Directory | `0:0` | `0755` | Empty |
| `agent/silo-agent` | Regular file | `0:0` | `0755` | Resolved agent executable |
| `agent/config.json` | Regular file | `0:0` | `0600` | Serialized `AgentConfig` |

Archive names are relative. Entries must never contain a leading slash, `.` or
`..` components, or platform path separators. The writer uses deterministic
entry attributes where the format permits it: modification times are zero,
inode numbers are local to the overlay, directory link counts are valid, and
nondirectory entries use one link. Both payload sizes must fit the unsigned
32-bit `newc` size field.

`libvm` writes the archive directly in process. Launch must not depend on host
`cpio`, `gzip`, a shell, or another external archive utility.

## Responsibilities And Handoff

### `libvm`

While holding the machine lifecycle boundary, `libvm`:

1. Resolves the Silo guest asset bundle.
2. Resolves any explicit base-initramfs override.
3. Resolves all launch-specific inputs required by `AgentConfig`.
4. Serializes the typed configuration to JSON.
5. Creates the composite initramfs at a managed machine path.
6. Writes the generated launch specification with the composite path.
7. Starts `vmmon` only after every generated launch input is complete.

The persisted machine specification retains the configured base-initramfs
reference. The composite is a derived launch artifact, never the canonical
input for later composition, so overlays cannot accumulate across starts.
`libvm` regenerates it for every start, even if the machine and base are
unchanged, because configuration belongs to that launch. It follows the normal
lifetime and cleanup policy for managed per-machine launch artifacts.

Generation uses a temporary file in the destination directory. The temporary
file and final composite are owner-readable and owner-writable only. After all
base and overlay bytes are written and the temporary file closes successfully,
`libvm` atomically renames it over the prior derived artifact. Failed writes
leave no partially updated launch artifact.

`vmmon` receives only the generated VM specification and composite initramfs
path. It does not resolve the agent, parse `AgentConfig`, write CPIO entries, or
serve boot configuration.

### `silo-init`

`/agent` is reserved in the early root for Silo-managed boot payloads. Its
presence asserts that managed agent payload preparation is required. After
mounting the target root, `silo-init`:

1. Verifies `/agent/silo-agent` is a readable regular file.
2. Verifies `/agent/config.json` is a readable regular file.
3. Creates `/run/agent` in the initramfs-owned `/run` tmpfs.
4. Copies the binary to `/run/agent/silo-agent` with mode `0755`.
5. Copies the configuration to `/run/agent/config.json` with mode `0600`.

Both copies complete before either payload is used. `silo-init` rejects
symlinks, directories, devices, and every other non-regular payload entry. The
prepared early `/run` mount is the output boundary of this ADR. The later
handoff design must preserve both files without writing them into the persistent
root.

### Agent

When the later handoff contract invokes the agent, every `libvm`-managed
invocation has `--config=<path>`. The agent:

1. Parses its process arguments.
2. Opens the supplied path without discovery.
3. Reads one bounded complete JSON document.
4. Deserializes and validates the typed `AgentConfig`.
5. Begins managed startup from the in-memory configuration.

Configuration loading and validation precede later managed boot behavior. The
agent reads configuration once per boot and must not reopen it to observe
changes. The explicit configuration path is mandatory. There is no implicit
managed-config path, environment-variable fallback, or discovery mechanism.
The path is not sensitive and may appear in process arguments; configuration
contents must never appear in arguments, environment variables, or logs.

## Configuration And Failure Semantics

`libvm` builds the complete typed `AgentConfig` only after all machine,
network, mount, user, SSH, and provisioning inputs are resolved. It serializes
one UTF-8 JSON document, and the exact bytes become `agent/config.json`. Schema
ownership remains with the shared agent specification; the direction for
static guest network configuration is defined by draft
[ADR 0010](0010-static-guest-network-configuration.md). Archive code treats the
JSON as opaque after serialization.

Configuration is immutable for one boot. A changed configuration requires a
new launch and a new composite initramfs.

Before VM start, an incomplete or incompatible bundle; missing, non-regular, or
unreadable agent; failed configuration construction or serialization; an
unopenable or uncopyable base; an unrepresentable overlay entry; or a temporary
file, write, close, or atomic-replacement error is a launch failure. `libvm`
reports the machine and relevant host path without configuration contents.

If `/agent` is absent, the managed payload path is not selected. The base remains
independently bootable outside a managed launch through behavior defined by the
later handoff decision. If `/agent` exists, both payload files are mandatory.
Any missing, invalid, or uncopyable binary or configuration enters the
`silo-init` rescue shell before the deferred root transition. There is no
partial payload preparation and no fallback to an older agent or configuration
source.

An agent that cannot parse or validate the copied JSON fails managed boot before
proceeding beyond configuration validation, writes a bounded diagnostic to the
serial console, and never reports readiness. `libvm` cannot prove that an
arbitrary custom `/init` honors the payload contract. Failure by a custom
initramfs to consume `/agent` is reported through normal guest startup and
readiness failure behavior.

## Security And Trust

The overlay controls provenance inside the host manager boundary. It does not
provide confidentiality from guest root or the guest kernel, which can read the
initramfs, `/run/agent/config.json`, agent memory, and provisioning effects.

The host composite and temporary file are `0600`; guest configuration is
`0600`; the executable is `0755`. Archive paths are fixed by Silo, never
derived from guest-controlled names. The writer rejects non-normalized paths
and data too large for the format.

Agent configuration, userdata, credentials, keys, and certificate material
must not appear in logs, errors, command-line arguments, or the persisted
machine specification. Host access to a managed composite is equivalent to
access to its generated configuration. The base initramfs and agent are
executable release artifacts in Silo's trusted computing base. Asset signing,
package verification, and confidential guest provisioning are separate
decisions.

## Custom Initramfs Compatibility

A custom initramfs receives the same overlay. Its `/init` must:

- Reserve `/agent` for the Silo payload contract.
- Preserve or copy both payloads into the target root's runtime filesystem.
- Execute the agent with the explicit configuration path.
- Fail closed when only part of the payload is present.
- Ensure configuration validation precedes successful managed boot.

A custom base must not contain a conflicting `/agent/silo-agent` or
`/agent/config.json`. The appended overlay follows the base and its entries are
authoritative, but relying on archive overwrite behavior is not a supported
customization mechanism. Compatibility is behavioral, not a magic marker or
version file. Contract negotiation, if needed, requires a separate decision.

## Conformance Requirements

Unit and integration tests cover:

- Byte-for-byte preservation of the base initramfs.
- Correct four-byte alignment before the raw overlay.
- Exact overlay entry order, paths, types, ownership, modes, sizes, and
  contents.
- A valid independent `TRAILER!!!` entry.
- Rejection of invalid archive paths and oversized files.
- Atomic replacement without overlay accumulation across starts.
- Complete asset-bundle resolution without cross-directory mixing.
- Explicit custom-initramfs composition.
- Launch failure before `vmmon` starts when generation fails.
- Copying both payloads into the early `/run` mount.
- Rescue behavior for each missing, invalid, and failed-copy payload.
- Agent configuration parsing and validation when invoked with
  `--config=/run/agent/config.json` by the later handoff contract.
- Absence of configuration bytes from logs and errors.
- A real Linux boot of the compressed-base plus raw-overlay buffer.

The Linux boot test proves extraction and preparation behavior rather than
relying only on an archive reader. It verifies that both appended payloads are
visible to `silo-init` and copied into early `/run/agent`. It does not select a
root-transition or process-start contract.

## Consequences

### Benefits

- One base initramfs serves managed and unmanaged boots.
- Agent release and machine-specific configuration are selected at launch.
- Agent configuration delivery does not depend on guest networking or a host
  configuration service.
- The base is never unpacked or recompressed during normal launch.
- `vmmon` remains focused on supervision and post-boot control surfaces.
- An explicit configuration argument makes tests and alternate launch modes
  straightforward.
- Machine-specific configuration never modifies the guest root disk.
- Partial extraction fails before the deferred root transition.

### Tradeoffs

- Every launch copies the agent into a new composite artifact.
- The composite consumes host disk and guest initramfs memory during boot.
- The machine directory retains a sensitive derived artifact while it exists.
- Runtime configuration updates require another mechanism.
- Custom compatibility depends on its `/init` implementation.
- Guest root and the guest kernel can inspect injected configuration.

## Alternatives Considered

### Bundle The Agent In The Base Initramfs

This removes a launch-time entry but couples the base to an agent release and
requires a base rebuild when the agent changes. It also invites agent-bearing
and agent-free variants. Independent assets and per-launch composition keep
release and runtime responsibilities clear.

### Rebuild One Compressed Initramfs Per Launch

Unpacking the base, adding files, and recompressing it adds CPU cost, temporary
storage, and failure points. Linux already defines concatenated members, so
rewriting the base has no benefit.

### Fetch Configuration Over A Guest Transport

A pre-network vsock or HTTP service adds listener ordering, a startup protocol,
retries, availability coupling, and a configuration-serving responsibility to a
long-running process. The configuration is known before boot and immutable for
that boot, so injection is simpler.

### Dedicated Configuration Disk Or Virtiofs Share

A configuration disk adds a virtual device, filesystem image creation, device
discovery, and an early mount. A virtiofs share adds an early mount and host
directory lifecycle, and host changes can become visible during boot. The
initramfs already exists and carries both the executable and immutable
configuration without either extra subsystem.

### Modify The Root Disk

Writing agent state into the root filesystem persists launch-specific data,
complicates immutable images and repeated starts, and requires safe offline
mutation. `/run` delivery leaves the root disk unchanged.

### Kernel Command-Line Configuration

Kernel arguments suit small non-secret selectors but are visible through
`/proc/cmdline`, have practical size limits, and handle JSON poorly. Only the
nonsensitive configuration path belongs in a process argument.

## Accepted Limitations

- Injection does not protect payloads from guest root or the guest kernel.
- Configuration cannot change without a new launch.
- Custom initramfs compatibility cannot be established completely before boot.
- A composite from one launch is not a reusable base for another launch.
- Each regular file is limited to the unsigned 32-bit archive size field.
- This mechanism does not synchronize host and guest clocks. The virtual RTC
  and kernel timekeeping configuration own early wall-clock initialization.

## References

- [Linux initramfs buffer format](https://docs.kernel.org/driver-api/early-userspace/buffer-format.html)

## What This Does Not Decide

This ADR does not define the fields or evolution rules of `AgentConfig`, the
public interface for selecting a custom initramfs, runtime configuration
updates, agent installation or self-update, asset signing, remote-manager
artifact transfer, kernel, root-disk, or guest-image distribution,
confidential guest secrets, attestation, or custom-initramfs contract version
negotiation. It also does not define target-init selection, kernel `init=`
interpretation, the mechanism that preserves `/run` across root replacement,
`switch_root` invocation, agent process start, PID 1 ownership, fork or exec
behavior, automatic init probing, or init and handoff arguments beyond the
required `--config` argument. Those concerns require a separate handoff
decision.
