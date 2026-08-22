# 13. Image-First Machine Lifecycle

Date: 2026-08-07

## Status

Implemented

## Context

Machine creation must produce one durable description that can be inspected,
started, stopped, and reused without reconstructing image or command inputs.
The CLI needs a direct image-first workflow while templates remain a bounded way
to share machine defaults. Workloads also need clear cleanup ownership.

## Decision

`create` and `run` accept an image as their positional operand. A bare operand
is an OCI registry reference; `disk:PATH` selects a local disk. Image resolution
happens before machine creation, and creation materializes a machine-local root
disk.

Templates are named, strict YAML documents. Version 1 requires `version: "1"`
and rejects unknown fields. A template supplies machine defaults and may supply
an image. A positional image overrides the template image.

`silo create` always creates a stopped persistent VM. `silo start` and
`silo restart` boot persistent VMs in an idle state. They do not run the
machine's persisted process configuration.

The resolved OCI process settings are persisted as `ProcessConfig`: entrypoint,
command, environment, working directory, and user. Omitted and empty entrypoint
or command arrays remain distinct. CLI execution uses these values when no
explicit command is supplied.

`silo run` has two retention modes. A run without `--name` receives a generated
name and is ephemeral; its lifecycle owner makes a best-effort removal attempt
after completion. A named run is persistent and remains after the workload
exits. Foreground runs attempt removal directly, while detached runs install a
one-shot `vmmon` exit watcher. The watcher receives the exact run generation,
waits for that monitor process to exit, and removes the machine only if a newer
generation has not taken ownership. Cleanup is not persisted or retried;
failures may leave a stopped machine that can be removed with `silo rm`. The
persisted retention value is visible through machine inspection.

`silo run --detach` sets a launch-only `Entrypoint` on the start request.
`vmmon` acknowledges the start only after the guest program launches, then
supervises the VM until the program exits. The launch-only entrypoint is not
written into `ProcessConfig`. Detachment changes CLI attachment and ownership;
it does not make VM lifetime independent of the workload. The VM stops when the
detached workload exits. Consequently, an image whose default workload is an
interactive shell may stop immediately without an attached terminal or input.
Users who need an idle VM use `silo create` followed by `silo start`.

## Consequences

- Image selection is explicit at the point where a machine is created.
- Templates are stable, reviewable defaults with one accepted schema version.
- Idle lifecycle operations and workload execution have separate ownership.
- Detached execution preserves workload-owned VM lifetime.
- Inspection exposes durable process and retention decisions without depending
  on live monitor state.
- Cleanup policy is deterministic from whether `run` received a name.
- Ephemeral cleanup remains deliberately best effort rather than durable work.
