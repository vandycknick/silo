# Hybrid Vsock

Silo exposes virtio-vsock through a host Unix-socket surface. silo-vmm always
attaches the device so its SSH and guest-agent connections to guest ports 22
and 1027 remain available. The public host surface is opt-in:

```yaml
vsock:
  enabled: true
  uds: vsock.sock # optional; defaults to vsock.sock
```

Omitting `vsock`, or setting `enabled: false`, creates no public sockets. A
custom `uds` must be one filename, not an absolute or nested path. Setting
`uds` while disabled is rejected. The runtime-owned names `vm.sock`, `vm.pid`,
`vm.lock`, and `krun.vsock` are reserved. `krun.vsock` is retained as a legacy
validator reservation; the current krun transport does not create that path.
This is an intentional schema break without a VM spec version bump: old
endpoint and plugin fields are rejected with a migration error rather than
ignored.

The krun backend implements this public surface over a separate private
socketpair inherited by the `krun` worker (fd 7 of its fixed descriptor
table) on both Linux and macOS. Connection-control
messages cross that channel with one per-connection Unix stream descriptor
passed by `SCM_RIGHTS`; payload bytes use the passed stream and never the
control channel. This private transport creates no filesystem path and does not
change the public registry, admission limits, listener discovery, stream
relays, or lifecycle described below. Krun is the default backend on Linux and
macOS; Virtualization.framework remains available through an explicit `vz`
selection on macOS.

## Host To Guest

When enabled, `Machine::vsock_socket()` returns the mux path below the machine
runtime directory. Connect to it and send one canonical command:

```text
CONNECT <guest-port>\n
```

silo-vmm replies `OK <host-source-port>\n` after the guest accepts, then relays
bytes in both directions. Bytes sent in the same write after the newline are
preserved. For example:

```bash
printf 'CONNECT 7000\nhello\n' | socat - UNIX-CONNECT:/tmp/silo-1000/machines/MACHINE_ID/vsock.sock
```

Ports 22 and 1027 are valid mux destinations. The mux client must have the same
effective UID as silo-vmm. Malformed, oversized, or unauthorized requests are
closed without a reply. Backend connection setup has a two-second timeout.

## Guest To Host

An extension publishes a Unix listener named `<mux>_<host-port>`, for example
`vsock.sock_5000`. `Machine::vsock_listener_socket(port)` returns this path and
returns `None` when the public surface is disabled. Host port 1027 is reserved
for Silo and also returns `None`; host port 22 is available to extensions.

The extension, not silo-vmm, owns the listener lifecycle:

1. Resolve the path and bind the Unix listener, preferably before VM startup.
2. Keep the listener open while the service is available.
3. Accept relayed Unix streams from silo-vmm.
4. Close and attempt to unlink the listener during extension shutdown, treating
   an already-removed path as success.

silo-vmm watches the runtime directory and registers valid listeners dynamically.
Filesystem notifications are eventual-consistency signals, so a guest racing a
new, replaced, or removed listener can receive a reset and must retry. A guest
can connect with an AF_VSOCK-capable tool:

```bash
socat - VSOCK-CONNECT:2:5000
```

To serve a guest port for host mux clients:

```bash
socat VSOCK-LISTEN:7000,reuseaddr,fork EXEC:/usr/bin/cat
```

Only socket entries in silo-vmm's owner-only runtime directory are discovered.
The machine-runtime owner is trusted and can replace or redirect listener paths,
so extensions must retain the directory's `0700` trust boundary and must not
expose these paths through broader permissions.

## Limits And Shutdown

Each VM permits 1024 monotonically registered guest-to-host ports and 1023
active virtio-vsock connections total across both directions. A mux client does
not consume connection capacity until it submits a valid `CONNECT` command.

silo-vmm stops admitting work during shutdown, resets backend streams, drains
relays, and removes the mux and private backend sockets it owns. After
silo-vmm exits, libvm removes the complete machine runtime tree, including names for
extension-owned `<mux>_<port>` listeners. Extensions must close their listener
descriptors, tolerate an already-removed path, and retry or fail outstanding
work when the VM exits.

See [ADR 0015](adr/0015-hybrid-vsock-host-surface.md) for the normative protocol
and architecture decisions.
