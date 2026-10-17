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
replaces only the `silo-vmm` path. Machine starts launch the resolved absolute
`silo-vmm` path directly. For the krun backend,
silo-vmm re-executes itself with `argv[0]` set to `krun` to run libkrun in a
private worker, so there is no separate krun component to resolve (see
[silo-vmm architecture](../../docs/architecture/silo-vmm.md)).
Private networking launches the resolved absolute `netd` path directly.

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

Machine kernel, initramfs, and agent overrides remain independent. An omitted
asset always uses its matching file from the resolved installation set, so one
launch never combines defaults from separate installations. `libvm` performs
all component environment and controlled PATH resolution while opening the
runtime; launched helpers do not repeat discovery.

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
