# silo Node SDK

Native Node.js bindings for Silo's `libvm` runtime.

The SDK is a thin TypeScript facade over a napi-rs addon. VM creation, image
materialization, lifecycle, and guest operations all delegate to `libvm`; the
TypeScript layer only provides idiomatic method names, types, and error mapping.

The current SDK does not bundle a runtime payload. `libvm` resolves one complete
co-versioned runtime set containing `silo-vmm`, `netd`, the kernel,
initramfs, and agent (`silo-vmm` also runs the libkrun worker, so there is no
separate krun binary). `Runtime.open({ supervisorPath })` replaces only
`silo-vmm`; the remaining components must still resolve from the same
centralized discovery contract. `Runtime.open({ home })` selects the Silo home
that holds all persistent state; it defaults to `SILO_HOME`, else `~/.silo`.
Generated sockets always live under `/tmp/silo-<euid>`. The retained component overrides (`SILO_VMM_PATH`, `NETD_BIN`,
and `SILO_ASSET_DIR`) and portable-root override
(`SILO_RUNTIME_DIR`) remain available to `libvm`.

`PATH` is disabled unless `SILO_ASSET_DIR` is explicit and validates as one
complete asset set. When enabled, `silo-vmm` and `netd` must be executable
files in the same absolute `PATH` entry. Historical asset directories are not
searched automatically. Bundled Node runtime packaging is deferred to Commit
13.

Machine builders also expose `.forwards([...])`, `.vsock(enabled)`, and
`.network(n => n.private().publish("loopback"))`. Publications are disabled
unless explicitly enabled on a private network. Use `"any"` only when the
guest should be allowed to bind wildcard host addresses.

```ts
const engine = await runtime.machine().image("my-docker-image")
  .forwards([{ name: "docker", listen: "host:unix:docker.sock", connect: "guest:unix:/var/run/docker.sock" }])
  .vsock(true)
  .network(n => n.private().publish("any"))
  .create();
```

`inspect()` returns `forwards`, `vsock`, and `network.publish`. Relative host
Unix paths resolve inside the machine runtime directory. Forward `mode` is a
four-digit octal Unix permission string, default `"0600"`. SDK session-scoped
forward handles are not yet exposed.

```ts
import { ImageSource, NetworkPolicy, Runtime } from "silo";

const runtime = await Runtime.open();

const machine = await runtime
  .machine()
  .image("ubuntu:24.04")
  .name("dev")
  .cpus(2)
  .memory(1024)
  .create();

const policy = NetworkPolicy.define((policy) => {
  policy.defaultDeny();

  const openai = policy.endpoint("openai").https().host("api.openai.com");
  const codex = policy.credential("codex").openaiCodexOauth().endpoint(openai);

  policy.rule("allow-openai").endpoint(openai).credential(codex).allow();
});

const policyMachine = await runtime
  .machine()
  .image("ubuntu:24.04")
  .network((network) => network.private().policy(policy))
  .create();

await machine.start();
const output = await machine.exec("/usr/bin/uname", ["-a"]);
console.log(output.stdout());

const diskMachine = await runtime
  .machine()
  .imageSource(ImageSource.disk("./rootfs.raw"))
  .create();

await diskMachine.remove();
await policyMachine.remove();
```

## Execution

| Operation | Transport and result |
| --- | --- |
| `exec(program, args, options)` | Agent RPC, literal argv, collected `ExecutionOutput` |
| `spawn(program, args, options)` | Agent RPC, caller-driven `ExecutionSession`, optional PTY |
| `execScript(script, options)` | Agent RPC `/bin/sh -l -c`, collected `ExecutionOutput` |
| `shell(options)` | Certificate-authenticated SSH login PTY, `SshExitStatus` |

This is a hard cutover: rebuild the addon and facade together. There are no
attachment aliases or script/interactive overload dispatch, and no version bump.
The canonical transport and lifecycle guide is [libvm's README](../../runtime/libvm/README.md).

```ts
import { Runtime } from "silo";
const runtime = await Runtime.open();
const machine = await runtime.getMachine("existing-machine-id");
console.log((await machine.exec("/usr/bin/printf", ["%s", "$HOME"])).stdout()); // literal
console.log((await machine.execScript('printf "%s\\n" "$HOME" | cat')).stdout());
const session = await machine.spawn("/bin/cat", [], { pipeStdin: true });
try {
  for (;;) {
    const event = await session.recv();
    if (event === null) throw new Error("process ended before Started");
    if (event.kind === "started") break;
  }
  const input = session.stdin();
  if (!input) throw new Error("stdin unavailable");
  await input.write("hello\\n");
  await input.close();
  console.log((await session.collect()).stdout());
} finally { session.cancel(); }
```

Scripts read login startup files; shell syntax and injection safety are the
caller's responsibility. Never concatenate untrusted input into scripts.
Collected execution applies `timeout` after startup; `spawn` does not acquire
a deadline from that option. `wait` discards output, `collect` buffers it;
neither is a reconnect API. Receive Started before acquiring or writing stdin.

`await machine.shell({ user: "silo", term: "xterm-256color" })` owns the local
terminal. SSH needs a Running, non-stopping VM, vsock 22, an existing immutable
host-key pin, a matching presented key and accepted user certificate. A fresh
agent readiness report is not a prerequisite for independently owned SSH.
`cwd` is best effort; cwd/env use the existing quoted exec wrapper rather than
AcceptEnv. Without cwd/env, sshd selects the login shell/environment.

```ts
const cancellation = new AbortController();
const chunks: Uint8Array[] = [];
const status = await machine.shell({
  term: "xterm-256color", signal: cancellation.signal,
  attachment: {
    rows: 37, columns: 119,
    // This finite memory iterator cannot block.
    async *stdin() { yield new TextEncoder().encode('printf "embedded:%s\\n" "$USER"; exit 7\\n'); },
    // Memory sinks cannot block either. Blocking sinks must observe signal.
    async stdout(chunk) { chunks.push(chunk.slice()); },
    async stderr(chunk) { chunks.push(chunk.slice()); },
    async *controls() { yield { kind: "resize" as const, rows: 37, columns: 119 }; },
  },
});
console.log(status.code); // 7, not an exception
```

Attachments are one-call ownership of supplied I/O only; no host stdio,
termios, ioctls or process signals are touched. Dimensions must be integers
in 1..65535. `detachKeys` is invalid with an attachment; supplied Ctrl+] bytes
are transparent. Missing stdin sends SSH channel EOF, missing sinks discard,
and absent controls create no JS pump. Channel EOF is not Ctrl-D: a login PTY
may need `exit` or explicit EOT bytes. Cancellation is neither EOF nor login exit.
SSH signal exits map to code 128; local detach maps to success.

Callbacks/iterables receive separate input/control and output abort signals.
They must settle on abort, including pending next/write calls. Arbitrary
uncooperative callbacks cannot be forcibly interrupted. Native success stops
and joins input/control while both output readers drain; only then are output
callbacks aborted and the native operation closed. Parent abort remains active
during drain. Actual sink calls are serialized so one non-thread-safe sink can
serve both streams; per-stream, not cross-stream, order is guaranteed.
Failure cancels and joins all pumps and native cleanup, preserving the first
error. Borrowed outer SSH sessions and process stdio are never closed.

The addon owns bounded 64-KiB simplex pipes and a 64-entry control channel,
not JS callbacks or a second SSH client. Its private operation retains the
machine/runtime until awaited cleanup. Dropping a Rust future can request
cancellation but cannot await wire release; public awaited calls join cleanup.
Run `node sdk/node/examples/shell.mjs <machine-id>` against a selected running
machine (`SILO_HOME` selects its home); it prints and returns exit 7.

## Guest files

Running machines expose `statFile`, `createDirectory`, `uploadFile`, and
`downloadFile`. Guest paths must be absolute. Uploads accept a `Uint8Array` or
an `AsyncIterable<Uint8Array>` and return `{ disposition, bytes }`; the guest
atomically creates or replaces the regular file. Optional numeric `mode`
(at most `0o7777`), `uid`, and `gid` configure uploads or directory creation.
Omitted metadata preserves an existing file; new files default to `0644`.

```ts
await machine.createDirectory("/tmp/files", { parents: true });
await machine.uploadFile("/tmp/files/example", new TextEncoder().encode("hello"));
const download = await machine.downloadFile("/tmp/files/example");
const bytes = await download.collect();
```

Downloads are async iterables of byte chunks. `collect()` buffers the complete
file; use iteration for large files, or `cancel()` to stop a transfer. Breaking
iteration cancels it automatically. `statFile()` preserves `sizeBytes` as a
`bigint` and exposes `modifiedAt` as a `Date`.

## Tailnet policy forwards

Network-policy forwards are separate from machine-scoped forwards. For a
dedicated 1:1 VM network, expose a guest HTTP service with managed tailnet HTTPS:

```ts
const policy = NetworkPolicy.define((p) => {
  p.forward("web").tailscale().target("self").targetPort(8080).listen(":443")
    .protocol("https").tls({ provider: "tailscale" });
});
```

The fluent equivalent uses `.forward("web", f => f.tailscale()...)`. Listener
selection and binding are separate: use `.tailscale().tunnel(tunnelRef)` in the
definition API or `.tailscale().tunnel("vm")` in the fluent API when declaring
an explicit node. This example creates a reusable unbound policy. Managed SSH
policies omit the binding; the lobby supplies it. A local launch still needs
exactly one declared Tailscale node and its enrollment/state configuration.
An omitted protocol means raw TCP, even on port 443; TCP cannot carry a `tls`
configuration. HTTPS terminates at netd and forwards plaintext HTTP to the guest
interface, where the service must listen (not only on loopback). `self` requires
a dedicated attachment; shared/unknown scopes reject it. Managed certificates
require certificate-enabled tailnet DNS, not a certificate secret in the guest.

## Lifecycle And Process Data

`create()` materializes an image and persists a stopped machine. `start()` boots
that machine without launching an application workload; `stop()` returns it to
the stopped state. `exec`, `spawn`, and `shell` run structured guest commands on
an already-running machine.

`inspect()` returns the durable process configuration in `MachineData.process`.
It keeps the selected entrypoint, command, environment, working directory, and
user separate from the VM lifecycle state:

```ts
const data = await machine.inspect();
console.log(data.process.entrypoint, data.process.command);
```

For diagnostics, `Machine.logs(source, options)` reads one semantic machine log
stream. The available sources are `"monitor"`, `"serial"`, `"exec"`, `"network"`,
and `"networkAudit"`; chunks preserve raw bytes in `Uint8Array`.
