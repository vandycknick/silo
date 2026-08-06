# silo Node SDK

Native Node.js bindings for Silo's `libvm` runtime.

The SDK is a thin TypeScript facade over a napi-rs addon. VM creation,
image materialization, datastore updates, lifecycle, and guest sessions all
delegate to `libvm`; the TypeScript layer only provides idiomatic method names,
types, and error mapping.

The current SDK does not bundle a runtime payload. `libvm` resolves one complete
co-versioned runtime set containing `vmmon`, `netd`, `krun`, the kernel,
initramfs, and agent. `Runtime.open({ vmmonPath })` replaces only `vmmon`; the
remaining components must still resolve from the same centralized discovery
contract. The retained component overrides (`SILO_VMMON_PATH`, `NETD_BIN`,
`KRUN_BIN`, and `SILO_ASSET_DIR`) and portable-root override
(`SILO_RUNTIME_DIR`) remain available to `libvm`.

`PATH` is disabled unless `SILO_ASSET_DIR` is explicit and validates as one
complete asset set. When enabled, `vmmon`, `netd`, and `krun` must be executable
files in the same absolute `PATH` entry. Historical asset directories are not
searched automatically. Bundled Node runtime packaging is deferred to Commit
13.

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
const output = await machine.shell("uname -a");
console.log(output.stdout());

const diskMachine = await runtime
  .machine()
  .imageSource(ImageSource.disk("./rootfs.raw"))
  .create();

await diskMachine.remove();
await policyMachine.remove();
```

## Persisted Machine Logs

`Machine.logs(source, options)` is the SDK access boundary for retained
machine-owned logs. Sources are semantic, never paths or filenames:

```ts
for await (const chunk of await machine.logs("monitor", { follow: true })) {
  process.stdout.write(chunk.data);
}
```

The supported sources are `"monitor"`, `"serial"`, `"exec"`, `"network"`, and
`"networkAudit"`. Chunks preserve bytes in `Uint8Array` and identify a transport
output channel. The `"exec"` source is bounded, best-effort JSON Lines output,
not a process attachment or authoritative execution result. Network sources
reject machines without private networking.

Without `follow`, the stream is a finite snapshot. With `follow: true`, it
emits the same snapshot then appended bytes without a handoff gap. The stream
remains attached while the machine is stopped and across later starts until the
reader closes it. Async iteration closes automatically, including when a
`for await` loop exits early. Code that calls `recv()` directly must call
`close()` when it is finished. Filesystem paths, offsets, and retained log names
are intentionally not part of the Node API. Detached startup commands and
ordinary structured executions both contribute output to the same lossy,
bounded `"exec"` source without creating process history or a durable result.
