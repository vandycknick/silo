# silo Node SDK

Native Node.js bindings for Silo's `libvm` runtime.

The SDK is a thin TypeScript facade over a napi-rs addon. VM creation, image
materialization, lifecycle, and guest operations all delegate to `libvm`; the
TypeScript layer only provides idiomatic method names, types, and error mapping.

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
