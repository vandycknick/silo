# silo Node SDK

Native Node.js bindings for Silo's `libvm` runtime.

The SDK is a thin TypeScript facade over a napi-rs addon. VM creation,
image materialization, datastore updates, lifecycle, and guest sessions all
delegate to `libvm`; the TypeScript layer only provides idiomatic method names,
types, and error mapping.

`silo` does not bundle the Silo CLI or `vmmon`. `vmmon` must be available
on `PATH`, or supplied through `Runtime.open({ vmmonPath })`.

```ts
import { ImageSource, NetworkPolicy, Runtime } from "silo";

const runtime = await Runtime.open({
  defaultKernel: "/usr/local/share/silo/assets/kernel-default",
  defaultInitramfs: "/usr/local/share/silo/assets/initramfs",
});

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
