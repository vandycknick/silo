# bentobox Node SDK

Native Node.js bindings for BentoBox's `libvm` runtime.

The SDK is a thin TypeScript facade over a napi-rs addon. VM creation,
image materialization, datastore updates, lifecycle, and guest sessions all
delegate to `libvm`; the TypeScript layer only provides idiomatic method names,
types, and error mapping.

`bentobox` does not bundle the Bento CLI or `vmmon`. `vmmon` must be available
on `PATH`, or supplied through `Runtime.open({ vmmonPath })`.

```ts
import { ImageSource, Runtime } from "bentobox";

const runtime = await Runtime.open({
  defaultKernel: "/usr/local/share/bento/assets/kernel-default",
  defaultInitramfs: "/usr/local/share/bento/assets/initramfs",
});

const machine = await runtime
  .machine()
  .image("ubuntu:24.04")
  .name("dev")
  .cpus(2)
  .memory(1024)
  .create();

await machine.start();
const output = await machine.shell("uname -a");
console.log(output.stdout());

const diskMachine = await runtime
  .machine()
  .imageSource(ImageSource.disk("./rootfs.raw"))
  .create();

await diskMachine.remove();
```
