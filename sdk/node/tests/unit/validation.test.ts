import { describe, expect, it } from "vitest";
import { MachineBuilder } from "../../src/machine.js";
import { ImageSource, type ImageSource as ImageSourceValue, type RuntimeOpenOptions } from "../../src/types.js";
import {
  execEventFromNative,
  execOptionsToNative,
  imageSourceToNative,
  machineDataFromNative,
  networkToNative,
  runtimeOptionsToNative,
} from "../../src/convert.js";
import type { NativeMachineBuilder } from "../../src/internal/napi.js";

describe("ImageSource", () => {
  it("constructs explicit image sources", () => {
    expect(ImageSource.oci("ubuntu:24.04")).toEqual({ kind: "oci", reference: "ubuntu:24.04" });
    expect(ImageSource.disk("./rootfs.raw")).toEqual({ kind: "disk", path: "./rootfs.raw" });
    expect(ImageSource.tar("./rootfs.tar")).toEqual({ kind: "tar", path: "./rootfs.tar" });
  });

  it("rejects empty image source values", () => {
    expect(() => ImageSource.oci("")).toThrow(TypeError);
    expect(() => ImageSource.disk("")).toThrow(TypeError);
    expect(() => ImageSource.tar("")).toThrow(TypeError);
  });

  it("rejects missing structured image source values", () => {
    const missingReference: ImageSourceValue = { kind: "oci", reference: "" };

    expect(() => imageSourceToNative(missingReference)).toThrow(TypeError);
  });
});

describe("runtime options", () => {
  it("passes through supported runtime options", () => {
    expect(
      runtimeOptionsToNative({
        dataRoot: "/tmp/bento",
        defaultKernel: "/usr/local/share/bento/assets/kernel-default",
        defaultInitramfs: "/usr/local/share/bento/assets/initramfs",
      }),
    ).toMatchObject({
      dataRoot: "/tmp/bento",
      defaultKernel: "/usr/local/share/bento/assets/kernel-default",
      defaultInitramfs: "/usr/local/share/bento/assets/initramfs",
    });
  });

  it("does not reject extra runtime option fields", () => {
    const options: RuntimeOpenOptions & { bogus: string } = { dataRoot: "/tmp/bento", bogus: "nope" };
    expect(runtimeOptionsToNative(options)).toMatchObject({ dataRoot: "/tmp/bento" });
  });
});

describe("Network", () => {
  it("converts private policy refs to native input", () => {
    expect(networkToNative({ kind: "private", policyRef: "github" })).toEqual({
      kind: "private",
      policyRef: "github",
    });
  });

  it("rejects empty private policy refs", () => {
    expect(() => networkToNative({ kind: "private", policyRef: "" })).toThrow(TypeError);
  });

  it("converts private policy refs from native machine data", () => {
    expect(
      machineDataFromNative({
        id: "machine-id",
        name: "machine-name",
        machineDir: "/tmp/bento/machines/machine-id",
        createdAt: 1,
        modifiedAt: 1,
        imageRef: "ubuntu:24.04",
        labels: [],
        metadata: [],
        network: { kind: "private", policyRef: "github" },
        status: { kind: "stopped" },
        updatedAt: 1,
      }).network,
    ).toEqual({ kind: "private", policyRef: "github" });
  });
});

describe("exec option and event validation", () => {
  it("converts string stdin into bytes", () => {
    const native = execOptionsToNative({ stdin: "hello" });
    expect(native?.stdin).toBeInstanceOf(Uint8Array);
    expect(new TextDecoder().decode(native?.stdin)).toBe("hello");
  });

  it("rejects stdin bytes and pipe stdin together", () => {
    expect(() => execOptionsToNative({ stdin: "hello", pipeStdin: true })).toThrow(TypeError);
  });

  it("rejects malformed native exec events instead of inventing values", () => {
    expect(() => execEventFromNative({ kind: "stdout" })).toThrow(TypeError);
    expect(() => execEventFromNative({ kind: "exited" })).toThrow(TypeError);
  });
});

describe("MachineBuilder boundary validation", () => {
  it("validates simple scalar setters before native calls", () => {
    const builder = new MachineBuilder(fakeNativeBuilder());

    expect(() => builder.image("")).toThrow(TypeError);
    expect(() => builder.cpus(0)).toThrow(RangeError);
    expect(() => builder.cpus(256)).toThrow(RangeError);
    expect(() => builder.memory(0)).toThrow(RangeError);
    expect(() => builder.rootDiskSize(-1)).toThrow(RangeError);
  });
});

function fakeNativeBuilder(): NativeMachineBuilder {
  return {
    image: () => undefined,
    imageSource: () => undefined,
    name: () => undefined,
    label: () => undefined,
    labels: () => undefined,
    metadataEntry: () => undefined,
    metadata: () => undefined,
    cpus: () => undefined,
    memory: () => undefined,
    kernel: () => undefined,
    initramfs: () => undefined,
    rootDiskSize: () => undefined,
    nestedVirtualization: () => undefined,
    rosetta: () => undefined,
    userdata: () => undefined,
    disks: () => undefined,
    mounts: () => undefined,
    network: () => undefined,
    create: async () => {
      throw new Error("not used by validation tests");
    },
  };
}
