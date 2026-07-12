import { describe, expect, it } from "vitest";
import { MachineBuilder } from "../../src/machine.js";
import { NetworkPolicy } from "../../src/network.js";
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

const policyJson = `{ "version": 1, "metadata": { "source": "test" } }`;

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
        dataRoot: "/tmp/silo",
      }),
    ).toMatchObject({
      dataRoot: "/tmp/silo",
    });
  });

  it("does not reject extra runtime option fields", () => {
    const options: RuntimeOpenOptions & { bogus: string } = { dataRoot: "/tmp/silo", bogus: "nope" };
    expect(runtimeOptionsToNative(options)).toMatchObject({ dataRoot: "/tmp/silo" });
  });
});

describe("Network", () => {
  it("converts private policy JSON to native input", () => {
    expect(networkToNative({ kind: "private", policyJson })).toEqual({
      kind: "private",
      policyJson,
    });
  });

  it("rejects empty private policy JSON", () => {
    expect(() => networkToNative({ kind: "private", policyJson: "" })).toThrow(TypeError);
  });

  it("converts private policy JSON from native machine data", () => {
    expect(
      machineDataFromNative({
        id: "machine-id",
        name: "machine-name",
        machineDir: "/tmp/silo/machines/machine-id",
        createdAt: 1,
        modifiedAt: 1,
        imageRef: "ubuntu:24.04",
        labels: [],
        metadata: [],
        network: { kind: "private", policyJson },
        agentMode: "default",
        status: { kind: "stopped" },
        updatedAt: 1,
      }).network,
    ).toEqual({ kind: "private", policyJson });
  });
});

describe("NetworkPolicy.define", () => {
  it("builds reference-based endpoint and rule definitions", () => {
    const policy = NetworkPolicy.define((p) => {
      p.defaultDeny();

      const ntp = p
        .endpoint("ntp")
        .ip()
        .udp()
        .toCidr("0.0.0.0/0")
        .port(123);
      const google = p.endpoint("google").https().host("google.com");
      const archlinuxarm = p
        .endpoint("archlinuxarm")
        .http()
        .host("mirror.archlinuxarm.org")
        .host("*.mirror.archlinuxarm.org");

      p.rule("allow_ntp").endpoint(ntp).allow();
      p.rule("allow_google").endpoint(google).allow();
      p.rule("allow_arch").endpoint(archlinuxarm).allow();
    });

    const document = parsePolicyDocument(policy);
    const endpoints = recordArrayField(document, "endpoints");
    const rules = recordArrayField(document, "rules");

    expect(document).toMatchObject({
      settings: { default_action: "deny" },
    });
    expect(endpoints).toContainEqual(
      expect.objectContaining({
        name: "ntp",
        kind: "ip",
        destination_cidrs: ["0.0.0.0/0"],
        protocol: "udp",
        ports: [expect.objectContaining({ start: 123 })],
      }),
    );
    expect(endpoints).toContainEqual(
      expect.objectContaining({
        name: "google",
        kind: "https",
        hosts: ["google.com"],
      }),
    );
    expect(rules).toContainEqual(
      expect.objectContaining({
        name: "allow_ntp",
        endpoints: ["ntp"],
        verdict: "allow",
      }),
    );
  });

  it("builds typed credential references", () => {
    const policy = NetworkPolicy.define((p) => {
      p.defaultDeny();

      const api = p.endpoint("api").https().host("api.example.com");
      const apiToken = p
        .credential("api_token")
        .bearerToken()
        .endpoint(api)
        .prefix("Bearer ");

      p.rule("allow_api").endpoint(api).credential(apiToken).allow();
    });

    const document = parsePolicyDocument(policy);
    const credentials = recordArrayField(document, "credentials");
    const rules = recordArrayField(document, "rules");

    expect(credentials).toContainEqual(
      expect.objectContaining({
        name: "api_token",
        kind: "bearer_token",
        endpoint: "api",
        prefix: "Bearer ",
      }),
    );
    expect(rules).toContainEqual(
      expect.objectContaining({
        name: "allow_api",
        endpoints: ["api"],
        credential: "api_token",
        verdict: "allow",
      }),
    );
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

  it("configures networking through the fluent builder", () => {
    let networkInput: unknown;
    const builder = new MachineBuilder(
      fakeNativeBuilder({
        network: (network) => {
          networkInput = network;
        },
      }),
    );

    builder.network((network) =>
      network.private().policy(NetworkPolicy.fromJson(policyJson)),
    );

    expect(networkInput).toEqual({ kind: "private", policyJson });
  });

  it("configures custom and disabled guest agents", () => {
    const selections: Array<string | undefined> = [];
    const builder = new MachineBuilder(
      fakeNativeBuilder({
        agent: (path) => selections.push(path),
      }),
    );

    builder.guest((guest) => guest.agent("/custom/agent"));
    builder.guest((guest) => guest.agent(null));

    expect(selections).toEqual(["/custom/agent", undefined]);
  });
});

function fakeNativeBuilder(overrides: Partial<NativeMachineBuilder> = {}): NativeMachineBuilder {
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
    agent: () => undefined,
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
    ...overrides,
  };
}

function parsePolicyDocument(policy: NetworkPolicy): Record<string, unknown> {
  const document: unknown = JSON.parse(policy.toJson());
  if (!isRecord(document)) {
    throw new TypeError("policy document must be an object");
  }
  return document;
}

function recordArrayField(
  record: Record<string, unknown>,
  field: string,
): Record<string, unknown>[] {
  const value = record[field];
  if (!Array.isArray(value) || !value.every(isRecord)) {
    throw new TypeError(`${field} must be an array of objects`);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
