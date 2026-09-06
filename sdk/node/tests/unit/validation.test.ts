import { describe, expect, it } from "vitest";
import { MachineBuilder } from "../../src/machine.js";
import { NetworkPolicy, MachineNetworkBuilder } from "../../src/network.js";
import { ImageSource, type ImageSource as ImageSourceValue, type RuntimeOpenOptions } from "../../src/types.js";
import {
  executionEventFromNative,
  forwardsToNative,
  executionOptionsToNative,
  executionResultFromNative,
  imageDetailFromNative,
  imageHandleFromNative,
  imageSourceToNative,
  machineDataFromNative,
  networkToNative,
  runtimeOptionsToNative,
  sshShellOptionsToNative,
} from "../../src/convert.js";
import type { NativeImageHandle, NativeMachineBuilder, NativeMachineData } from "../../src/internal/napi.js";

const policyJson = `{ "version": 1, "metadata": { "source": "test" } }`;

describe("ImageSource", () => {
  it("constructs explicit image sources", () => {
    expect(ImageSource.oci("ubuntu:24.04")).toEqual({ kind: "oci", reference: "ubuntu:24.04" });
    expect(ImageSource.disk("./rootfs.raw")).toEqual({ kind: "disk", path: "./rootfs.raw" });
  });

  it("rejects empty image source values", () => {
    expect(() => ImageSource.oci("")).toThrow(TypeError);
    expect(() => ImageSource.disk("")).toThrow(TypeError);
  });

  it("rejects missing structured image source values", () => {
    const missingReference: ImageSourceValue = { kind: "oci", reference: "" };

    expect(() => imageSourceToNative(missingReference)).toThrow(TypeError);
  });
});

describe("image inspection", () => {
  it("preserves requested and selected OCI identities", () => {
    expect(imageHandleFromNative(nativeImageHandle())).toMatchObject({
      requestedReference: "alpine:3.21",
      selectedReference: "docker.io/library/alpine@sha256:manifest",
      selectedManifestDigest: "sha256:manifest",
      configDigest: "sha256:config",
    });
  });

  it("preserves absent and explicitly empty OCI configuration collections", () => {
    const absent = imageDetailFromNative({
      handle: nativeImageHandle(),
      config: {},
      layers: [],
    });
    const empty = imageDetailFromNative({
      handle: nativeImageHandle(),
      config: { entrypoint: [], cmd: [], env: [], labels: [] },
      layers: [],
    });

    expect(absent.config).toEqual({
      entrypoint: undefined,
      cmd: undefined,
      env: undefined,
      workingDir: undefined,
      user: undefined,
      labels: undefined,
      stopSignal: undefined,
    });
    expect(empty.config).toMatchObject({ entrypoint: [], cmd: [], env: [], labels: {} });
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

describe("forwarding configuration", () => {
  it("preserves forward modes, public vsock settings, and publication authority", () => {
    const data = nativeMachineData();
    data.forwards = [{ name: "docker", listen: "host:unix:docker.sock", connect: "guest:unix:/run/docker.sock", mode: "0660" }];
    data.vsock = { enabled: true, uds: "custom.sock" };
    data.network = { kind: "private", publish: { bind: "loopback" } };
    const inspected = machineDataFromNative(data);
    expect(forwardsToNative(inspected.forwards)).toEqual(data.forwards);
    expect(inspected.vsock).toEqual(data.vsock);
    expect(networkToNative(inspected.network)).toMatchObject(data.network);
    expect(new MachineNetworkBuilder().publish("any").toNative()).toEqual({ kind: "private", publish: { bind: "any" } });
    expect(() => new MachineNetworkBuilder().none().publish("any")).toThrow(TypeError);
    expect(() => new MachineNetworkBuilder().named("shared").publish("loopback")).toThrow(TypeError);
  });

  it("rejects line injection and invalid Unix modes before reaching native code", () => {
    expect(() => forwardsToNative([{ listen: "host:tcp:0", connect: "guest:unix:/run/x\nextra" }])).toThrow(TypeError);
    expect(() => forwardsToNative([{ listen: "host:unix:socket", connect: "vsock:22", mode: "8888" }])).toThrow(TypeError);
    const data = nativeMachineData();
    data.network = { kind: "private", publish: { bind: "invalid" } };
    expect(() => machineDataFromNative(data)).toThrow(TypeError);
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
        retention: "ephemeral",
        process: {
          entrypoint: [],
          command: [],
          environment: [
            { key: "ALPHA", value: "first" },
            { key: "ZED", value: "last" },
          ],
          workingDirectory: "/workspace",
          user: "1000:1000",
        },
        templateName: "rust-worker",
        configuredAgent: { mode: "disabled" },
        rootfs: {
          sourceKind: "oci",
          requestedReference: "ubuntu:24.04",
          selectedReference: "docker.io/library/ubuntu@sha256:manifest",
          selectedManifestDigest: "sha256:manifest",
          configDigest: "sha256:config",
          imageId: "sha256:image",
          rootDiskPath: "/tmp/silo/machines/machine-id/rootfs.img",
          rootDiskSizeBytes: 1024,
          createdAt: 1,
        },
        labels: [],
        metadata: [],
        forwards: [],
        network: { kind: "private", policyJson },
        agentMode: "default",
        status: { kind: "stopped" },
        updatedAt: 1,
      }),
    ).toMatchObject({
      network: { kind: "private", policyJson },
      retention: "ephemeral",
      process: {
        entrypoint: [],
        command: [],
        environment: { ALPHA: "first", ZED: "last" },
        workingDirectory: "/workspace",
        user: "1000:1000",
      },
      templateName: "rust-worker",
      agentMode: { mode: "disabled" },
      rootfs: {
        requestedReference: "ubuntu:24.04",
        selectedManifestDigest: "sha256:manifest",
        rootDiskSizeBytes: 1024,
      },
    });
  });

  it("preserves unset process arrays and a concrete empty environment map", () => {
    const machine = machineDataFromNative({
      id: "machine-id",
      name: "machine-name",
      machineDir: "/tmp/silo/machines/machine-id",
      createdAt: 1,
      modifiedAt: 1,
      imageRef: "ubuntu:24.04",
      retention: "persistent",
      process: {
        environment: [],
        workingDirectory: "/",
      },
      labels: [],
      metadata: [],
      forwards: [],
      network: { kind: "none" },
      agentMode: "default",
      status: { kind: "stopped" },
      updatedAt: 1,
    });

    expect(machine.process).toEqual({
      entrypoint: undefined,
      command: undefined,
      environment: {},
      workingDirectory: "/",
      user: undefined,
    });
  });

  it("converts guest boot and provisioning reports with millisecond timestamps", () => {
    const machine = machineDataFromNative({
      ...nativeMachineData(),
      bootReport: {
        mode: "init-child",
        requestedInit: "/sbin/init",
        probedInitPaths: ["/sbin/init", "/init"],
        agentPath: "/usr/bin/silo-agent",
        agentPid: 42,
        agentIsPid1: false,
      },
      provisionReport: {
        status: "degraded",
        startedUnixMs: 1_700_000_000_001,
        finishedUnixMs: 1_700_000_000_123,
        durationMs: 122,
        steps: [{
          id: "packages",
          status: "failed",
          failurePolicy: "best-effort",
          changed: true,
          durationMs: 122,
          message: "package mirror unavailable",
        }],
      },
    });

    expect(machine.bootReport).toEqual({
      mode: "init-child",
      requestedInit: "/sbin/init",
      handoffInitPath: undefined,
      probedInitPaths: ["/sbin/init", "/init"],
      agentPath: "/usr/bin/silo-agent",
      agentPid: 42,
      agentIsPid1: false,
      message: undefined,
    });
    expect(machine.provisionReport).toEqual({
      status: "degraded",
      startedAt: new Date(1_700_000_000_001),
      finishedAt: new Date(1_700_000_000_123),
      durationMs: 122,
      steps: [{
        id: "packages",
        status: "failed",
        failurePolicy: "best-effort",
        changed: true,
        backend: undefined,
        durationMs: 122,
        message: "package mirror unavailable",
        errorChain: undefined,
      }],
      message: undefined,
    });
  });

  it("preserves absent reports and falls back for unknown report enums", () => {
    const absent = machineDataFromNative(nativeMachineData());
    const unknown = machineDataFromNative({
      ...nativeMachineData(),
      bootReport: {
        mode: "unknown",
        probedInitPaths: [],
        agentPid: 0,
        agentIsPid1: false,
      },
      provisionReport: {
        status: "unknown",
        startedUnixMs: 0,
        finishedUnixMs: 0,
        durationMs: 0,
        steps: [{
          id: "future-step",
          status: "unknown",
          failurePolicy: "unknown",
          changed: false,
          durationMs: 0,
        }],
      },
    });

    expect(absent.bootReport).toBeUndefined();
    expect(absent.provisionReport).toBeUndefined();
    expect(unknown.bootReport?.mode).toBe("unknown");
    expect(unknown.provisionReport?.status).toBe("unknown");
    expect(unknown.provisionReport?.steps[0]).toMatchObject({
      status: "unknown",
      failurePolicy: "unknown",
    });
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
    const native = executionOptionsToNative({ stdin: "hello" });
    expect(native?.stdin).toBeInstanceOf(Uint8Array);
    expect(new TextDecoder().decode(native?.stdin)).toBe("hello");
  });

  it("rejects stdin bytes and pipe stdin together", () => {
    expect(() => executionOptionsToNative({ stdin: "hello", pipeStdin: true })).toThrow(TypeError);
  });

  it("rejects malformed native exec events instead of inventing values", () => {
    expect(() => executionEventFromNative({ kind: "stdout" })).toThrow(TypeError);
    expect(executionEventFromNative({ kind: "exited" })).toEqual({
      kind: "exited",
      code: undefined,
    });
  });

  it("preserves signaled and lost terminal results without exit-code fallbacks", () => {
    expect(executionResultFromNative({ kind: "signaled", signal: 15 })).toEqual({ kind: "signaled", signal: 15 });
    expect(executionResultFromNative({ kind: "lost", reason: "vmmon_exited" })).toEqual({ kind: "lost", reason: "vmmon_exited", message: undefined });
  });

  it("keeps SSH agent forwarding on the SSH-only shell options", () => {
    expect(sshShellOptionsToNative({
      cwd: "/workspace",
      forwardAgent: true,
    })).toEqual({
      cwd: "/workspace",
      user: undefined,
      env: undefined,
      term: undefined,
      detachKeys: undefined,
      forwardAgent: true,
    });
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
    forwards: () => undefined,
    vsock: () => undefined,
    network: () => undefined,
    create: async () => {
      throw new Error("not used by validation tests");
    },
    ...overrides,
  };
}

function nativeImageHandle(): NativeImageHandle {
  return {
    requestedReference: "alpine:3.21",
    selectedReference: "docker.io/library/alpine@sha256:manifest",
    selectedManifestDigest: "sha256:manifest",
    configDigest: "sha256:config",
    imageId: "sha256:image",
    platformOs: "linux",
    platformArchitecture: "arm64",
    createdAt: 1,
    updatedAt: 2,
  };
}

function nativeMachineData(): NativeMachineData {
  return {
    id: "machine-id",
    name: "machine-name",
    machineDir: "/tmp/silo/machines/machine-id",
    createdAt: 1,
    modifiedAt: 1,
    imageRef: "ubuntu:24.04",
    retention: "ephemeral",
    process: {
      environment: [],
      workingDirectory: "/",
    },
    labels: [],
    metadata: [],
    forwards: [],
    network: { kind: "none" },
    agentMode: "default",
    status: { kind: "stopped" },
    updatedAt: 1,
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
