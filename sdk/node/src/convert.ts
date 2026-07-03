import type {
  NativeAttachOptionsInput,
  NativeExecEvent,
  NativeExecOptionsInput,
  NativeImageDetail,
  NativeImageHandle,
  NativeImageLayerDetail,
  NativeImagePruneReport,
  NativeImageSourceInput,
  NativeKeyValue,
  NativeMachineData,
  NativeMountInput,
  NativeNetworkData,
  NativeNetworkInput,
  NativeRuntimeOpenOptions,
} from "./internal/napi.js";
import type {
  AttachOptions,
  ExecOptions,
  ImageDetail,
  ImageHandle,
  ImageLayerDetail,
  ImagePruneReport,
  ImageSource,
  KeyValueMap,
  MachineData,
  Mount,
  Network,
  RuntimeOpenOptions,
} from "./types.js";
import {
  assertBoolean,
  assertNonEmptyString,
  assertPositiveInteger,
  assertRecord,
  assertString,
  assertStringArray,
  assertUint8Array,
} from "./validation.js";

export function runtimeOptionsToNative(options?: RuntimeOpenOptions): NativeRuntimeOpenOptions | undefined {
  if (!options) return undefined;
  const record = assertRecord(options, "options");
  return {
    dataRoot: optionalNonEmptyString(record.dataRoot, "options.dataRoot"),
    runRoot: optionalNonEmptyString(record.runRoot, "options.runRoot"),
    imageRoot: optionalNonEmptyString(record.imageRoot, "options.imageRoot"),
    defaultKernel: optionalNonEmptyString(record.defaultKernel, "options.defaultKernel"),
    defaultInitramfs: optionalNonEmptyString(record.defaultInitramfs, "options.defaultInitramfs"),
    vmmonPath: optionalNonEmptyString(record.vmmonPath, "options.vmmonPath"),
  };
}

export function mapToKeyValues(value?: KeyValueMap): NativeKeyValue[] | undefined {
  if (!value) return undefined;
  const record = assertRecord(value, "value");
  return Object.entries(record).map(([key, entryValue]) => ({ key, value: entryValue as string }));
}

export function keyValuesToMap(values: NativeKeyValue[]): KeyValueMap {
  return Object.fromEntries(values.map(({ key, value }) => [key, value]));
}

export function mountsToNative(mounts: Mount[]): NativeMountInput[] {
  if (!Array.isArray(mounts)) throw new TypeError("mounts must be an array");
  return mounts.map((mount, index) => {
    const record = assertRecord(mount, `mounts[${index}]`);
    return {
      source: record.source as string,
      tag: record.tag as string,
      readOnly: record.readOnly as boolean | undefined,
    };
  });
}

export function networkToNative(network: Network): NativeNetworkInput {
  const record = assertRecord(network, "network");
  const kind = assertString(record.kind, "network.kind");
  switch (kind) {
    case "private":
      return {
        kind,
        policyRef: optionalNonEmptyString(record.policyRef, "network.policyRef"),
      };
    case "none":
      return { kind };
    case "named":
      return { kind: "named", name: assertNonEmptyString(record.name, "network.name") };
    case "unknown":
      throw new TypeError("unknown network data cannot be used as a machine builder input");
    default:
      throw new TypeError("network.kind must be private, none, or named");
  }
}

export function imageSourceToNative(source: ImageSource): NativeImageSourceInput {
  const record = assertRecord(source, "source");
  const kind = assertString(record.kind, "source.kind");
  switch (kind) {
    case "oci":
      return { kind, reference: assertNonEmptyString(record.reference, "source.reference") };
    case "disk":
    case "tar":
      return { kind, path: assertNonEmptyString(record.path, "source.path") };
    default:
      throw new TypeError("source.kind must be oci, disk, or tar");
  }
}

export function machineDataFromNative(data: NativeMachineData): MachineData {
  return {
    id: data.id,
    name: data.name,
    machineDir: data.machineDir,
    createdAt: unixDate(data.createdAt),
    modifiedAt: unixDate(data.modifiedAt),
    imageRef: data.imageRef,
    rootDiskSize: data.rootDiskSize ?? undefined,
    labels: keyValuesToMap(data.labels),
    metadata: keyValuesToMap(data.metadata),
    network: networkFromNative(data.network),
    status: {
      kind: data.status.kind,
      guestReady: data.status.guestReady ?? undefined,
      message: data.status.message ?? undefined,
    },
    startedAt: optionalUnixDate(data.startedAt),
    lastError: data.lastError ?? undefined,
    updatedAt: unixDate(data.updatedAt),
  };
}

export function execOptionsToNative(options?: ExecOptions): NativeExecOptionsInput | undefined {
  if (!options) return undefined;
  const record = assertRecord(options, "options");
  const stdin = optionalStdin(record.stdin, "options.stdin");
  const pipeStdin = optionalBoolean(record.pipeStdin, "options.pipeStdin");
  if (stdin && pipeStdin) {
    throw new TypeError("options.stdin and options.pipeStdin cannot both be set");
  }
  return {
    args: optionalStringArray(record.args, "options.args"),
    cwd: optionalString(record.cwd, "options.cwd"),
    user: optionalString(record.user, "options.user"),
    env: record.env === undefined ? undefined : mapToKeyValues(record.env as KeyValueMap),
    timeout: optionalPositiveInteger(record.timeout, "options.timeout"),
    stdin,
    pipeStdin,
    tty: optionalBoolean(record.tty, "options.tty"),
    forwardAgent: optionalBoolean(record.forwardAgent, "options.forwardAgent"),
  };
}

export function attachOptionsToNative(options?: AttachOptions): NativeAttachOptionsInput | undefined {
  if (!options) return undefined;
  const record = assertRecord(options, "options");
  return {
    args: optionalStringArray(record.args, "options.args"),
    cwd: optionalString(record.cwd, "options.cwd"),
    user: optionalString(record.user, "options.user"),
    env: record.env === undefined ? undefined : mapToKeyValues(record.env as KeyValueMap),
    term: optionalNonEmptyString(record.term, "options.term"),
    detachKeys: optionalNonEmptyString(record.detachKeys, "options.detachKeys"),
    forwardAgent: optionalBoolean(record.forwardAgent, "options.forwardAgent"),
  };
}

export function imageHandleFromNative(handle: NativeImageHandle): ImageHandle {
  return {
    reference: handle.reference,
    imageId: handle.imageId,
    manifestDigest: handle.manifestDigest ?? undefined,
    platform: {
      os: handle.platformOs,
      architecture: handle.platformArchitecture,
      variant: handle.platformVariant ?? undefined,
    },
    size: handle.sizeBytes ?? undefined,
    createdAt: unixDate(handle.createdAt),
    updatedAt: unixDate(handle.updatedAt),
    lastUsedAt: optionalUnixDate(handle.lastUsedAt),
  };
}

export function imageDetailFromNative(detail: NativeImageDetail): ImageDetail {
  return {
    handle: imageHandleFromNative(detail.handle),
    layers: detail.layers.map(imageLayerFromNative),
  };
}

export function imagePruneReportFromNative(report: NativeImagePruneReport): ImagePruneReport {
  return {
    referencesRemoved: report.referencesRemoved,
    artifactsRemoved: report.artifactsRemoved,
    bytesRemoved: report.bytesRemoved,
  };
}

export type ExecEvent =
  | { kind: "started" }
  | { kind: "stdout"; data: Uint8Array }
  | { kind: "stderr"; data: Uint8Array }
  | { kind: "exited"; code: number }
  | { kind: "failed"; message: string }
  | { kind: "stdin_error"; message: string };

export function execEventFromNative(event: NativeExecEvent): ExecEvent {
  switch (event.kind) {
    case "stdout":
    case "stderr":
      return { kind: event.kind, data: assertUint8Array(event.data, `exec event ${event.kind}.data`) };
    case "exited":
      return { kind: "exited", code: assertExitCode(event.code, "exec event exited.code") };
    case "failed":
    case "stdin_error":
      return { kind: event.kind, message: assertString(event.message, `exec event ${event.kind}.message`) };
    case "started":
      return { kind: "started" };
  }
}

function imageLayerFromNative(layer: NativeImageLayerDetail): ImageLayerDetail {
  return {
    blobDigest: layer.blobDigest,
    diffId: layer.diffId,
    mediaType: layer.mediaType,
    compressedSize: layer.compressedSizeBytes ?? undefined,
    uncompressedSize: layer.uncompressedSizeBytes ?? undefined,
    position: layer.position,
  };
}

function networkFromNative(network: NativeNetworkData): Network {
  if (network.kind === "private") {
    const policyRef = optionalNullableNonEmptyString(network.policyRef, "network.policyRef");
    return policyRef === undefined ? { kind: "private" } : { kind: "private", policyRef };
  }
  if (network.kind === "named") {
    return { kind: "named", name: network.name ?? "" };
  }
  return { kind: network.kind };
}

function optionalString(value: unknown, name: string): string | undefined {
  return value === undefined ? undefined : assertString(value, name);
}

function optionalNonEmptyString(value: unknown, name: string): string | undefined {
  return value === undefined ? undefined : assertNonEmptyString(value, name);
}

function optionalNullableNonEmptyString(value: unknown, name: string): string | undefined {
  return value === undefined || value === null ? undefined : assertNonEmptyString(value, name);
}

function optionalBoolean(value: unknown, name: string): boolean | undefined {
  return value === undefined ? undefined : assertBoolean(value, name);
}

function optionalStringArray(value: unknown, name: string): string[] | undefined {
  return value === undefined ? undefined : assertStringArray(value, name);
}

function optionalPositiveInteger(value: unknown, name: string): number | undefined {
  return value === undefined ? undefined : assertPositiveInteger(value, name);
}

function optionalStdin(value: unknown, name: string): Uint8Array | undefined {
  if (value === undefined) return undefined;
  return typeof value === "string" ? new TextEncoder().encode(value) : assertUint8Array(value, name);
}

function assertExitCode(value: unknown, name: string): number {
  return assertIntegerInRange(value, name, -2_147_483_648, 2_147_483_647);
}

function assertIntegerInRange(value: unknown, name: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new TypeError(`${name} must be a safe integer`);
  }
  if (value < min || value > max) {
    throw new RangeError(`${name} must be between ${min} and ${max}`);
  }
  return value;
}

function unixDate(value: number): Date {
  return new Date(value * 1000);
}

function optionalUnixDate(value: number | null | undefined): Date | undefined {
  return value == null ? undefined : unixDate(value);
}
