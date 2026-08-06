import type {
  NativeExecutionEvent,
  NativeExecutionOptionsInput,
  NativeExecutionResult,
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
  NativeSshShellOptionsInput,
} from "./internal/napi.js";
import type {
  ExecutionOptions,
  ExecutionLaunchFailureReason,
  ExecutionLostReason,
  ExecutionResult,
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
  SshShellOptions,
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
    vmmonPath: optionalNonEmptyString(record.vmmonPath, "options.vmmonPath"),
  };
}

export function mapToKeyValues(value?: unknown): NativeKeyValue[] | undefined {
  if (!value) return undefined;
  const record = assertRecord(value, "value");
  return Object.entries(record).map(([key, entryValue]) => ({ key, value: assertString(entryValue, `value.${key}`) }));
}

export function keyValuesToMap(values: NativeKeyValue[]): KeyValueMap {
  return Object.fromEntries(values.map(({ key, value }) => [key, value]));
}

export function mountsToNative(mounts: Mount[]): NativeMountInput[] {
  if (!Array.isArray(mounts)) throw new TypeError("mounts must be an array");
  return mounts.map((mount, index) => {
    const record = assertRecord(mount, `mounts[${index}]`);
    return {
      source: assertNonEmptyString(record.source, `mounts[${index}].source`),
      tag: assertNonEmptyString(record.tag, `mounts[${index}].tag`),
      readOnly: optionalBoolean(record.readOnly, `mounts[${index}].readOnly`),
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
        policyJson: optionalNonEmptyString(record.policyJson, "network.policyJson"),
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
    agent: {
      mode: data.agentMode,
      path: data.agentPath ?? undefined,
    },
    status: {
      kind: data.status.kind,
      ready: data.status.ready ?? undefined,
      guestReady: data.status.guestReady ?? undefined,
      message: data.status.message ?? undefined,
    },
    startedAt: optionalUnixDate(data.startedAt),
    lastError: data.lastError ?? undefined,
    updatedAt: unixDate(data.updatedAt),
  };
}

export function executionOptionsToNative(options?: ExecutionOptions): NativeExecutionOptionsInput | undefined {
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
    env: record.env === undefined ? undefined : mapToKeyValues(record.env),
    timeout: optionalPositiveInteger(record.timeout, "options.timeout"),
    stdin,
    pipeStdin,
    tty: optionalBoolean(record.tty, "options.tty"),
  };
}

export function sshShellOptionsToNative(options?: SshShellOptions): NativeSshShellOptionsInput | undefined {
  if (!options) return undefined;
  const record = assertRecord(options, "options");
  return {
    cwd: optionalString(record.cwd, "options.cwd"),
    user: optionalString(record.user, "options.user"),
    env: record.env === undefined ? undefined : mapToKeyValues(record.env),
    term: optionalString(record.term, "options.term"),
    detachKeys: optionalString(record.detachKeys, "options.detachKeys"),
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

export type ExecutionEvent =
  | { kind: "accepted" }
  | { kind: "started" }
  | { kind: "stdout"; data: Uint8Array }
  | { kind: "stderr"; data: Uint8Array }
  | { kind: "terminal_output"; data: Uint8Array }
  | ExecutionResult;

export function executionEventFromNative(event: NativeExecutionEvent): ExecutionEvent {
  switch (event.kind) {
    case "stdout":
    case "stderr":
    case "terminal_output":
      return { kind: event.kind, data: assertUint8Array(event.data, `exec event ${event.kind}.data`) };
    case "exited":
    case "signaled":
    case "launch_failed":
    case "lost":
      return executionResultFromFields(event.kind, event.code, event.signal, event.reason, event.message);
    case "accepted":
    case "started":
      return { kind: event.kind };
  }
}

export function executionResultFromNative(result: NativeExecutionResult): ExecutionResult {
  return executionResultFromFields(result.kind, result.code, result.signal, result.reason, result.message);
}

function executionResultFromFields(
  kind: ExecutionResult["kind"],
  code: number | null | undefined,
  signal: number | null | undefined,
  reason: string | null | undefined,
  message: string | null | undefined,
): ExecutionResult {
  switch (kind) {
    case "exited":
      return { kind: "exited", code: code === undefined || code === null ? undefined : assertExitCode(code, "execution result code") };
    case "signaled":
      return { kind: "signaled", signal: signal === undefined || signal === null ? undefined : assertPositiveInteger(signal, "execution result signal") };
    case "launch_failed":
      return {
        kind: "launch_failed",
        reason: executionLaunchFailureReason(reason),
        message: message === undefined || message === null ? undefined : assertString(message, "execution result message"),
      };
    case "lost":
      return {
        kind: "lost",
        reason: executionLostReason(reason),
        message: message === undefined || message === null ? undefined : assertString(message, "execution result message"),
      };
  }
}

function executionLaunchFailureReason(value: unknown): ExecutionLaunchFailureReason {
  const reason = assertString(value, "execution launch failure reason");
  switch (reason) {
    case "unspecified":
    case "command_not_found":
    case "invalid_process_spec":
    case "working_directory_not_found":
    case "working_directory_not_directory":
    case "invalid_identity":
    case "identity_not_found":
    case "permission_denied":
    case "spawn_failed":
    case "cancelled_before_start":
      return reason;
    default:
      throw new TypeError(`unsupported execution launch failure reason ${JSON.stringify(reason)}`);
  }
}

function executionLostReason(value: unknown): ExecutionLostReason {
  const reason = assertString(value, "execution lost reason");
  switch (reason) {
    case "unspecified":
    case "agent_instance_replaced":
    case "agent_boot_replaced":
    case "agent_unavailable":
    case "guest_stream_lost":
    case "vm_stopped":
    case "vmmon_exited":
      return reason;
    default:
      throw new TypeError(`unsupported execution lost reason ${JSON.stringify(reason)}`);
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
    const policyJson = optionalNullableNonEmptyString(network.policyJson, "network.policyJson");
    return policyJson === undefined ? { kind: "private" } : { kind: "private", policyJson };
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
