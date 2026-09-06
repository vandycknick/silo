import type {
  NativeExecutionEvent,
  NativeForward,
  NativeExecutionOptionsInput,
  NativeExecutionResult,
  NativeImageDetail,
  NativeImageHandle,
  NativeImageLayerDetail,
  NativeImagePruneReport,
  NativeImageSourceInput,
  NativeKeyValue,
  NativeMachineAgent,
  NativeMachineBootReport,
  NativeMachineData,
  NativeMachineProvisionReport,
  NativeMachineProvisionStepReport,
  NativeMachineRootfs,
  NativeMountInput,
  NativeNetworkData,
  NativeNetworkInput,
  NativeOciImageConfig,
  NativeRuntimeOpenOptions,
  NativeSshShellOptionsInput,
} from "./internal/napi.js";
import type {
  ExecutionOptions,
  Forward,
  ForwardEndpoint,
  GuestPublish,
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
  MachineAgent,
  MachineBootMode,
  MachineBootReport,
  MachineRetention,
  MachineProvisionFailurePolicy,
  MachineProvisionReport,
  MachineProvisionStatus,
  MachineProvisionStepReport,
  MachineProvisionStepStatus,
  MachineRootfs,
  Mount,
  Network,
  OciImageConfig,
  ProcessConfig,
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

function forwardEndpoint(value: unknown, name: string): ForwardEndpoint {
  const text = assertNonEmptyString(value, name);
  if (/[\0\r\n]/u.test(text)) throw new TypeError(`${name} must not contain NUL, CR, or LF`);
  if (text.startsWith("host:")) return `host:${text.slice(5)}`;
  if (text.startsWith("guest:")) return `guest:${text.slice(6)}`;
  if (text.startsWith("vsock:")) return `vsock:${text.slice(6)}`;
  throw new TypeError(`${name} must start with host:, guest:, or vsock:`);
}

function forwardFromValue(value: unknown, name: string): Forward {
  const record = assertRecord(value, name);
  const mode = optionalNullableString(record.mode, `${name}.mode`);
  if (mode !== undefined && !/^0[0-7]{3}$/u.test(mode)) throw new TypeError(`${name}.mode must be a four-digit octal permission string`);
  return {
    name: optionalNullableString(record.name, `${name}.name`),
    listen: forwardEndpoint(record.listen, `${name}.listen`),
    connect: forwardEndpoint(record.connect, `${name}.connect`),
    mode,
  };
}

export function forwardsToNative(forwards: Forward[]): NativeForward[] {
  if (!Array.isArray(forwards)) throw new TypeError("forwards must be an array");
  return forwards.map((forward, index) => forwardFromValue(forward, `forwards[${index}]`));
}

function guestPublish(value: unknown): GuestPublish | undefined {
  if (value == null) return undefined;
  const record = assertRecord(value, "network.publish");
  if (record.bind !== "loopback" && record.bind !== "any") throw new TypeError("network.publish.bind must be loopback or any");
  return { bind: record.bind };
}

export function networkToNative(network: Network): NativeNetworkInput {
  const record = assertRecord(network, "network");
  const kind = assertString(record.kind, "network.kind");
  switch (kind) {
    case "private":
      return {
        kind,
        policyJson: optionalNonEmptyString(record.policyJson, "network.policyJson"),
        ...(record.publish == null ? {} : { publish: guestPublish(record.publish) }),
      };
    case "none":
      if (record.publish != null) throw new TypeError("guest publication requires a private network");
      return { kind };
    case "named":
      if (record.publish != null) throw new TypeError("guest publication requires a private network");
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
      return { kind, path: assertNonEmptyString(record.path, "source.path") };
    default:
      throw new TypeError("source.kind must be oci or disk");
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
    retention: machineRetentionFromNative(data.retention),
    process: processConfigFromNative(data.process),
    templateName: data.templateName ?? undefined,
    agentMode: optionalMachineAgentFromNative(data.configuredAgent),
    rootfs: machineRootfsFromNative(data.rootfs),
    rootDiskSize: data.rootDiskSize ?? undefined,
    labels: keyValuesToMap(data.labels),
    metadata: keyValuesToMap(data.metadata),
    network: networkFromNative(data.network),
    forwards: data.forwards.map((forward, index) => forwardFromValue(forward, `forwards[${index}]`)),
    vsock: data.vsock == null ? undefined : { enabled: data.vsock.enabled, uds: data.vsock.uds ?? undefined },
    agent: machineAgentFromNative({ mode: data.agentMode, path: data.agentPath }),
    status: {
      kind: data.status.kind,
      ready: data.status.ready ?? undefined,
      guestReady: data.status.guestReady ?? undefined,
      message: data.status.message ?? undefined,
    },
    bootReport: machineBootReportFromNative(data.bootReport),
    provisionReport: machineProvisionReportFromNative(data.provisionReport),
    startedAt: optionalUnixDate(data.startedAt),
    lastError: data.lastError ?? undefined,
    updatedAt: unixDate(data.updatedAt),
  };
}

function machineBootReportFromNative(
  report: NativeMachineBootReport | null | undefined,
): MachineBootReport | undefined {
  if (report == null) return undefined;
  return {
    mode: machineBootModeFromNative(report.mode),
    requestedInit: report.requestedInit ?? undefined,
    handoffInitPath: report.handoffInitPath ?? undefined,
    probedInitPaths: report.probedInitPaths,
    agentPath: report.agentPath ?? undefined,
    agentPid: report.agentPid,
    agentIsPid1: report.agentIsPid1,
    message: report.message ?? undefined,
  };
}

function machineBootModeFromNative(mode: NativeMachineBootReport["mode"]): MachineBootMode {
  switch (mode) {
    case "unspecified":
    case "standard":
    case "agent-pid1":
    case "init-child":
      return mode;
    default:
      return "unknown";
  }
}

function machineProvisionReportFromNative(
  report: NativeMachineProvisionReport | null | undefined,
): MachineProvisionReport | undefined {
  if (report == null) return undefined;
  return {
    status: machineProvisionStatusFromNative(report.status),
    startedAt: unixMillisecondsDate(report.startedUnixMs),
    finishedAt: unixMillisecondsDate(report.finishedUnixMs),
    durationMs: report.durationMs,
    steps: report.steps.map(machineProvisionStepReportFromNative),
    message: report.message ?? undefined,
  };
}

function machineProvisionStatusFromNative(
  status: NativeMachineProvisionReport["status"],
): MachineProvisionStatus {
  switch (status) {
    case "unspecified":
    case "succeeded":
    case "degraded":
    case "skipped":
    case "failed-boot":
      return status;
    default:
      return "unknown";
  }
}

function machineProvisionStepReportFromNative(
  report: NativeMachineProvisionStepReport,
): MachineProvisionStepReport {
  return {
    id: report.id,
    status: machineProvisionStepStatusFromNative(report.status),
    failurePolicy: machineProvisionFailurePolicyFromNative(report.failurePolicy),
    changed: report.changed,
    backend: report.backend ?? undefined,
    durationMs: report.durationMs,
    message: report.message ?? undefined,
    errorChain: report.errorChain ?? undefined,
  };
}

function machineProvisionStepStatusFromNative(
  status: NativeMachineProvisionStepReport["status"],
): MachineProvisionStepStatus {
  switch (status) {
    case "unspecified":
    case "succeeded":
    case "failed":
    case "skipped":
    case "unsupported":
      return status;
    default:
      return "unknown";
  }
}

function machineProvisionFailurePolicyFromNative(
  policy: NativeMachineProvisionStepReport["failurePolicy"],
): MachineProvisionFailurePolicy {
  switch (policy) {
    case "unspecified":
    case "best-effort":
    case "fail-boot":
      return policy;
    default:
      return "unknown";
  }
}

function machineRetentionFromNative(retention: MachineRetention): MachineRetention {
  return retention;
}

function processConfigFromNative(process: NativeMachineData["process"]): ProcessConfig {
  return {
    entrypoint: optionalNativeStringArray(process.entrypoint, "machine process entrypoint"),
    command: optionalNativeStringArray(process.command, "machine process command"),
    environment: keyValuesToMap(process.environment),
    workingDirectory: process.workingDirectory,
    user: optionalNullableString(process.user, "machine process user"),
  };
}

function optionalMachineAgentFromNative(agent: NativeMachineAgent | null | undefined): MachineAgent | undefined {
  return agent == null ? undefined : machineAgentFromNative(agent);
}

function machineAgentFromNative(agent: NativeMachineAgent): MachineAgent {
  switch (agent.mode) {
    case "default":
      return { mode: "default" };
    case "custom":
      return { mode: "custom", path: assertString(agent.path, "machine agent path") };
    case "disabled":
      return { mode: "disabled" };
    case "unknown":
      return { mode: "unknown" };
  }
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
    requestedReference: handle.requestedReference,
    selectedReference: handle.selectedReference,
    selectedManifestDigest: handle.selectedManifestDigest,
    configDigest: handle.configDigest,
    imageId: handle.imageId,
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
    config: ociImageConfigFromNative(detail.config),
    layers: detail.layers.map(imageLayerFromNative),
  };
}

function machineRootfsFromNative(rootfs: NativeMachineRootfs | null | undefined): MachineRootfs | undefined {
  if (rootfs == null) return undefined;
  return {
    sourceKind: rootfs.sourceKind,
    requestedReference: rootfs.requestedReference,
    selectedReference: rootfs.selectedReference ?? undefined,
    selectedManifestDigest: rootfs.selectedManifestDigest ?? undefined,
    configDigest: rootfs.configDigest ?? undefined,
    imageId: rootfs.imageId ?? undefined,
    rootDiskPath: rootfs.rootDiskPath,
    rootDiskSizeBytes: rootfs.rootDiskSizeBytes,
    createdAt: unixDate(rootfs.createdAt),
  };
}

function ociImageConfigFromNative(config: NativeOciImageConfig): OciImageConfig {
  return {
    entrypoint: optionalNativeStringArray(config.entrypoint, "image config entrypoint"),
    cmd: optionalNativeStringArray(config.cmd, "image config cmd"),
    env: optionalNativeStringArray(config.env, "image config env"),
    workingDir: optionalNullableString(config.workingDir, "image config workingDir"),
    user: optionalNullableString(config.user, "image config user"),
    labels: optionalNativeKeyValuesToMap(config.labels),
    stopSignal: optionalNullableString(config.stopSignal, "image config stopSignal"),
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
    const publish = guestPublish(network.publish);
    return { kind: "private", ...(policyJson === undefined ? {} : { policyJson }), ...(publish === undefined ? {} : { publish }) };
  }
  if (network.kind === "named") {
    return { kind: "named", name: network.name ?? "" };
  }
  return { kind: network.kind };
}

function optionalString(value: unknown, name: string): string | undefined {
  return value === undefined ? undefined : assertString(value, name);
}

function optionalNullableString(value: unknown, name: string): string | undefined {
  return value == null ? undefined : assertString(value, name);
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

function optionalNativeStringArray(value: string[] | null | undefined, name: string): string[] | undefined {
  return value == null ? undefined : assertStringArray(value, name);
}

function optionalNativeKeyValuesToMap(values: NativeKeyValue[] | null | undefined): KeyValueMap | undefined {
  return values == null ? undefined : keyValuesToMap(values);
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

function unixMillisecondsDate(value: number): Date {
  return new Date(value);
}

function optionalUnixDate(value: number | null | undefined): Date | undefined {
  return value == null ? undefined : unixDate(value);
}
