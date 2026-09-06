const nativeAddonPath = "../../native/index.cjs";

const nativeModule = (await import(nativeAddonPath)) as {
  default?: unknown;
} & Record<string, unknown>;

export const napi = (nativeModule.default ?? nativeModule) as NativeBindings;

export interface NativeBindings {
  openRuntime(options?: NativeRuntimeOpenOptions): Promise<NativeRuntime>;
  buildNetworkPolicy(input: NativeNetworkPolicyInput): string;
}

export interface NativeRuntimeOpenOptions {
  dataRoot?: string;
  runRoot?: string;
  imageRoot?: string;
  vmmonPath?: string;
}

export interface NativeRuntime {
  machine(): NativeMachineBuilder;
  images(): NativeImages;
  getMachine(reference: string): Promise<NativeMachine>;
  listMachines(): Promise<NativeMachine[]>;
}

export interface NativeMachineBuilder {
  image(reference: string): void;
  imageSource(source: NativeImageSourceInput): void;
  name(name: string): void;
  label(key: string, value: string): void;
  labels(labels: NativeKeyValue[]): void;
  metadataEntry(key: string, value: string): void;
  metadata(metadata: NativeKeyValue[]): void;
  cpus(cpus: number): void;
  memory(value: number): void;
  kernel(path: string): void;
  initramfs(path: string): void;
  agent(path?: string): void;
  rootDiskSize(value: number): void;
  nestedVirtualization(enabled: boolean): void;
  rosetta(enabled: boolean): void;
  userdata(userdata: string): void;
  disks(disks: string[]): void;
  mounts(mounts: NativeMountInput[]): void;
  forwards(forwards: NativeForward[]): void;
  vsock(enabled: boolean): void;
  network(network: NativeNetworkInput): void;
  create(): Promise<NativeMachine>;
}

export interface NativeMachine {
  id(): string;
  inspect(): Promise<NativeMachineData>;
  start(): Promise<NativeMachineData>;
  stop(): Promise<NativeMachineData>;
  remove(): Promise<void>;
  exec(program: string, args?: string[], options?: NativeExecutionOptionsInput): Promise<NativeExecutionOutput>;
  spawn(program: string, args?: string[], options?: NativeExecutionOptionsInput): Promise<NativeExecutionSession>;
  shell(script: string, options?: NativeExecutionOptionsInput): Promise<NativeExecutionOutput>;
  attach(program: string, args?: string[], options?: NativeExecutionOptionsInput): Promise<NativeExecutionResult>;
  attachShell(options?: NativeSshShellOptionsInput): Promise<NativeSshExitStatus>;
  logs(source: NativeMachineLogSource, options?: NativeMachineLogOptionsInput): Promise<NativeMachineLogHandle>;
}

export interface NativeImages {
  pull(reference: string, policy?: string): Promise<NativeImageHandle>;
  get(reference: string): Promise<NativeImageHandle | null>;
  list(): Promise<NativeImageHandle[]>;
  inspect(reference: string): Promise<NativeImageDetail | null>;
  remove(reference: string, force?: boolean): Promise<void>;
  prune(): Promise<NativeImagePruneReport>;
}

export interface NativeExecutionSession {
  recv(): Promise<NativeExecutionEvent | null>;
  stdin(): NativeExecutionStdin | null;
  wait(): Promise<NativeExecutionResult>;
  collect(): Promise<NativeExecutionOutput>;
  signal(signal: number): Promise<void>;
  resizePty(rows: number, cols: number): Promise<void>;
  closeRequests(): void;
  cancel(): void;
}

export interface NativeExecutionStdin {
  write(data: Uint8Array): Promise<void>;
  close(): Promise<void>;
}

export interface NativeMachineLogHandle {
  recv(): Promise<NativeMachineLogChunk | null>;
  close(): void;
}

export interface NativeImageSourceInput {
  kind: "oci" | "disk";
  reference?: string;
  path?: string;
}

export interface NativeKeyValue {
  key: string;
  value: string;
}

export interface NativeMountInput {
  source: string;
  tag: string;
  readOnly?: boolean;
}

export interface NativeForward {
  name?: string | null;
  listen: string;
  connect: string;
  mode?: string | null;
}

export interface NativeVsockConfig {
  enabled: boolean;
  uds?: string | null;
}

export interface NativeGuestPublish { bind: string }

export interface NativeNetworkInput {
  publish?: NativeGuestPublish;
  kind: "private" | "none" | "named";
  name?: string;
  policyJson?: string;
}

export interface NativeNetworkPolicyInput {
  defaultAction?: "allow" | "deny";
  metadata?: NativeKeyValue[];
  audit?: NativeNetworkAuditInput;
  endpoints?: NativeNetworkEndpointInput[];
  credentials?: NativeNetworkCredentialInput[];
  rules?: NativeNetworkRuleInput[];
  tailscale?: NativeTailscaleTunnelInput[];
  forwards?: NativeNetworkForwardInput[];
}

export interface NativeNetworkAuditInput {
  bodyBufferBytes?: number;
  bodyStorageBytes?: number;
}

export interface NativeNetworkPortRangeInput {
  start: number;
  end?: number;
}

export interface NativeNetworkEndpointInput {
  name: string;
  kind?: "ip" | "http" | "https";
  sourceCidrs?: string[];
  destinationCidrs?: string[];
  protocol?: "any" | "tcp" | "udp";
  ports?: NativeNetworkPortRangeInput[];
  hosts?: string[];
}

export interface NativeNetworkCredentialInput {
  name: string;
  kind?: "basic_auth" | "bearer_token" | "header_token" | "github_oauth" | "openai_codex_oauth" | "aws_credential";
  endpoint?: string;
  username?: string;
  header?: string;
  prefix?: string;
  idempotencyKey?: boolean;
  condition?: string;
}

export interface NativeNetworkRuleInput {
  name?: string;
  endpoints?: string[];
  credential?: string;
  condition?: string;
  tunnel?: string;
  priority?: number;
  disabled?: boolean;
  reason?: string;
  verdict?: "allow" | "deny";
}

export interface NativeTailscaleTunnelInput {
  name: string;
  tags?: string[];
  hostname?: string;
  controlUrl?: string;
}

export interface NativeNetworkForwardInput {
  name: string;
  kind?: "host" | "tailscale";
  target?: string;
  targetPort?: number;
  listen?: string;
  tunnel?: string;
}

export interface NativeExecutionOptionsInput {
  args?: string[];
  cwd?: string;
  user?: string;
  env?: NativeKeyValue[];
  timeout?: number;
  stdin?: Uint8Array;
  pipeStdin?: boolean;
  tty?: boolean;
}

export interface NativeSshShellOptionsInput {
  cwd?: string;
  user?: string;
  env?: NativeKeyValue[];
  term?: string;
  detachKeys?: string;
  forwardAgent?: boolean;
}

export type NativeMachineLogSource = "monitor" | "serial" | "exec" | "network" | "networkAudit";

export interface NativeMachineLogOptionsInput {
  follow?: boolean;
}

export interface NativeMachineLogChunk {
  output: "stdout" | "stderr";
  data: Uint8Array;
}

export interface NativeMachineData {
  id: string;
  name: string;
  machineDir: string;
  createdAt: number;
  modifiedAt: number;
  imageRef: string;
  retention: "persistent" | "ephemeral" | "unknown";
  process: NativeProcessConfig;
  templateName?: string | null;
  configuredAgent?: NativeMachineAgent | null;
  rootfs?: NativeMachineRootfs | null;
  rootDiskSize?: number | null;
  labels: NativeKeyValue[];
  metadata: NativeKeyValue[];
  network: NativeNetworkData;
  forwards: NativeForward[];
  vsock?: NativeVsockConfig | null;
  agentMode: "default" | "custom" | "disabled" | "unknown";
  agentPath?: string | null;
  status: NativeMachineStatus;
  bootReport?: NativeMachineBootReport | null;
  provisionReport?: NativeMachineProvisionReport | null;
  startedAt?: number | null;
  lastError?: string | null;
  updatedAt: number;
}

export interface NativeMachineBootReport {
  mode: "unspecified" | "standard" | "agent-pid1" | "init-child" | "unknown";
  requestedInit?: string | null;
  handoffInitPath?: string | null;
  probedInitPaths: string[];
  agentPath?: string | null;
  agentPid: number;
  agentIsPid1: boolean;
  message?: string | null;
}

export interface NativeMachineProvisionReport {
  status: "unspecified" | "succeeded" | "degraded" | "skipped" | "failed-boot" | "unknown";
  startedUnixMs: number;
  finishedUnixMs: number;
  durationMs: number;
  steps: NativeMachineProvisionStepReport[];
  message?: string | null;
}

export interface NativeMachineProvisionStepReport {
  id: string;
  status: "unspecified" | "succeeded" | "failed" | "skipped" | "unsupported" | "unknown";
  failurePolicy: "unspecified" | "best-effort" | "fail-boot" | "unknown";
  changed: boolean;
  backend?: string | null;
  durationMs: number;
  message?: string | null;
  errorChain?: string | null;
}

export interface NativeProcessConfig {
  entrypoint?: string[] | null;
  command?: string[] | null;
  environment: NativeKeyValue[];
  workingDirectory: string;
  user?: string | null;
}

export interface NativeMachineAgent {
  mode: "default" | "custom" | "disabled" | "unknown";
  path?: string | null;
}

export interface NativeMachineStatus {
  kind: "stopped" | "starting" | "running" | "stopping" | "error" | "unknown";
  ready?: boolean | null;
  guestReady?: boolean | null;
  message?: string | null;
}

export interface NativeMachineRootfs {
  sourceKind: "oci" | "disk";
  requestedReference: string;
  selectedReference?: string | null;
  selectedManifestDigest?: string | null;
  configDigest?: string | null;
  imageId?: string | null;
  rootDiskPath: string;
  rootDiskSizeBytes: number;
  createdAt: number;
}

export interface NativeNetworkData {
  publish?: NativeGuestPublish | null;
  kind: "private" | "none" | "named" | "unknown";
  name?: string | null;
  policyJson?: string | null;
}

export interface NativeExecutionResult {
  kind: "exited" | "signaled" | "launch_failed" | "lost";
  code?: number | null;
  signal?: number | null;
  reason?: string | null;
  message?: string | null;
}

export interface NativeSshExitStatus {
  code: number;
  success: boolean;
}

export interface NativeExecutionOutput {
  result: NativeExecutionResult;
  stdout: Uint8Array;
  stderr: Uint8Array;
  terminalOutput: Uint8Array;
}

export interface NativeExecutionEvent {
  kind: "accepted" | "started" | "stdout" | "stderr" | "terminal_output" | "exited" | "signaled" | "launch_failed" | "lost";
  data?: Uint8Array | null;
  code?: number | null;
  signal?: number | null;
  reason?: string | null;
  message?: string | null;
}

export interface NativeImageHandle {
  requestedReference: string;
  selectedReference: string;
  selectedManifestDigest: string;
  configDigest: string;
  imageId: string;
  platformOs: string;
  platformArchitecture: string;
  platformVariant?: string | null;
  sizeBytes?: number | null;
  createdAt: number;
  updatedAt: number;
  lastUsedAt?: number | null;
}

export interface NativeImageDetail {
  handle: NativeImageHandle;
  config: NativeOciImageConfig;
  layers: NativeImageLayerDetail[];
}

export interface NativeOciImageConfig {
  entrypoint?: string[] | null;
  cmd?: string[] | null;
  env?: string[] | null;
  workingDir?: string | null;
  user?: string | null;
  labels?: NativeKeyValue[] | null;
  stopSignal?: string | null;
}

export interface NativeImageLayerDetail {
  blobDigest: string;
  diffId: string;
  mediaType: string;
  compressedSizeBytes?: number | null;
  uncompressedSizeBytes?: number | null;
  position: number;
}

export interface NativeImagePruneReport {
  referencesRemoved: number;
  artifactsRemoved: number;
  bytesRemoved: number;
}
