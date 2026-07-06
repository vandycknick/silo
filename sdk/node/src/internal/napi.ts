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
  defaultKernel?: string;
  defaultInitramfs?: string;
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
  rootDiskSize(value: number): void;
  nestedVirtualization(enabled: boolean): void;
  rosetta(enabled: boolean): void;
  userdata(userdata: string): void;
  disks(disks: string[]): void;
  mounts(mounts: NativeMountInput[]): void;
  network(network: NativeNetworkInput): void;
  create(): Promise<NativeMachine>;
}

export interface NativeMachine {
  id(): string;
  inspect(): Promise<NativeMachineData>;
  start(): Promise<NativeMachineData>;
  stop(): Promise<NativeMachineData>;
  remove(): Promise<void>;
  exec(program: string, args?: string[], options?: NativeExecOptionsInput): Promise<NativeExecOutput>;
  spawn(program: string, args?: string[], options?: NativeExecOptionsInput): Promise<NativeExecHandle>;
  shell(script: string, options?: NativeExecOptionsInput): Promise<NativeExecOutput>;
  attach(program: string, args?: string[], options?: NativeAttachOptionsInput): Promise<NativeExitStatus>;
  attachShell(options?: NativeAttachOptionsInput): Promise<NativeExitStatus>;
}

export interface NativeImages {
  pull(reference: string, policy?: string): Promise<NativeImageHandle>;
  get(reference: string): Promise<NativeImageHandle | null>;
  list(): Promise<NativeImageHandle[]>;
  inspect(reference: string): Promise<NativeImageDetail | null>;
  remove(reference: string, force?: boolean): Promise<void>;
  prune(): Promise<NativeImagePruneReport>;
}

export interface NativeExecHandle {
  recv(): Promise<NativeExecEvent | null>;
  takeStdin(): NativeExecSink | null;
  wait(): Promise<NativeExitStatus>;
  collect(): Promise<NativeExecOutput>;
  signal(signal: number): Promise<void>;
  kill(): Promise<void>;
  resize(rows: number, cols: number): Promise<void>;
}

export interface NativeExecSink {
  write(data: Uint8Array): Promise<void>;
  close(): void;
}

export interface NativeImageSourceInput {
  kind: "oci" | "disk" | "tar";
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

export interface NativeNetworkInput {
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

export interface NativeExecOptionsInput {
  args?: string[];
  cwd?: string;
  user?: string;
  env?: NativeKeyValue[];
  timeout?: number;
  stdin?: Uint8Array;
  pipeStdin?: boolean;
  tty?: boolean;
  forwardAgent?: boolean;
}

export interface NativeAttachOptionsInput {
  args?: string[];
  cwd?: string;
  user?: string;
  env?: NativeKeyValue[];
  term?: string;
  detachKeys?: string;
  forwardAgent?: boolean;
}

export interface NativeMachineData {
  id: string;
  name: string;
  machineDir: string;
  createdAt: number;
  modifiedAt: number;
  imageRef: string;
  rootDiskSize?: number | null;
  labels: NativeKeyValue[];
  metadata: NativeKeyValue[];
  network: NativeNetworkData;
  status: NativeMachineStatus;
  startedAt?: number | null;
  lastError?: string | null;
  updatedAt: number;
}

export interface NativeMachineStatus {
  kind: "stopped" | "starting" | "running" | "stopping" | "error" | "unknown";
  guestReady?: boolean | null;
  message?: string | null;
}

export interface NativeNetworkData {
  kind: "private" | "none" | "named" | "unknown";
  name?: string | null;
  policyJson?: string | null;
}

export interface NativeExitStatus {
  code: number;
  success: boolean;
}

export interface NativeExecOutput {
  status: NativeExitStatus;
  stdout: Uint8Array;
  stderr: Uint8Array;
}

export interface NativeExecEvent {
  kind: "started" | "stdout" | "stderr" | "exited" | "failed" | "stdin_error";
  data?: Uint8Array | null;
  code?: number | null;
  message?: string | null;
}

export interface NativeImageHandle {
  reference: string;
  imageId: string;
  manifestDigest?: string | null;
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
  layers: NativeImageLayerDetail[];
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
