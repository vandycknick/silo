import { assertNonEmptyString } from "./validation.js";

/** String-keyed values used for labels, metadata, and environment variables. */
export type KeyValueMap = Record<string, string>;

/**
 * Options used when opening a {@link Runtime}.
 *
 * `libvm` resolves one complete runtime set, including default boot assets.
 * `PATH` is disabled unless `SILO_ASSET_DIR` explicitly selects a complete
 * asset set.
 */
export interface RuntimeOpenOptions {
  /** Root directory for persistent state. */
  dataRoot?: string;
  /** Runtime directory for sockets and transient files. */
  runRoot?: string;
  /** Image cache directory. */
  imageRoot?: string;
  /** Explicit `vmmon` override. Remaining components use centralized discovery. */
  vmmonPath?: string;
}

/** Source used to materialize a machine root disk during `MachineBuilder.create()`. */
export type ImageSource =
  /** Pull and materialize an OCI image reference. */
  | { kind: "oci"; reference: string }
  /** Clone/copy an existing local disk image into the machine. */
  | { kind: "disk"; path: string };

/** Constructors for explicit machine image sources. */
export const ImageSource = {
  /** Create an OCI image source. Strings passed to `.image(...)` use this meaning too. */
  oci(reference: string): ImageSource {
    return { kind: "oci", reference: assertNonEmptyString(reference, "reference") };
  },
  /** Create a local disk image source. */
  disk(path: string): ImageSource {
    return { kind: "disk", path: assertNonEmptyString(path, "path") };
  },
};

/** Additional disk mounted into the guest. */
export interface Mount {
  /** Host path to mount. */
  source: string;
  /** Guest mount tag. */
  tag: string;
  /** Mount read-only when true. Defaults to false. */
  readOnly?: boolean;
}

/** Inspectable machine network attachment data. Configure networking with `MachineBuilder.network(...)`. */
export type Network =
  /** Private NAT-backed network, optionally constrained by canonical `NetworkPolicy` JSON. */
  | { kind: "private"; policyJson?: string; publish?: GuestPublish }
  /** No network attachment. */
  | { kind: "none" }
  /** Attach to a named network. */
  | { kind: "named"; name: string }
  /** Inspection-only fallback for network kinds this SDK does not know yet. */
  | { kind: "unknown" };

/** Options for a structured guest process started by `exec`, `spawn`, or `shell`. */
export interface ExecutionOptions {
  /** Additional argv values appended to the command. */
  args?: string[];
  /** Guest working directory. */
  cwd?: string;
  /** Guest user. */
  user?: string;
  /** Extra guest environment variables. */
  env?: KeyValueMap;
  /** Command timeout in seconds. */
  timeout?: number;
  /** Bytes or UTF-8 text sent to input. Pipe mode then receives EOF; PTYs do not. */
  stdin?: Uint8Array | string;
  /** Open a writable stdin pipe. Mutually exclusive with `stdin`. */
  pipeStdin?: boolean;
  /** Request a guest PTY for the command. */
  tty?: boolean;
}

/** Options for the SSH-only interactive guest shell. */
export interface SshShellOptions {
  /** Guest working directory. */
  cwd?: string;
  /** Guest user. */
  user?: string;
  /** Extra guest environment variables. */
  env?: KeyValueMap;
  /** Terminal type requested for the guest PTY. */
  term?: string;
  /** Docker-style detach key sequence, for example `ctrl-]` or `ctrl-p,ctrl-q`. */
  detachKeys?: string;
  /** Forward the host SSH agent into the guest shell. */
  forwardAgent?: boolean;
}

/** Selects one persisted machine log source. */
export type MachineLogSource = "monitor" | "serial" | "exec" | "network" | "networkAudit";

/** Options for reading persisted machine logs. */
export interface MachineLogOptions {
  /**
   * Continue after the snapshot until the reader closes the stream.
   * The stream remains attached while the machine is stopped and across later starts.
   */
  follow?: boolean;
}

/** Output channel associated with a machine log chunk. */
export type MachineLogOutput = "stdout" | "stderr";

/** Raw bytes read from a persisted machine log source. */
export interface MachineLogChunk {
  output: MachineLogOutput;
  /** Log bytes are preserved without text decoding. */
  data: Uint8Array;
}

/** Exact terminal result reported by the execution service. */
export type ExecutionResult =
  | { kind: "exited"; code?: number }
  | { kind: "signaled"; signal?: number }
  | { kind: "launch_failed"; reason: ExecutionLaunchFailureReason; message?: string }
  | { kind: "lost"; reason: ExecutionLostReason; message?: string };

export type ExecutionLaunchFailureReason =
  | "unspecified"
  | "command_not_found"
  | "invalid_process_spec"
  | "working_directory_not_found"
  | "working_directory_not_directory"
  | "invalid_identity"
  | "identity_not_found"
  | "permission_denied"
  | "spawn_failed"
  | "cancelled_before_start";

export type ExecutionLostReason =
  | "unspecified"
  | "agent_instance_replaced"
  | "agent_boot_replaced"
  | "agent_unavailable"
  | "guest_stream_lost"
  | "vm_stopped"
  | "vmmon_exited";

/** Exit status reported by an SSH shell attachment. */
export interface SshExitStatus {
  code: number;
  success: boolean;
}

/** Current machine lifecycle status. */
export interface MachineStatus {
  kind: "stopped" | "starting" | "running" | "stopping" | "error" | "unknown";
  /** True when the machine satisfies its configured readiness policy. */
  ready?: boolean;
  /** True when the managed guest agent has registered. Present for running machines. */
  guestReady?: boolean;
  /** Human-readable status detail when available. */
  message?: string;
}

/** Retention policy recorded for a machine. */
export type MachineRetention = "persistent" | "ephemeral" | "unknown";

/** Agent executable selection recorded for a machine. */
export type MachineAgent =
  | { mode: "default" }
  | { mode: "custom"; path: string }
  | { mode: "disabled" }
  /** Inspection-only fallback for agent selections this SDK does not know yet. */
  | { mode: "unknown" };

/** Guest boot mode reported by the managed guest agent. */
export type MachineBootMode = "unspecified" | "standard" | "agent-pid1" | "init-child" | "unknown";

/** Latest managed guest boot report, when the guest agent registered one. */
export interface MachineBootReport {
  mode: MachineBootMode;
  requestedInit?: string;
  handoffInitPath?: string;
  probedInitPaths: string[];
  agentPath?: string;
  agentPid: number;
  agentIsPid1: boolean;
  message?: string;
}

/** Overall result reported by managed guest provisioning. */
export type MachineProvisionStatus = "unspecified" | "succeeded" | "degraded" | "skipped" | "failed-boot" | "unknown";

/** Result reported by one managed guest provisioning step. */
export type MachineProvisionStepStatus = "unspecified" | "succeeded" | "failed" | "skipped" | "unsupported" | "unknown";

/** Failure policy applied to one managed guest provisioning step. */
export type MachineProvisionFailurePolicy = "unspecified" | "best-effort" | "fail-boot" | "unknown";

/** Result reported by one managed guest provisioning step. */
export interface MachineProvisionStepReport {
  id: string;
  status: MachineProvisionStepStatus;
  failurePolicy: MachineProvisionFailurePolicy;
  changed: boolean;
  backend?: string;
  durationMs: number;
  message?: string;
  errorChain?: string;
}

/** Latest managed guest provisioning report, when the guest agent registered one. */
export interface MachineProvisionReport {
  status: MachineProvisionStatus;
  startedAt: Date;
  finishedAt: Date;
  durationMs: number;
  steps: MachineProvisionStepReport[];
  message?: string;
}

/** Durable desired process settings. They do not configure current execution APIs. */
export interface ProcessConfig {
  /** OCI entrypoint. Unset and explicitly empty values remain distinct. */
  entrypoint?: string[];
  /** OCI command. Unset and explicitly empty values remain distinct. */
  command?: string[];
  /** Explicit process environment, including an explicitly empty map. */
  environment: KeyValueMap;
  /** Process working directory. */
  workingDirectory: string;
  /** Optional OCI-style user selector. */
  user?: string;
}

/** Snapshot of persisted machine config plus runtime state. */
export type PublishBind = "loopback" | "any";

export interface GuestPublish { bind: PublishBind }

/** Endpoint grammar validated by the native layer, with literal IP addresses only. */
export type ForwardEndpoint = `host:${string}` | `guest:${string}` | `vsock:${string}`;

/** Machine-scoped forward. Relative host Unix paths resolve inside the runtime directory. */
export interface Forward {
  name?: string;
  listen: ForwardEndpoint;
  connect: ForwardEndpoint;
  /** Four-digit octal Unix listener mode, default "0600". */
  mode?: string;
}

export interface VsockConfig {
  enabled: boolean;
  /** Omitted for the default mux filename. */
  uds?: string;
}

export interface MachineData {
  id: string;
  name: string;
  machineDir: string;
  createdAt: Date;
  modifiedAt: Date;
  imageRef: string;
  retention: MachineRetention;
  process: ProcessConfig;
  /** Selected machine template, when one was used. */
  templateName?: string;
  /** Explicit agent mode selection, when set independently of guest settings. */
  agentMode?: MachineAgent;
  /** Durable source identity and local root disk pin, when available. */
  rootfs?: MachineRootfs;
  rootDiskSize?: number;
  labels: KeyValueMap;
  metadata: KeyValueMap;
  network: Network;
  forwards: Forward[];
  vsock?: VsockConfig;
  /** Guest agent configuration currently used by machine startup. */
  agent: MachineAgent;
  status: MachineStatus;
  /** Latest managed guest boot report, when the guest registered one. */
  bootReport?: MachineBootReport;
  /** Latest managed guest provisioning report, when the guest registered one. */
  provisionReport?: MachineProvisionReport;
  startedAt?: Date;
  lastError?: string;
  updatedAt: Date;
}

/** Runtime image pull policy. */
export type ImagePullPolicy = "ifMissing" | "always" | "never";

/** Lightweight image cache handle with the OCI identity selected for this host. */
export interface ImageHandle {
  /** OCI reference requested by the caller. */
  requestedReference: string;
  /** Digest-pinned OCI reference selected for the host platform. */
  selectedReference: string;
  /** Immutable OCI manifest digest selected for the reference. */
  selectedManifestDigest: string;
  /** Digest of the OCI image configuration document. */
  configDigest: string;
  imageId: string;
  platform: {
    os: string;
    architecture: string;
    variant?: string;
  };
  size?: number;
  createdAt: Date;
  updatedAt: Date;
  lastUsedAt?: Date;
}

/** Full image detail, including layer metadata. */
export interface ImageDetail {
  handle: ImageHandle;
  /** Inspection-only OCI image configuration metadata. */
  config: OciImageConfig;
  layers: ImageLayerDetail[];
}

/** OCI image configuration retained with a cached image. */
export interface OciImageConfig {
  /** OCI `Entrypoint` metadata. It does not configure guest execution APIs. */
  entrypoint?: string[];
  /** OCI `Cmd` metadata. */
  cmd?: string[];
  /** OCI `Env` metadata. */
  env?: string[];
  /** OCI `WorkingDir` metadata. */
  workingDir?: string;
  /** OCI `User` metadata. */
  user?: string;
  /** OCI `Labels` metadata. */
  labels?: KeyValueMap;
  /** OCI `StopSignal` metadata. It does not change `Machine.stop()`. */
  stopSignal?: string;
}

/** Durable source identity and machine-local root disk pin. */
export interface MachineRootfs {
  sourceKind: "oci" | "disk";
  requestedReference: string;
  selectedReference?: string;
  selectedManifestDigest?: string;
  configDigest?: string;
  imageId?: string;
  rootDiskPath: string;
  rootDiskSizeBytes: number;
  createdAt: Date;
}

/** OCI layer metadata. */
export interface ImageLayerDetail {
  blobDigest: string;
  diffId: string;
  mediaType: string;
  compressedSize?: number;
  uncompressedSize?: number;
  position: number;
}

/** Summary returned by `runtime.images().prune()`. */
export interface ImagePruneReport {
  referencesRemoved: number;
  artifactsRemoved: number;
  bytesRemoved: number;
}
