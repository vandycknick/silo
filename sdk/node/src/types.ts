import { assertNonEmptyString } from "./validation.js";

/** String-keyed values used for labels, metadata, and environment variables. */
export type KeyValueMap = Record<string, string>;

/**
 * Options used when opening a {@link Runtime}.
 *
 * Default VM assets are resolved from Silo's installed asset locations.
 */
export interface RuntimeOpenOptions {
  /** Root directory for persistent state. */
  dataRoot?: string;
  /** Runtime directory for sockets and transient files. */
  runRoot?: string;
  /** Image cache directory. */
  imageRoot?: string;
  /** Explicit `vmmon` executable path. If unset, `vmmon` is resolved from the environment and `PATH`. */
  vmmonPath?: string;
}

/** Source used to materialize a machine root disk during `MachineBuilder.create()`. */
export type ImageSource =
  /** Pull and materialize an OCI image reference. */
  | { kind: "oci"; reference: string }
  /** Clone/copy an existing local disk image into the machine. */
  | { kind: "disk"; path: string }
  /** Convert a local rootfs tar archive into a machine root disk. */
  | { kind: "tar"; path: string };

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
  /** Create a local rootfs tar source. */
  tar(path: string): ImageSource {
    return { kind: "tar", path: assertNonEmptyString(path, "path") };
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
  | { kind: "private"; policyJson?: string }
  /** No network attachment. */
  | { kind: "none" }
  /** Attach to a named network. */
  | { kind: "named"; name: string }
  /** Inspection-only fallback for network kinds this SDK does not know yet. */
  | { kind: "unknown" };

/** Options for a guest command started by `exec`, `spawn`, or `shell`. */
export interface ExecOptions {
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
  /** Bytes or UTF-8 text sent to stdin, then EOF. */
  stdin?: Uint8Array | string;
  /** Open a writable stdin pipe. Mutually exclusive with `stdin`. */
  pipeStdin?: boolean;
  /** Request a guest PTY for the command. */
  tty?: boolean;
  /** Forward the host agent into the guest when supported. */
  forwardAgent?: boolean;
}

/** Options for an interactive terminal attachment. */
export interface AttachOptions {
  /** Additional argv values for the attached process. */
  args?: string[];
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
  /** Forward the host agent into the guest when supported. */
  forwardAgent?: boolean;
}

/** Guest process exit status. */
export interface ExitStatus {
  /** Numeric exit code reported by the guest process. */
  code: number;
  /** True when `code === 0`. */
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

/** Snapshot of persisted machine config plus runtime state. */
export interface MachineData {
  id: string;
  name: string;
  machineDir: string;
  createdAt: Date;
  modifiedAt: Date;
  imageRef: string;
  rootDiskSize?: number;
  labels: KeyValueMap;
  metadata: KeyValueMap;
  network: Network;
  agent: { mode: "default" | "custom" | "disabled" | "unknown"; path?: string };
  status: MachineStatus;
  startedAt?: Date;
  lastError?: string;
  updatedAt: Date;
}

/** Runtime image pull policy. */
export type ImagePullPolicy = "ifMissing" | "always" | "never";

/** Lightweight image cache handle. */
export interface ImageHandle {
  reference: string;
  imageId: string;
  manifestDigest?: string;
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
  layers: ImageLayerDetail[];
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
