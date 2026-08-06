import type {
  NativeMachineLogChunk,
  NativeMachineLogHandle,
  NativeMachineLogOptionsInput,
  NativeMachineLogSource,
} from "./internal/napi.js";
import { mapNativePromise } from "./errors.js";
import type { MachineLogChunk } from "./types.js";
import { assertBoolean, assertRecord, assertUint8Array } from "./validation.js";

export function machineLogSourceToNative(source: unknown): NativeMachineLogSource {
  switch (source) {
    case "monitor":
    case "serial":
    case "exec":
    case "network":
    case "networkAudit":
      return source;
    default:
      throw new TypeError("source must be monitor, serial, exec, network, or networkAudit");
  }
}

export function machineLogOptionsToNative(
  options?: unknown,
): NativeMachineLogOptionsInput | undefined {
  if (options === undefined) return undefined;
  const record = assertRecord(options, "options");
  return {
    follow: record.follow === undefined ? undefined : assertBoolean(record.follow, "options.follow"),
  };
}

export function machineLogChunkFromNative(chunk: NativeMachineLogChunk): MachineLogChunk {
  const data = assertUint8Array(chunk.data, "machine log chunk.data");
  switch (chunk.output) {
    case "stdout":
    case "stderr":
      return { output: chunk.output, data };
    default:
      throw new TypeError("machine log chunk.output must be stdout or stderr");
  }
}

/** Async stream of semantic machine log chunks. */
export class MachineLogStream implements AsyncIterable<MachineLogChunk> {
  private closed = false;
  private receiving = false;

  constructor(private readonly native: NativeMachineLogHandle) {}

  /** Receive the next chunk, or `null` after the stream has ended. */
  async recv(): Promise<MachineLogChunk | null> {
    if (this.closed) throw new Error("machine log handle is closed");
    if (this.receiving) throw new Error("machine log handle is busy");

    this.receiving = true;
    try {
      const chunk = await mapNativePromise(this.native.recv());
      if (chunk === null) {
        this.closed = true;
        return null;
      }
      return machineLogChunkFromNative(chunk);
    } finally {
      this.receiving = false;
    }
  }

  /** Stop reading and release the native stream. Idempotent. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.native.close();
  }

  /** Iterate over raw machine log chunks until the stream ends. */
  async *[Symbol.asyncIterator](): AsyncIterator<MachineLogChunk> {
    try {
      while (true) {
        const chunk = await this.recv();
        if (chunk === null) return;
        yield chunk;
      }
    } finally {
      this.close();
    }
  }
}
