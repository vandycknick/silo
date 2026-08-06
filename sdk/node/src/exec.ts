import type {
  NativeExecutionOutput,
  NativeExecutionSession,
  NativeExecutionStdin,
} from "./internal/napi.js";
import { executionEventFromNative, executionResultFromNative, type ExecutionEvent } from "./convert.js";
import { mapNativePromise } from "./errors.js";
import type { ExecutionResult } from "./types.js";
import { assertPositiveInteger, assertPositiveU16, assertUint8Array } from "./validation.js";

/** Captured bytes and the exact terminal result of a structured execution. */
export class ExecutionOutput {
  constructor(private readonly native: NativeExecutionOutput) {}

  get result(): ExecutionResult {
    return executionResultFromNative(this.native.result);
  }

  stdoutBytes(): Uint8Array { return this.native.stdout; }
  stderrBytes(): Uint8Array { return this.native.stderr; }
  terminalOutputBytes(): Uint8Array { return this.native.terminalOutput; }
  stdout(): string { return new TextDecoder().decode(this.native.stdout); }
  stderr(): string { return new TextDecoder().decode(this.native.stderr); }
  terminalOutput(): string { return new TextDecoder().decode(this.native.terminalOutput); }
}

/** Writable stdin or PTY input for a structured execution. */
export class ExecutionStdin {
  private closed = false;
  constructor(private readonly native: NativeExecutionStdin) {}

  async write(data: Uint8Array | string): Promise<void> {
    if (this.closed) throw new Error("execution stdin is closed");
    const bytes = typeof data === "string" ? new TextEncoder().encode(data) : assertUint8Array(data, "data");
    await mapNativePromise(this.native.write(bytes));
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await mapNativePromise(this.native.close());
  }
}

/** Bidirectional execution call returned by `Machine.spawn()`. */
export class ExecutionSession implements AsyncIterable<ExecutionEvent> {
  constructor(private readonly native: NativeExecutionSession) {}

  async recv(): Promise<ExecutionEvent | null> {
    const event = await mapNativePromise(this.native.recv());
    return event === null ? null : executionEventFromNative(event);
  }

  stdin(): ExecutionStdin | null {
    const stdin = this.native.stdin();
    return stdin === null ? null : new ExecutionStdin(stdin);
  }

  async wait(): Promise<ExecutionResult> {
    return executionResultFromNative(await mapNativePromise(this.native.wait()));
  }

  async collect(): Promise<ExecutionOutput> {
    return new ExecutionOutput(await mapNativePromise(this.native.collect()));
  }

  async signal(signal: number): Promise<void> {
    await mapNativePromise(this.native.signal(assertPositiveInteger(signal, "signal", 64)));
  }

  async resizePty(rows: number, columns: number): Promise<void> {
    await mapNativePromise(this.native.resizePty(assertPositiveU16(rows, "rows"), assertPositiveU16(columns, "columns")));
  }

  closeRequests(): void { this.native.closeRequests(); }
  cancel(): void { this.native.cancel(); }

  async *[Symbol.asyncIterator](): AsyncIterator<ExecutionEvent> {
    while (true) {
      const event = await this.recv();
      if (event === null) return;
      yield event;
    }
  }
}

export type { ExecutionEvent } from "./convert.js";
