import type { NativeExecHandle, NativeExecSink, NativeExecOutput } from "./internal/napi.js";
import { execEventFromNative, type ExecEvent } from "./convert.js";
import { mapNativePromise } from "./errors.js";
import type { ExitStatus } from "./types.js";
import { assertPositiveI32, assertPositiveU16, assertUint8Array } from "./validation.js";

/** Captured output from `Machine.exec()` or `Machine.shell()`. */
export class ExecOutput {
  constructor(private readonly native: NativeExecOutput) {}

  /** Guest process exit status. */
  get status(): ExitStatus {
    return this.native.status;
  }

  /** Guest process exit code. */
  get code(): number {
    return this.native.status.code;
  }

  /** True when the guest process exited with code 0. */
  get success(): boolean {
    return this.native.status.success;
  }

  /** Raw stdout bytes. */
  stdoutBytes(): Uint8Array {
    return this.native.stdout;
  }

  /** Raw stderr bytes. */
  stderrBytes(): Uint8Array {
    return this.native.stderr;
  }

  /** Decode stdout as UTF-8. Invalid sequences are replaced. */
  stdout(): string {
    return new TextDecoder().decode(this.native.stdout);
  }

  /** Decode stderr as UTF-8. Invalid sequences are replaced. */
  stderr(): string {
    return new TextDecoder().decode(this.native.stderr);
  }
}

/** Writable stdin pipe for a streamed guest command. */
export class ExecSink {
  private closed = false;

  constructor(private readonly native: NativeExecSink) {}

  /** Write UTF-8 text or raw bytes to guest stdin. */
  async write(data: Uint8Array | string): Promise<void> {
    if (this.closed) throw new Error("exec stdin is closed");
    const bytes = typeof data === "string" ? new TextEncoder().encode(data) : assertUint8Array(data, "data");
    await mapNativePromise(this.native.write(bytes));
  }

  /** Close stdin. Idempotent. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.native.close();
  }
}

/** Streaming handle returned by `Machine.spawn()`. */
export class ExecHandle implements AsyncIterable<ExecEvent> {
  private stdinTaken = false;

  constructor(private readonly native: NativeExecHandle) {}

  /** Receive the next event, or `null` once the stream has ended. */
  async recv(): Promise<ExecEvent | null> {
    const event = await mapNativePromise(this.native.recv());
    return event ? execEventFromNative(event) : null;
  }

  /** Take ownership of the stdin sink. Returns `null` after the first call. */
  takeStdin(): ExecSink | null {
    if (this.stdinTaken) return null;
    const sink = this.native.takeStdin();
    if (sink) this.stdinTaken = true;
    return sink ? new ExecSink(sink) : null;
  }

  /** Wait for the guest process to exit. */
  async wait(): Promise<ExitStatus> {
    return await mapNativePromise(this.native.wait());
  }

  /** Drain stdout/stderr and wait for the guest process to exit. */
  async collect(): Promise<ExecOutput> {
    return new ExecOutput(await mapNativePromise(this.native.collect()));
  }

  /** Send a POSIX signal number to the guest process. */
  async signal(signal: number): Promise<void> {
    await mapNativePromise(this.native.signal(assertPositiveI32(signal, "signal")));
  }

  /** Kill the guest process. */
  async kill(): Promise<void> {
    await mapNativePromise(this.native.kill());
  }

  /** Resize the guest PTY. */
  async resize(rows: number, cols: number): Promise<void> {
    await mapNativePromise(this.native.resize(assertPositiveU16(rows, "rows"), assertPositiveU16(cols, "cols")));
  }

  /** Iterate over streamed exec events. */
  async *[Symbol.asyncIterator](): AsyncIterator<ExecEvent> {
    while (true) {
      const event = await this.recv();
      if (!event) return;
      yield event;
    }
  }
}

/** Event emitted by streamed guest commands. */
export type { ExecEvent } from "./convert.js";
