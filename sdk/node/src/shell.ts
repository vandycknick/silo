import type { NativeMachine } from "./internal/napi.js";
import type { SshExitStatus, SshShellOptions, SshShellControl } from "./types.js";
import { sshShellOptionsToNative } from "./convert.js";
import { mapNativePromise } from "./errors.js";

function dimension(value: number): number {
  if (!Number.isInteger(value) || value < 1 || value > 65535) throw new RangeError("shell dimensions must be integers in 1..65535");
  return value;
}
const signals: Record<string, true> = { HUP: true, INT: true, QUIT: true, ILL: true, ABRT: true, FPE: true, KILL: true, USR1: true, SEGV: true, USR2: true, PIPE: true, ALRM: true, TERM: true };
/** Private SDK boundary adapter: owns pumps, never an SSH client. */
export async function shell(native: NativeMachine, options: SshShellOptions = {}): Promise<SshExitStatus> {
  const { attachment, signal, ...scalars } = options;
  if (attachment && scalars.detachKeys !== undefined) throw new TypeError("detachKeys is only valid for local shell I/O");
  const size = attachment ? { rows: dimension(attachment.rows), columns: dimension(attachment.columns) } : undefined;
  if (signal?.aborted) throw signal.reason ?? new Error("shell aborted");
  const operation = native.startShell(sshShellOptionsToNative(scalars), size);
  const input = new AbortController();
  const output = new AbortController();
  let firstError: unknown;
  let failed = false;
  let rejectFailure!: (error: unknown) => void;
  const failure = new Promise<never>((_, reject) => { rejectFailure = reject; });
  // Keep this observed even if an error arrives during final cleanup.
  void failure.catch(() => {});
  const fail = (error: unknown) => {
    if (failed) return;
    failed = true; firstError = error;
    operation.cancel(); input.abort(error); output.abort(error); rejectFailure(error);
  };
  const abort = () => fail(signal?.reason ?? new Error("shell aborted"));
  signal?.addEventListener("abort", abort, { once: true });
  if (signal?.aborted) abort();
  const workers: Promise<void>[] = [];
  const start = (work: () => Promise<void>, scope: AbortSignal) => {
    const promise = work().catch(async error => {
      if (scope.aborted) return;
      if (scope === input.signal && error instanceof Error &&
          (error.message.endsWith("shell input closed") || error.message.endsWith("shell controls closed"))) {
        try { await mapNativePromise(operation.result()); } catch (nativeError) { fail(nativeError); }
        return;
      }
      fail(error);
    });
    workers.push(promise);
    return promise;
  };
  // Chain only sink calls, not reads. A waiting callback checks cancellation
  // before entering the gate; an active callback must honor its signal.
  let gate = Promise.resolve();
  const deliver = (sink: ((chunk: Uint8Array, signal: AbortSignal) => Promise<void>) | undefined, chunk: Uint8Array) => {
    const call = gate.then(async () => {
      if (output.signal.aborted) throw output.signal.reason;
      await sink?.(chunk, output.signal);
    });
    gate = call.catch(() => {});
    return call;
  };
  const inputWorkers: Promise<void>[] = [];
  const outputWorkers: Promise<void>[] = [];
  if (attachment) {
    inputWorkers.push(start(async () => {
      if (attachment.stdin) {
        for await (const chunk of attachment.stdin(input.signal)) {
          if (input.signal.aborted) return;
          if (!(chunk instanceof Uint8Array)) throw new TypeError("shell stdin must yield Uint8Array");
          for (let offset = 0; offset < chunk.length; offset += 65536) {
            if (input.signal.aborted) return;
            await mapNativePromise(operation.writeStdin(chunk.subarray(offset, offset + 65536)));
          }
        }
      }
      if (!input.signal.aborted) await mapNativePromise(operation.closeStdin());
    }, input.signal));
    if (attachment.controls) inputWorkers.push(start(async () => {
      for await (const control of attachment.controls!(input.signal)) {
        if (input.signal.aborted) return;
        await sendControl(control);
      }
    }, input.signal));
    async function sendControl(control: SshShellControl) {
      if (control.kind === "resize") await mapNativePromise(operation.resize(dimension(control.rows), dimension(control.columns)));
      else if (control.kind === "signal" && Object.hasOwn(signals, control.signal)) await mapNativePromise(operation.signal(control.signal));
      else throw new TypeError("invalid SSH shell control");
    }
    for (const stderr of [false, true]) outputWorkers.push(start(async () => {
      while (!output.signal.aborted) {
        const chunk = await mapNativePromise(stderr ? operation.readStderr() : operation.readStdout());
        if (chunk === null) return;
        await deliver(stderr ? attachment.stderr : attachment.stdout, chunk);
      }
    }, output.signal));
  }
  const result = mapNativePromise(operation.result());
  void result.catch(fail);
  try {
    const status = await Promise.race([result, failure]);
    input.abort(new Error("shell input complete"));
    await Promise.race([Promise.all(inputWorkers), failure]);
    await Promise.race([Promise.all(outputWorkers), failure]);
    if (failed) throw firstError;
    return status;
  } catch (error) {
    fail(error);
    throw firstError;
  } finally {
    input.abort();
    if (failed) output.abort();
    await Promise.allSettled(workers);
    output.abort();
    signal?.removeEventListener("abort", abort);
    try { await mapNativePromise(operation.close()); }
    catch (error) { if (!failed) throw error; }
  }
}
