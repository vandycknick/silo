import { describe, expect, expectTypeOf, it } from "vitest";
import { SiloError } from "../../src/errors.js";
import {
  MachineLogStream,
  machineLogOptionsToNative,
  machineLogSourceToNative,
} from "../../src/logs.js";
import type { NativeMachineLogChunk, NativeMachineLogHandle } from "../../src/internal/napi.js";
import type { Machine } from "../../src/machine.js";
import type { MachineLogChunk, MachineLogOptions, MachineLogSource } from "../../src/types.js";

describe("machine log conversion", () => {
  it("accepts only semantic log sources and options", () => {
    expect(machineLogSourceToNative("monitor")).toBe("monitor");
    expect(machineLogSourceToNative("serial")).toBe("serial");
    expect(machineLogSourceToNative("exec")).toBe("exec");
    expect(machineLogSourceToNative("network")).toBe("network");
    expect(machineLogSourceToNative("networkAudit")).toBe("networkAudit");
    expect(() => machineLogSourceToNative("audit")).toThrow(TypeError);
    expect(machineLogOptionsToNative()).toBeUndefined();
    expect(machineLogOptionsToNative({ follow: true })).toEqual({ follow: true });
    expect(() => machineLogOptionsToNative({ follow: "yes" })).toThrow(TypeError);
  });

  it("preserves raw bytes and ends async iteration at the native terminator", async () => {
    const bytes = new Uint8Array([0, 255, 128, 10]);
    const stream = new MachineLogStream(new SequenceLogHandle([
      { output: "stdout", data: bytes },
      { output: "stderr", data: new Uint8Array([1]) },
      null,
    ]));

    const chunks: MachineLogChunk[] = [];
    for await (const chunk of stream) chunks.push(chunk);

    expect(chunks).toEqual([
      { output: "stdout", data: bytes },
      { output: "stderr", data: new Uint8Array([1]) },
    ]);
    expect(chunks[0]?.data).toBe(bytes);
  });

  it("closes the native stream when async iteration exits early", async () => {
    const native = new SequenceLogHandle([
      { output: "stdout", data: new Uint8Array([1]) },
      { output: "stdout", data: new Uint8Array([2]) },
    ]);
    const stream = new MachineLogStream(native);

    for await (const _chunk of stream) break;

    expect(native.closeCalls).toBe(1);
    stream.close();
    expect(native.closeCalls).toBe(1);
  });

  it("cancels a pending receive on close and rejects concurrent receives as busy", async () => {
    const native = new PendingLogHandle();
    const stream = new MachineLogStream(native);
    const pending = stream.recv();

    await expect(stream.recv()).rejects.toThrow("machine log handle is busy");

    stream.close();
    stream.close();

    expect(native.closeCalls).toBe(1);
    await expect(pending).rejects.toThrow("machine log handle is closed");
  });

  it("maps tagged native stream failures", async () => {
    const stream = new MachineLogStream(new FailingLogHandle());

    await expect(stream.recv()).rejects.toMatchObject({
      name: "MachineLogSourceUnavailableError",
      variant: "MachineLogSourceUnavailable",
    } satisfies Partial<SiloError>);
  });

  it("exports the typed logs surface", () => {
    expectTypeOf<Machine["logs"]>().returns.toEqualTypeOf<Promise<MachineLogStream>>();
    expectTypeOf<MachineLogSource>().toEqualTypeOf<"monitor" | "serial" | "exec" | "network" | "networkAudit">();
    expectTypeOf<MachineLogOptions>().toEqualTypeOf<{ follow?: boolean }>();
    expectTypeOf<MachineLogChunk>().toEqualTypeOf<{ output: "stdout" | "stderr"; data: Uint8Array }>();
  });
});

class SequenceLogHandle implements NativeMachineLogHandle {
  closeCalls = 0;

  constructor(private readonly chunks: Array<NativeMachineLogChunk | null>) {}

  async recv(): Promise<NativeMachineLogChunk | null> {
    return this.chunks.shift() ?? null;
  }

  close(): void {
    this.closeCalls += 1;
  }
}

class FailingLogHandle implements NativeMachineLogHandle {
  async recv(): Promise<NativeMachineLogChunk | null> {
    throw new Error("[MachineLogSourceUnavailable] machine does not provide network logs");
  }

  close(): void {}
}

class PendingLogHandle implements NativeMachineLogHandle {
  closeCalls = 0;
  private closed = false;
  private rejectPending: ((reason?: unknown) => void) | undefined;

  recv(): Promise<NativeMachineLogChunk | null> {
    if (this.closed) return Promise.reject(new Error("machine log handle is closed"));
    return new Promise<NativeMachineLogChunk | null>((_resolve, reject) => {
      this.rejectPending = reject;
    });
  }

  close(): void {
    this.closeCalls += 1;
    if (this.closed) return;
    this.closed = true;
    this.rejectPending?.(new Error("machine log handle is closed"));
  }
}
