import { describe, expect, it } from "vitest";
import { BentoError, mapNativeError } from "../../src/errors.js";

describe("mapNativeError", () => {
  it("translates tagged native errors into BentoError", () => {
    const raw = new Error("[MachineNotFound] no machine named ubuntu");

    expect(() => mapNativeError(raw)).toThrow(BentoError);
    const error = capture(() => mapNativeError(raw));
    expect(error).toBeInstanceOf(BentoError);
    if (!(error instanceof BentoError)) throw error;
    expect(error.variant).toBe("MachineNotFound");
    expect(error.message).toBe("no machine named ubuntu");
    expect(error.cause).toBe(raw);
  });

  it("wraps untagged errors", () => {
    const raw = new Error("plain failure");

    const error = capture(() => mapNativeError(raw));
    expect(error).toBeInstanceOf(BentoError);
    if (!(error instanceof BentoError)) throw error;
    expect(error.variant).toBeUndefined();
    expect(error.message).toBe("plain failure");
    expect(error.cause).toBe(raw);
  });
});

function capture(callback: () => void): unknown {
  try {
    callback();
  } catch (error) {
    return error;
  }
  throw new Error("callback did not throw");
}
