import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const require = createRequire(import.meta.url);
const nativePath = fileURLToPath(new URL("../../native/index.cjs", import.meta.url));

describe("native addon contract", () => {
  it("exports the entry point used by the TypeScript facade when the native addon is built", () => {
    if (!existsSync(nativePath)) return;

    const loaded = require(nativePath);
    const module = plainRecord(loaded, "native module");
    const exported = module.default === undefined ? module : module.default;
    const native = plainRecord(exported, "native exports");

    expect(typeof native.openRuntime).toBe("function");
  });
});

function plainRecord(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object`);
  }
  return Object.fromEntries(Object.entries(value));
}
