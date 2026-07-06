const MAX_U32 = 4_294_967_295;
const MAX_I32 = 2_147_483_647;
const MAX_U16 = 65_535;

export function assertRecord(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

export function assertString(value: unknown, name: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`${name} must be a string`);
  }
  return value;
}

export function assertNonEmptyString(value: unknown, name: string): string {
  const stringValue = assertString(value, name);
  if (stringValue.length === 0) {
    throw new TypeError(`${name} must not be empty`);
  }
  return stringValue;
}

export function assertBoolean(value: unknown, name: string): boolean {
  if (typeof value !== "boolean") {
    throw new TypeError(`${name} must be a boolean`);
  }
  return value;
}

export function assertPositiveInteger(value: unknown, name: string, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new TypeError(`${name} must be a safe integer`);
  }
  if (value <= 0 || value > max) {
    throw new RangeError(`${name} must be between 1 and ${max}`);
  }
  return value;
}

export function assertNonNegativeInteger(value: unknown, name: string, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new TypeError(`${name} must be a safe integer`);
  }
  if (value < 0 || value > max) {
    throw new RangeError(`${name} must be between 0 and ${max}`);
  }
  return value;
}

export function assertPositiveU16(value: unknown, name: string): number {
  return assertPositiveInteger(value, name, MAX_U16);
}

export function assertPositiveI32(value: unknown, name: string): number {
  return assertPositiveInteger(value, name, MAX_I32);
}

export function assertI32(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new TypeError(`${name} must be a safe integer`);
  }
  if (value < -MAX_I32 - 1 || value > MAX_I32) {
    throw new RangeError(`${name} must be between ${-MAX_I32 - 1} and ${MAX_I32}`);
  }
  return value;
}

export function assertPositiveU32(value: unknown, name: string): number {
  return assertPositiveInteger(value, name, MAX_U32);
}

export function assertStringArray(value: unknown, name: string): string[] {
  if (!Array.isArray(value)) {
    throw new TypeError(`${name} must be an array`);
  }
  return value.map((entry, index) => assertString(entry, `${name}[${index}]`));
}

export function assertNonEmptyStringArray(value: unknown, name: string): string[] {
  if (!Array.isArray(value)) {
    throw new TypeError(`${name} must be an array`);
  }
  return value.map((entry, index) => assertNonEmptyString(entry, `${name}[${index}]`));
}

export function assertUint8Array(value: unknown, name: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
  return value;
}
