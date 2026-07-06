/** Error thrown by SDK operations. */
export class SiloError extends Error {
  constructor(
    message: string,
    public readonly variant?: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = variant ? `${variant}Error` : "SiloError";
  }
}

const PREFIX = /^\[(\w+)] ([\s\S]*)$/;

/** Convert an unknown error into a `SiloError` and throw it. */
export function mapNativeError(error: unknown): never {
  if (error instanceof Error) {
    const match = PREFIX.exec(error.message);
    if (match) {
      throw new SiloError(match[2] ?? error.message, match[1], { cause: error });
    }
    throw new SiloError(error.message, undefined, { cause: error });
  }
  throw new SiloError(String(error));
}

export async function mapNativePromise<T>(promise: Promise<T>): Promise<T> {
  try {
    return await promise;
  } catch (error) {
    mapNativeError(error);
  }
}
