import type { NativeImages } from "./internal/napi.js";
import { imageDetailFromNative, imageHandleFromNative, imagePruneReportFromNative } from "./convert.js";
import { mapNativePromise } from "./errors.js";
import type { ImageDetail, ImageHandle, ImagePruneReport, ImagePullPolicy } from "./types.js";
import { assertBoolean, assertNonEmptyString, assertRecord, assertString } from "./validation.js";

/** Image cache and image-management operations. */
export class Images {
  constructor(private readonly native: NativeImages) {}

  /**
   * Pull or materialize an OCI image into the runtime image cache.
   *
   * `policy` defaults to the runtime pull policy.
   */
  async pull(reference: string, policy?: ImagePullPolicy): Promise<ImageHandle> {
    const nativePolicy = imagePullPolicyToNative(policy);
    return imageHandleFromNative(await mapNativePromise(this.native.pull(assertNonEmptyString(reference, "reference"), nativePolicy)));
  }

  /** Look up a cached image by reference. Returns `null` when missing. */
  async get(reference: string): Promise<ImageHandle | null> {
    const handle = await mapNativePromise(this.native.get(assertNonEmptyString(reference, "reference")));
    return handle ? imageHandleFromNative(handle) : null;
  }

  /** List cached OCI images known to this runtime. */
  async list(): Promise<ImageHandle[]> {
    return (await mapNativePromise(this.native.list())).map(imageHandleFromNative);
  }

  /** Inspect a cached image, including layer metadata. Returns `null` when missing. */
  async inspect(reference: string): Promise<ImageDetail | null> {
    const detail = await mapNativePromise(this.native.inspect(assertNonEmptyString(reference, "reference")));
    return detail ? imageDetailFromNative(detail) : null;
  }

  /** Remove a cached image reference. Pass `{ force: true }` to remove referenced images. */
  async remove(reference: string, options?: { force?: boolean }): Promise<void> {
    await mapNativePromise(this.native.remove(assertNonEmptyString(reference, "reference"), removeForce(options)));
  }

  /** Prune cached image data that is no longer referenced by machines. */
  async prune(): Promise<ImagePruneReport> {
    return imagePruneReportFromNative(await mapNativePromise(this.native.prune()));
  }
}

function imagePullPolicyToNative(policy: ImagePullPolicy | undefined): string | undefined {
  if (policy === undefined) return undefined;
  const value = assertString(policy, "policy");
  if (value !== "ifMissing" && value !== "always" && value !== "never") {
    throw new TypeError("policy must be ifMissing, always, or never");
  }
  return value === "ifMissing" ? "if_missing" : value;
}

function removeForce(options: { force?: boolean } | undefined): boolean | undefined {
  if (!options) return undefined;
  const record = assertRecord(options, "options");
  return record.force === undefined ? undefined : assertBoolean(record.force, "options.force");
}
