import { napi, type NativeRuntime } from "./internal/napi.js";
import { runtimeOptionsToNative } from "./convert.js";
import { mapNativePromise } from "./errors.js";
import { Images } from "./images.js";
import { Machine, MachineBuilder } from "./machine.js";
import type { RuntimeOpenOptions } from "./types.js";
import { assertNonEmptyString } from "./validation.js";

/**
 * Entry point for local machine management.
 */
export class Runtime {
  private constructor(private readonly native: NativeRuntime) {}

  /**
   * Open a local runtime.
   *
   * If `vmmonPath` is not set, `vmmon` is resolved from the environment and `PATH`.
   *
   * @example
   * ```ts
   * const runtime = await Runtime.open({ dataRoot: "/tmp/silo-sdk" });
   * ```
   *
   * @throws {TypeError} When `options` is malformed.
   * @throws {SiloError} When the runtime cannot be opened.
   */
  static async open(options?: RuntimeOpenOptions): Promise<Runtime> {
    return new Runtime(await mapNativePromise(napi.openRuntime(runtimeOptionsToNative(options))));
  }

  /** Begin building a new machine. The builder must be given an image before `create()`. */
  machine(): MachineBuilder {
    return new MachineBuilder(this.native.machine());
  }

  /** Image cache and image-management operations scoped to this runtime. */
  images(): Images {
    return new Images(this.native.images());
  }

  /**
   * Look up an existing machine by name or ID.
   *
   * @throws {TypeError} When `reference` is not a non-empty string.
   * @throws {SiloError} When the machine cannot be found or loaded.
   */
  async getMachine(reference: string): Promise<Machine> {
    return new Machine(await mapNativePromise(this.native.getMachine(assertNonEmptyString(reference, "reference"))));
  }

  /** List all machines known to this runtime. */
  async listMachines(): Promise<Machine[]> {
    return (await mapNativePromise(this.native.listMachines())).map((machine) => new Machine(machine));
  }
}
