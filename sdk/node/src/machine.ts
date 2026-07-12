import type { NativeMachine, NativeMachineBuilder } from "./internal/napi.js";
import {
    attachOptionsToNative,
    execOptionsToNative,
    imageSourceToNative,
    machineDataFromNative,
    mapToKeyValues,
    mountsToNative,
} from "./convert.js";
import { mapNativePromise } from "./errors.js";
import { ExecHandle, ExecOutput } from "./exec.js";
import { MachineNetworkBuilder, type MachineNetworkBuilderCallback } from "./network.js";
import type {
    AttachOptions,
    ExecOptions,
    ExitStatus,
    ImageSource,
    KeyValueMap,
    MachineData,
    Mount,
} from "./types.js";
import {
    assertBoolean,
    assertNonEmptyString,
    assertNonEmptyStringArray,
    assertNonNegativeInteger,
    assertPositiveInteger,
    assertPositiveU32,
    assertString,
    assertStringArray,
} from "./validation.js";

/**
 * Fluent builder for a machine.
 *
 * `create()` materializes the selected image immediately. `Machine.start()`
 * never pulls images.
 */
export class MachineBuilder {
    constructor(private readonly native: NativeMachineBuilder) {}

    /**
     * Set an OCI image reference. Strings always mean OCI references.
     * Use {@link ImageSource.disk} or {@link ImageSource.tar} for local paths.
     */
    image(reference: string): this {
        this.native.image(assertNonEmptyString(reference, "reference"));
        return this;
    }

    /** Set an explicit OCI, disk, or tar image source. */
    imageSource(source: ImageSource): this {
        this.native.imageSource(imageSourceToNative(source));
        return this;
    }

    /** Set the machine name. */
    name(name: string): this {
        this.native.name(assertNonEmptyString(name, "name"));
        return this;
    }

    /** Attach a single metadata label. */
    label(key: string, value: string): this {
        this.native.label(
            assertNonEmptyString(key, "key"),
            assertString(value, "value"),
        );
        return this;
    }

    /** Replace builder labels with a map of key/value strings. */
    labels(labels: KeyValueMap): this {
        this.native.labels(mapToKeyValues(labels) ?? []);
        return this;
    }

    /** Attach one machine metadata entry. */
    metadataEntry(key: string, value: string): this {
        this.native.metadataEntry(
            assertNonEmptyString(key, "key"),
            assertString(value, "value"),
        );
        return this;
    }

    /** Replace builder metadata with a map of key/value strings. */
    metadata(metadata: KeyValueMap): this {
        this.native.metadata(mapToKeyValues(metadata) ?? []);
        return this;
    }

    /** Set the virtual CPU count. */
    cpus(cpus: number): this {
        this.native.cpus(assertPositiveInteger(cpus, "cpus", 255));
        return this;
    }

    /** Set guest memory in mebibytes. */
    memory(value: number): this {
        this.native.memory(assertPositiveU32(value, "value"));
        return this;
    }

    /** Set the Linux kernel path for this machine, overriding runtime defaults. */
    kernel(path: string): this {
        this.native.kernel(assertNonEmptyString(path, "path"));
        return this;
    }

    /** Set the initramfs path for this machine, overriding runtime defaults. */
    initramfs(path: string): this {
        this.native.initramfs(assertNonEmptyString(path, "path"));
        return this;
    }

    /** Configure guest behavior owned by Silo rather than the VMM specification. */
    guest(configure: (guest: GuestBuilder) => GuestBuilder): this {
        const guest = new GuestBuilder(this.native);
        configure(guest);
        return this;
    }

    /** Set the machine root disk size in bytes. */
    rootDiskSize(value: number): this {
        this.native.rootDiskSize(assertNonNegativeInteger(value, "value"));
        return this;
    }

    /** Enable or disable nested virtualization. */
    nestedVirtualization(enabled: boolean): this {
        this.native.nestedVirtualization(assertBoolean(enabled, "enabled"));
        return this;
    }

    /** Enable or disable Rosetta integration on supported macOS hosts. */
    rosetta(enabled: boolean): this {
        this.native.rosetta(assertBoolean(enabled, "enabled"));
        return this;
    }

    /** Set guest userdata passed through provisioning. */
    userdata(userdata: string): this {
        this.native.userdata(assertString(userdata, "userdata"));
        return this;
    }

    /** Attach additional disk image paths. */
    disks(disks: string[]): this {
        this.native.disks(assertNonEmptyStringArray(disks, "disks"));
        return this;
    }

    /** Configure guest mounts. */
    mounts(mounts: Mount[]): this {
        this.native.mounts(mountsToNative(mounts));
        return this;
    }

    /** Configure the machine network attachment. */
    network(configure: MachineNetworkBuilderCallback): this {
        const builder = new MachineNetworkBuilder();
        const configured = configure(builder) ?? builder;
        this.native.network(configured.toNative());
        return this;
    }

    /**
     * Materialize the image and persist the machine.
     *
     * The virtual machine is created but not started.
     */
    async create(): Promise<Machine> {
        return new Machine(await mapNativePromise(this.native.create()));
    }
}

/** Builder for durable guest settings. */
export class GuestBuilder {
    constructor(private readonly native: NativeMachineBuilder) {}

    /** Select a custom agent path, or disable managed injection with `null`. */
    agent(path: string | null): this {
        this.native.agent(path === null ? undefined : assertNonEmptyString(path, "path"));
        return this;
    }
}

/** Handle to an existing machine. */
export class Machine {
    constructor(private readonly native: NativeMachine) {}

    /** Return the stable machine ID. */
    id(): string {
        return this.native.id();
    }

    /** Inspect persisted config and runtime state. */
    async inspect(): Promise<MachineData> {
        return machineDataFromNative(
            await mapNativePromise(this.native.inspect()),
        );
    }

    /** Start the machine. This never pulls or re-materializes images. */
    async start(): Promise<MachineData> {
        return machineDataFromNative(
            await mapNativePromise(this.native.start()),
        );
    }

    /** Stop the machine gracefully. */
    async stop(): Promise<MachineData> {
        return machineDataFromNative(
            await mapNativePromise(this.native.stop()),
        );
    }

    /** Remove the machine. */
    async remove(): Promise<void> {
        await mapNativePromise(this.native.remove());
    }

    /**
     * Run a guest executable and capture stdout, stderr, and exit status.
     * No shell is inserted; use {@link shell} for pipes, redirects, and shell syntax.
     */
    async exec(
        program: string,
        args: string[] = [],
        options?: ExecOptions,
    ): Promise<ExecOutput> {
        return new ExecOutput(
            await mapNativePromise(
                this.native.exec(
                    assertNonEmptyString(program, "program"),
                    assertStringArray(args, "args"),
                    execOptionsToNative(options),
                ),
            ),
        );
    }

    /** Run a guest executable and return a streaming handle. */
    async spawn(
        program: string,
        args: string[] = [],
        options?: ExecOptions,
    ): Promise<ExecHandle> {
        return new ExecHandle(
            await mapNativePromise(
                this.native.spawn(
                    assertNonEmptyString(program, "program"),
                    assertStringArray(args, "args"),
                    execOptionsToNative(options),
                ),
            ),
        );
    }

    /** Run a script through the guest shell and capture output. */
    async shell(script: string, options?: ExecOptions): Promise<ExecOutput> {
        return new ExecOutput(
            await mapNativePromise(
                this.native.shell(
                    assertString(script, "script"),
                    execOptionsToNative(options),
                ),
            ),
        );
    }

    /** Attach the current terminal to an interactive guest process. */
    async attach(
        program: string,
        args: string[] = [],
        options?: AttachOptions,
    ): Promise<ExitStatus> {
        return await mapNativePromise(
            this.native.attach(
                assertNonEmptyString(program, "program"),
                assertStringArray(args, "args"),
                attachOptionsToNative(options),
            ),
        );
    }

    /** Attach the current terminal to the guest's default shell. */
    async attachShell(options?: AttachOptions): Promise<ExitStatus> {
        return await mapNativePromise(
            this.native.attachShell(attachOptionsToNative(options)),
        );
    }
}
