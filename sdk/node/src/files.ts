import type { NativeFileDownload, NativeFileEntry, NativeUploadOptions, NativeCreateDirectoryOptions } from "./internal/napi.js";
import { mapNativePromise } from "./errors.js";
import { assertBoolean, assertNonNegativeInteger, assertString } from "./validation.js";

export type FileEntryKind = "file" | "directory" | "symlink" | "fifo" | "socket" | "block_device" | "character_device";
export type DirectoryDisposition = "created" | "already_exists";
export type FileWriteDisposition = "created" | "replaced";
export interface FileEntry {
  path: string;
  name: string;
  kind: FileEntryKind;
  sizeBytes: bigint;
  mode: number;
  uid: number;
  gid: number;
  modifiedAt: Date;
}
export interface UploadOptions { mode?: number; uid?: number; gid?: number }
export interface CreateDirectoryOptions extends UploadOptions { parents?: boolean }
export interface UploadResult { disposition: FileWriteDisposition; bytes: number }

export function guestPath(path: string): string {
  const value = assertString(path, "path");
  if (!value.startsWith("/")) throw new TypeError("guest paths must be absolute");
  return value;
}

export function uploadOptionsToNative(options?: UploadOptions): NativeUploadOptions | undefined {
  if (options === undefined) return undefined;
  if (options.mode !== undefined && options.mode > 0o7777) {
    throw new RangeError("mode must be a Unix permission value no greater than 0o7777");
  }
  return {
    mode: options.mode === undefined ? undefined : assertNonNegativeInteger(options.mode, "mode", 0o7777),
    uid: options.uid === undefined ? undefined : assertNonNegativeInteger(options.uid, "uid", 0xffffffff),
    gid: options.gid === undefined ? undefined : assertNonNegativeInteger(options.gid, "gid", 0xffffffff),
  };
}

export function directoryOptionsToNative(options?: CreateDirectoryOptions): NativeCreateDirectoryOptions | undefined {
  if (options === undefined) return undefined;
  return { ...uploadOptionsToNative(options), parents: options.parents === undefined ? undefined : assertBoolean(options.parents, "parents") };
}

export function directoryDisposition(value: string): DirectoryDisposition {
  if (value === "created" || value === "already_exists") return value;
  throw new TypeError(`unknown directory disposition: ${value}`);
}

export function fileWriteDisposition(value: string): FileWriteDisposition {
  if (value === "created" || value === "replaced") return value;
  throw new TypeError(`unknown file write disposition: ${value}`);
}

export function fileEntryFromNative(entry: NativeFileEntry): FileEntry {
  const kind = entry.kind;
  if (kind !== "file" && kind !== "directory" && kind !== "symlink" && kind !== "fifo" && kind !== "socket" && kind !== "block_device" && kind !== "character_device") {
    throw new TypeError(`unknown file entry kind: ${kind}`);
  }
  return { path: entry.path, name: entry.name, kind, sizeBytes: entry.sizeBytes, mode: entry.mode, uid: entry.uid, gid: entry.gid, modifiedAt: new Date(Number(entry.modifiedAtUnixMillis)) };
}

/** A streaming guest file download. Breaking iteration cancels the transfer. */
export class FileDownload implements AsyncIterable<Uint8Array> {
  constructor(private readonly native: NativeFileDownload) {}

  cancel(): void { this.native.cancel(); }

  async *[Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
    try {
      while (true) {
        const chunk = await mapNativePromise(this.native.read());
        if (chunk === null) return;
        yield chunk;
      }
    } finally {
      this.cancel();
    }
  }

  async collect(): Promise<Uint8Array> {
    const chunks: Uint8Array[] = [];
    let length = 0;
    for await (const chunk of this) { chunks.push(chunk); length += chunk.byteLength; }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return bytes;
  }
}
