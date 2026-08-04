import type { Machine } from "./machine.js";
import type { MachineLogStream } from "./logs.js";
import type { MachineLogChunk, MachineLogOptions, MachineLogSource } from "./types.js";

type Equal<Left, Right> = [Left] extends [Right]
  ? [Right] extends [Left]
    ? true
    : false
  : false;
type Assert<Condition extends true> = Condition;

type MachineLogsReturnsStream = Assert<
  Equal<ReturnType<Machine["logs"]>, Promise<MachineLogStream>>
>;
type MachineLogSourceHasOnlySemanticSources = Assert<
  Equal<MachineLogSource, "monitor" | "serial" | "network" | "networkAudit">
>;
type MachineLogOptionsAcceptsFollow = Assert<Equal<MachineLogOptions, { follow?: boolean }>>;
type MachineLogChunkPreservesBytes = Assert<
  Equal<MachineLogChunk, { output: "stdout" | "stderr"; data: Uint8Array }>
>;
type MachineLogStreamCloseIsSynchronous = Assert<Equal<MachineLogStream["close"], () => void>>;
