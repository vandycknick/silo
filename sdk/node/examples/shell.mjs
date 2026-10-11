import { Runtime } from '../dist/index.js';
import { once } from 'node:events';

const id = process.argv[2];
if (!id) throw new Error('usage: node sdk/node/examples/shell.mjs <machine-id>');
const runtime = await Runtime.open({ home: process.env.SILO_HOME });
const machine = await runtime.getMachine(id);
const abort = new AbortController();
const timer = setTimeout(() => abort.abort(new Error('shell deadline')), 15000);
// Process stdio is borrowed. Await drain with cancellation; never close it.
async function write(stream, chunk, signal) {
  if (signal.aborted) throw signal.reason;
  if (!stream.write(chunk)) await once(stream, 'drain', { signal });
}
try {
  const status = await machine.shell({ term: 'xterm-256color', signal: abort.signal, attachment: {
    rows: 37, columns: 119,
    // Finite in-memory input cannot block, so it need not wait on abort.
    async *stdin() { yield Buffer.from('printf \'embedded:%s\\n\' "$USER"; exit 7\n'); },
    stdout: (chunk, signal) => write(process.stdout, chunk, signal),
    stderr: (chunk, signal) => write(process.stderr, chunk, signal),
  } });
  console.log(`SSH exit: ${status.code}`);
  process.exitCode = status.code;
} finally { clearTimeout(timer); }
