import assert from 'node:assert/strict';
import { Runtime } from '../../dist/index.js';
import { setTimeout as delay } from 'node:timers/promises';

const [home, id, mode] = process.argv.slice(2);
assert(home && id && ['all', 'ssh-only'].includes(mode), 'usage: shell-smoke.mjs <home> <machine-id> <all|ssh-only>');
const runtime = await Runtime.open({ home });
const machine = await runtime.getMachine(id);
const deadline = new AbortController();
const timer = setTimeout(() => deadline.abort(new Error('Node shell qualification deadline')), 45000);
async function finiteShell(command) {
  const chunks = [];
  let writing = false;
  // Intentionally share a non-reentrant sink between both output channels.
  const sink = async (chunk, signal) => {
    assert.equal(writing, false, 'output sink calls must be serialized');
    writing = true;
    try { await delay(1, undefined, { signal }); chunks.push(Buffer.from(chunk)); }
    finally { writing = false; }
  };
  const status = await machine.shell({ term: 'xterm-256color', signal: deadline.signal, attachment: {
    rows: 37, columns: 119,
    async *stdin(signal) {
      yield Buffer.from(command);
      // Keep live input crossing the byte boundary while output is delivered.
      for (let i = 0; i < 3; i++) {
        await delay(5, undefined, { signal });
        yield Buffer.from('\n');
      }
    },
    stdout: sink, stderr: sink,
    async *controls(signal) {
      while (!signal.aborted) {
        yield { kind: 'resize', rows: 37, columns: 119 };
        await delay(5, undefined, { signal });
      }
    },
  } });
  return { status, text: Buffer.concat(chunks).toString().replaceAll('\r', '') };
}
try {
  if (mode === 'all') {
    const literal = await machine.exec('/usr/bin/printf', ['%s', '$HOME']);
    assert.equal(literal.stdout(), '$HOME');
    assert.deepEqual(literal.result, { kind: 'exited', code: 0 });
    const script = await machine.execScript('printf "%s" "$((6 * 7))" | cat');
    assert.equal(script.stdout(), '42');
    const session = await machine.spawn('/bin/cat', [], { pipeStdin: true });
    let started = false;
    for (;;) { const event = await session.recv(); assert(event); if (event.kind === 'started') { started = true; break; } }
    assert(started);
    const stdin = session.stdin(); assert(stdin);
    const bytes = Buffer.alloc(150123, 113);
    const collected = session.collect();
    await stdin.write(bytes);
    await stdin.close();
    const output = await collected;
    assert.deepEqual(Buffer.from(output.stdoutBytes()), bytes);
    assert.deepEqual(output.result, { kind: 'exited', code: 0 });
  }
  const login = await finiteShell('printf "\\nNODE_LOGIN USER=%s HOME=%s TERM=%s SIZE=" "$USER" "$HOME" "$TERM"; stty size; exit 7\n');
  assert.equal(login.status.code, 7);
  assert.match(login.text, /NODE_LOGIN USER=silo HOME=\/home\/silo TERM=xterm-256color SIZE=37 119\n/);
  // More than each bounded native pipe capacity, with input/control traffic.
  const bulk = await finiteShell('stty -echo; printf "\\nBULK_BEGIN\\n"; head -c 150123 /dev/zero | tr "\\000" A; head -c 150123 /dev/zero | tr "\\000" B >&2; printf "\\nBULK_END\\n"; exit 7\n');
  assert.equal(bulk.status.code, 7);
  assert(bulk.text.includes('\nBULK_BEGIN\n' + 'A'.repeat(150123) + 'B'.repeat(150123) + '\nBULK_END\n'));
  // Pending caller input must unblock after native success, not leak a worker.
  let stopped = false;
  const blocked = await machine.shell({ signal: deadline.signal, attachment: {
    rows: 37, columns: 119,
    async *stdin(signal) { try { yield Buffer.from('exit 7\n'); await delay(60000, undefined, { signal }); } finally { stopped = true; } },
    async *controls(signal) { yield { kind: 'resize', rows: 37, columns: 119 }; await delay(60000, undefined, { signal }); },
  } });
  assert.equal(blocked.code, 7); assert(stopped);
  const resizedChunks = [];
  const resized = await machine.shell({ signal: deadline.signal, term: 'xterm-256color', attachment: {
    rows: 37, columns: 119,
    async *stdin() { yield Buffer.from('sleep 0.2; printf "\\nRESIZED="; stty size; exit 7\n'); },
    async *controls() { yield { kind: 'resize', rows: 41, columns: 123 }; },
    async stdout(chunk) { resizedChunks.push(Buffer.from(chunk)); },
  } });
  assert.equal(resized.code, 7);
  assert.match(Buffer.concat(resizedChunks).toString().replaceAll('\r', ''), /\nRESIZED=41 123\n/);
  let signalReady;
  const readyForSignal = new Promise(resolve => { signalReady = resolve; });
  const signalChunks = [];
  const signaled = await machine.shell({ signal: deadline.signal, attachment: {
    rows: 37, columns: 119,
    async *stdin() { yield Buffer.from('trap \'printf "\\nUSR1_ACK\\n"; exit 7\' USR1; printf "\\nSIGNAL_READY\\n"; while :; do :; done\n'); },
    async *controls(signal) {
      await Promise.race([readyForSignal, delay(5000, undefined, { signal }).then(() => { throw new Error('signal readiness deadline'); })]);
      yield { kind: 'signal', signal: 'USR1' };
    },
    async stdout(chunk) {
      signalChunks.push(Buffer.from(chunk));
      if (Buffer.concat(signalChunks).toString().replaceAll('\r', '').includes('\nSIGNAL_READY\n')) signalReady();
    },
  } });
  assert.equal(signaled.code, 7);
  assert.match(Buffer.concat(signalChunks).toString().replaceAll('\r', ''), /\nUSR1_ACK\n/);
  await assert.rejects(machine.shell({ attachment: { rows: 0, columns: 119 } }), /dimensions/);
  await assert.rejects(machine.shell({ detachKeys: 'ctrl-]', attachment: { rows: 37, columns: 119 } }), /detachKeys/);
  assert.equal(deadline.signal.aborted, false, 'successful shells must not cancel caller token');
  const canceled = new AbortController();
  let sawOutput;
  const seen = new Promise(resolve => { sawOutput = resolve; });
  const active = machine.shell({ signal: canceled.signal, attachment: {
    rows: 37, columns: 119,
    async *stdin(signal) { yield Buffer.from('printf "ACTIVE\\n"; sleep 30\n'); await delay(60000, undefined, { signal }); },
    async stdout() { sawOutput(); },
  } });
  const rejected = assert.rejects(active);
  // Cancel one connection while another independently drains to success.
  const survivor = finiteShell('sleep 0.2; printf "\\nSURVIVED=%s\\n" "$USER"; exit 7\n');
  await seen; canceled.abort(new Error('intentional cancellation')); await rejected;
  const survived = await survivor;
  assert.equal(survived.status.code, 7); assert.match(survived.text, /\nSURVIVED=silo\n/);
  const again = await finiteShell('printf "\\nRECONNECTED=%s\\n" "$USER"; exit 7\n');
  assert.equal(again.status.code, 7); assert.match(again.text, /\nRECONNECTED=silo\n/);
  // Sink failure must cancel a producer blocked beyond the native pipe bound.
  const broken = machine.shell({ signal: deadline.signal, attachment: {
    rows: 37, columns: 119,
    async *stdin() { yield Buffer.from('head -c 1000000 /dev/zero\n'); },
    async stdout() { throw new Error('intentional sink failure'); },
  } });
  await assert.rejects(broken, /intentional sink failure/);
  // Abort while the guest has exited but a caller output write is pending.
  const drainingAbort = new AbortController();
  let sinkEntered;
  const sinkReady = new Promise(resolve => { sinkEntered = resolve; });
  const draining = machine.shell({ signal: drainingAbort.signal, attachment: {
    rows: 37, columns: 119,
    async *stdin() { yield Buffer.from('printf "\\nDRAIN\\n"; exit 7\n'); },
    async stdout(_chunk, signal) { sinkEntered(); await delay(60000, undefined, { signal }); },
  } });
  const drainRejected = assert.rejects(draining);
  await sinkReady; await delay(100);
  drainingAbort.abort(new Error('intentional drain cancellation')); await drainRejected;
  const final = await finiteShell('printf "\\nFINAL=%s\\n" "$USER"; exit 7\n');
  assert.equal(final.status.code, 7); assert.match(final.text, /\nFINAL=silo\n/);
  console.log(`Node ${mode} execution/SSH qualification passed`);
} finally { clearTimeout(timer); }
