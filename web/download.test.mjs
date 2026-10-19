import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
import { MessageChannel } from 'node:worker_threads';
import { webcrypto } from 'node:crypto';
import { CHUNK_SIZE, MEMORY_LIMIT, decodeKey, encodeKey, importKey, encryptChunk, decryptChunk, parseManifest, FramedReader, formatBytes, deriveClaimToken, serializeManifest } from './crypto.js';
import { ZipWriter, archiveSize } from './zip.js';

const flushMessages = () => new Promise(resolve => setImmediate(() => setImmediate(resolve)));

const workerSource = await readFile(new URL('./download-worker.js', import.meta.url), 'utf8');
const clientSource = await readFile(new URL('./download.js', import.meta.url), 'utf8');
const origin = 'https://vault.example';
const token = 'a'.repeat(64);
const nonce = 'b'.repeat(64);

function harness() {
  const listeners = new Map();
  const timers = new Set();
  const deadlines = new Map();
  let now = 0;
  function advance(milliseconds) {
    const target = now + milliseconds;
    while (deadlines.size) {
      const [callback, deadline] = [...deadlines].sort((a, b) => a[1] - b[1])[0];
      if (deadline > target) break;
      now = deadline;
      deadlines.delete(callback);
      timers.delete(callback);
      callback();
    }
    now = target;
  }
  const owners = new Map([['owner', { id: 'owner', type: 'window', url: `${origin}/package/example` }]]);
  let claims = 0;
  const self = {
    location: { origin },
    clients: { get: async id => owners.get(id), claim: async () => { claims++; } },
    addEventListener: (name, callback) => listeners.set(name, callback)
  };
  vm.runInNewContext(workerSource, {
    self, URL, Response, ReadableStream, Uint8Array, Number, Error,
    setTimeout: (callback, milliseconds) => { timers.add(callback); deadlines.set(callback, now + milliseconds); return callback; },
    clearTimeout: callback => { timers.delete(callback); deadlines.delete(callback); }
  });
  const fetchRoute = (path = `/local-download/${token}`, options = {}) => {
    let result;
    const request = { url: `${origin}${path}`, method: 'GET', mode: 'navigate', ...options.request };
    listeners.get('fetch')({ request, clientId: options.clientId ?? 'owner', respondWith: value => { result = value; } });
    return result;
  };
  async function prepare(extra = {}, source = { id: 'owner' }) {
    const { port1, port2 } = new MessageChannel();
    const queue = [];
    const waiting = [];
    port1.on('message', message => waiting.length ? waiting.shift()(message) : queue.push(message));
    let task;
    listeners.get('message')({ data: { type: 'prepare-download', token, nonce, ...extra }, ports: [port2], source, waitUntil: value => { task = value; } });
    await task;
    return {
      send: (type, more = {}) => port1.postMessage({ type, nonce, ...more }),
      next: () => queue.length ? Promise.resolve(queue.shift()) : new Promise(resolve => waiting.push(resolve)),
      close: () => port1.close(),
      port: port1
    };
  }
  return { self, listeners, owners, timers, fetchRoute, prepare, advance, now: () => now, claims: () => claims };
}

async function initialized(h, size = 3) {
  const port = await h.prepare();
  assert.equal((await port.next()).type, 'ready');
  port.send('initialize', { fileName: 'archive.zip', size });
  assert.equal((await port.next()).type, 'initialized');
  return port;
}

test('worker only intercepts exact same-origin capability GET routes and activates without skipWaiting', async () => {
  const h = harness();
  for (const path of ['/', '/admin', '/api/packages/example', '/download-worker.js', `/local-download/${token}?x=1`, '/local-download/short']) assert.equal(h.fetchRoute(path), undefined);
  assert.equal(h.fetchRoute(undefined, { request: { method: 'POST' } }), undefined);
  assert.equal(h.fetchRoute(undefined, { request: { url: `https://other.example/local-download/${token}` } }), undefined);
  assert.equal((await h.fetchRoute()).status, 404);
  let activation;
  h.listeners.get('activate')({ waitUntil: promise => { activation = promise; } });
  await activation;
  assert.equal(h.claims(), 1);
  assert.doesNotMatch(workerSource, /skipWaiting\(/);
});

test('probe proves interception and consumes its independent capability exactly once', async () => {
  const h = harness();
  const port = await h.prepare({ probe: true });
  assert.equal((await port.next()).type, 'ready');
  const response = await h.fetchRoute();
  assert.equal(response.status, 204);
  assert.equal(response.headers.get('X-Local-Download'), token);
  assert.equal((await h.fetchRoute()).status, 404);
  assert.equal(h.timers.size, 0);
  port.close();
});

test('one-use stream has exact ZIP headers, pull/ack backpressure and bounded chunks', async () => {
  const h = harness();
  const port = await initialized(h);
  const [response, duplicate] = await Promise.all([h.fetchRoute(), h.fetchRoute()]);
  assert.equal(duplicate.status, 404);
  assert.equal(response.headers.get('Content-Length'), '3');
  assert.equal(response.headers.get('Content-Disposition'), 'attachment; filename="archive.zip"');
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  const messages = [await port.next(), await port.next()];
  assert.deepEqual(messages.map(message => message.type).sort(), ['pull', 'started']);
  port.send('chunk', { bytes: new Uint8Array([1, 2]) });
  assert.equal((await port.next()).type, 'ack');
  // No second pull until the one-chunk queue is actually drained.
  const reader = response.body.getReader();
  assert.deepEqual((await reader.read()).value, new Uint8Array([1, 2]));
  assert.equal((await port.next()).type, 'pull');
  port.send('chunk', { bytes: new Uint8Array([3]) });
  assert.equal((await port.next()).type, 'ack');
  port.send('close');
  assert.equal((await port.next()).type, 'closed');
  assert.deepEqual((await reader.read()).value, new Uint8Array([3]));
  assert.equal((await reader.read()).done, true);
  assert.equal(h.timers.size, 0);
  port.close();
});

test('different-client fetch is rejected but capability navigation may create an iframe client', async () => {
  const h = harness();
  const port = await initialized(h, 0);
  assert.equal((await h.fetchRoute(undefined, { clientId: 'other', request: { mode: 'cors' } })).status, 403);
  const response = await h.fetchRoute(undefined, { clientId: 'new-iframe' });
  assert.equal(response.status, 200);
  await response.body.cancel();
  const messages = [await port.next(), await port.next(), await port.next()];
  assert.equal(messages.at(-1).type, 'error');
  assert.equal((await h.fetchRoute()).status, 404);
  port.close();
});

test('nonce is checked; malformed or oversized data destroys the stream', async () => {
  const h = harness();
  const port = await initialized(h, 1);
  port.send('abort', { nonce: 'wrong' });
  const response = await h.fetchRoute();
  await port.next();
  await port.next();
  port.send('chunk', { bytes: new Uint8Array(8 * 1024 * 1024 + 1) });
  assert.equal((await port.next()).type, 'error');
  await assert.rejects(response.body.getReader().read(), /protocol/);
  assert.equal((await h.fetchRoute()).status, 404);
  assert.equal(h.timers.size, 0);
  port.close();
});

test('closed owner and idle timeout purge prepared sessions', async () => {
  const h = harness();
  const port = await initialized(h);
  h.owners.delete('owner');
  assert.equal((await h.fetchRoute()).status, 410);
  assert.equal((await port.next()).type, 'error');
  port.close();
  const h2 = harness();
  const other = await initialized(h2);
  [...h2.timers][0]();
  assert.equal((await other.next()).type, 'error');
  assert.equal((await h2.fetchRoute()).status, 404);
  other.close();
});

test('stream cannot start before known size and rejects short completion', async () => {
  const h = harness();
  const port = await h.prepare();
  await port.next();
  assert.equal((await h.fetchRoute()).status, 409);
  port.send('initialize', { fileName: 'archive.zip', size: 10 });
  await port.next();
  const response = await h.fetchRoute();
  await port.next();
  await port.next();
  port.send('close');
  assert.equal((await port.next()).type, 'error');
  await assert.rejects(response.body.getReader().read());
  port.close();
});

test('ciphertext progress renews only the authenticated session and stalled reads still expire', async () => {
  const h = harness();
  const port = await initialized(h);
  const response = await h.fetchRoute();
  await port.next();
  await port.next();
  try {
    h.advance(90000);
    port.send('progress', { bytes: 65536 });
    await flushMessages();
    h.advance(119999);
    assert.equal(h.timers.size, 1, 'actual encrypted reads renew the finite idle deadline');
    port.send('progress', { bytes: 65536, nonce: 'wrong' });
    await flushMessages();
    h.advance(1);
    assert.match((await port.next()).message, /timed out/);
    await assert.rejects(response.body.getReader().read(), /timed out/);
    assert.equal(h.timers.size, 0);
  } finally { port.close(); }
});

test('ciphertext progress never grants plaintext write credit through downstream backpressure', async () => {
  const h = harness();
  const port = await initialized(h, 2);
  const response = await h.fetchRoute();
  await port.next();
  await port.next();
  try {
    port.send('chunk', { bytes: new Uint8Array([1]) });
    assert.equal((await port.next()).type, 'ack');
    port.send('progress', { bytes: 65536 });
    port.send('chunk', { bytes: new Uint8Array([2]) });
    assert.match((await port.next()).message, /protocol/);
    await assert.rejects(response.body.getReader().read(), /protocol/);
    assert.equal(h.timers.size, 0);
  } finally { port.close(); }
});

test('ciphertext progress rejects empty or invalid activity and cannot exceed the finite package budget', async () => {
  for (const bytes of [0, -1, 0.5, NaN, CHUNK_SIZE + 17]) {
    const h = harness();
    const port = await initialized(h);
    try {
      port.send('progress', { bytes });
      assert.match((await port.next()).message, /protocol/);
      assert.equal(h.timers.size, 0);
    } finally { port.close(); }
  }
  const h = harness();
  const port = await initialized(h);
  try {
    const limit = 20 * 1024 ** 3 + CHUNK_SIZE + 30000 * 20;
    const chunk = CHUNK_SIZE + 16;
    for (let i = 0; i < Math.floor(limit / chunk); i++) port.send('progress', { bytes: chunk });
    port.send('progress', { bytes: limit % chunk });
    await flushMessages();
    assert.equal(h.timers.size, 1);
    port.send('progress', { bytes: 1 });
    assert.match((await port.next()).message, /protocol/);
    assert.equal(h.timers.size, 0);
  } finally { port.close(); }
});

test('progressive 64 KiB/s ciphertext keeps an 8 MiB record alive beyond 120 seconds and saves the ZIP', async () => {
  const h = harness();
  const raw = new Uint8Array(32).fill(19);
  const key = await importKey(raw);
  const files = [{ path: 'slow.bin', size: CHUNK_SIZE, lastModified: 0 }];
  const contents = new Uint8Array(CHUNK_SIZE).fill(41);
  const { plaintext } = serializeManifest(files);
  const records = await Promise.all([plaintext, contents].map((bytes, index) => encryptChunk(key, 'pkg-123', index, bytes)));
  const body = Buffer.concat(records.flatMap(record => {
    const header = Buffer.alloc(4);
    header.writeUInt32BE(record.length);
    return [header, record];
  }));
  const saved = [];
  let background;
  let streamError;
  let claims = 0;
  let offset = 0;
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, {
      hidden: false, disabled: false, checked: false, textContent: '',
      classList: { toggle() {} }, addEventListener() {}
    });
    return elements.get(id);
  };
  const worker = {
    scriptURL: `${origin}/download-worker.js`,
    postMessage(data, ports) { h.listeners.get('message')({ data, ports, source: { id: 'owner' }, waitUntil() {} }); }
  };
  const location = { origin, pathname: '/package/pkg-123', search: '', hash: `#${encodeKey(raw)}` };
  const context = vm.createContext({
    CHUNK_SIZE, MEMORY_LIMIT, decodeKey, importKey, decryptChunk, parseManifest, FramedReader,
    formatBytes, deriveClaimToken, ZipWriter, archiveSize,
    window: { isSecureContext: true, addEventListener() {}, removeEventListener() {} },
    navigator: { serviceWorker: { controller: worker, register: async () => ({ active: worker }) } },
    document: {
      getElementById: element,
      createElement: () => ({ remove() {} }),
      body: { append(frame) {
        background = (async () => {
          const response = await h.fetchRoute(frame.src, { clientId: 'iframe' });
          assert.equal(response.headers.get('Content-Length'), String(archiveSize(files)));
          const reader = response.body.getReader();
          while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            saved.push(Buffer.from(value));
          }
        })().catch(error => { streamError = error; });
      } }
    },
    location, history: { replaceState() { location.hash = ''; } },
    crypto: webcrypto, MessageChannel, ReadableStream, Uint8Array, URL, DOMException, AbortController, TextDecoder,
    setTimeout, clearTimeout,
    fetch: async (path, options) => {
      if (path.startsWith('/local-download/')) return h.fetchRoute(path, { request: { mode: 'cors' } });
      if (options.method !== 'POST') return Response.json({ status: 'ready', expiresAt: '2099-01-01T00:00:00Z' });
      claims++;
      return new Response(new ReadableStream({ async pull(controller) {
        if (offset === body.length) { controller.close(); return; }
        await flushMessages();
        h.advance(1000);
        const next = Math.min(offset + 65536, body.length);
        controller.enqueue(body.subarray(offset, next));
        offset = next;
      } }, { highWaterMark: 0 }));
    }
  });
  vm.runInContext(clientSource.replace('export async function', 'async function'), context);
  const publicSource = await readFile(new URL('./public.js', import.meta.url), 'utf8');
  vm.runInContext(publicSource.replace(/^import .*;\n/gm, ''), context);
  for (let i = 0; i < 100 && element('package-state').textContent !== 'Ready'; i++) await flushMessages();
  assert.equal(element('package-state').textContent, 'Ready');
  element('download-consent').checked = true;
  await context.download();
  await background;
  assert.ok(h.now() > 120000, 'one encrypted record alone takes over two minutes');
  assert.equal(element('package-state').textContent, 'Downloaded');
  assert.equal(streamError, undefined);
  assert.equal(claims, 1);
  const archive = Buffer.concat(saved);
  assert.equal(archive.length, archiveSize(files));
  const dataOffset = 30 + archive.readUInt16LE(26);
  assert.deepEqual(archive.subarray(dataOffset, dataOffset + CHUNK_SIZE), Buffer.from(contents));
  assert.equal(h.timers.size, 0);
});

test('unsupported browser feature detection preserves bounded Blob fallback', async () => {
  const context = vm.createContext({ window: { isSecureContext: true }, navigator: {}, setTimeout, clearTimeout });
  vm.runInContext(clientSource.replace('export async function', 'async function') + '\nthis.prepare = prepareServiceWorkerDownload;', context);
  assert.equal(await context.prepare(), null);
});

test('client prepares with a real channel/probe and streams locally without a file key', async () => {
  const h = harness();
  let reader;
  const saved = [];
  let background;
  const events = new Map();
  const worker = {
    scriptURL: `${origin}/download-worker.js`,
    postMessage(data, ports) { h.listeners.get('message')({ data, ports, source: { id: 'owner' }, waitUntil: () => {} }); }
  };
  const document = {
    createElement: () => ({ remove() {} }),
    body: { append(frame) {
      background = (async () => {
        const response = await h.fetchRoute(frame.src, { clientId: 'iframe' });
        assert.equal(response.headers.get('Content-Length'), '4');
        reader = response.body.getReader();
        while (true) {
          const result = await reader.read();
          if (result.done) break;
          saved.push(...result.value);
        }
      })();
    } }
  };
  const controlEvents = new Map();
  const serviceWorker = {
    controller: null,
    async register(url, options) {
      assert.equal(url, `${origin}/download-worker.js`);
      assert.equal(options.scope, '/');
      setTimeout(() => { this.controller = worker; controlEvents.get('controllerchange')?.(); }, 0);
      return { active: worker };
    },
    addEventListener: (name, callback) => controlEvents.set(name, callback),
    removeEventListener: name => controlEvents.delete(name)
  };
  const context = vm.createContext({
    window: { isSecureContext: true, addEventListener: (name, callback) => events.set(name, callback), removeEventListener: name => events.delete(name) },
    navigator: { serviceWorker },
    location: { origin }, crypto: webcrypto, MessageChannel, ReadableStream, Uint8Array, URL, DOMException,
    document, setTimeout, clearTimeout,
    fetch: async url => h.fetchRoute(url, { request: { mode: 'cors' } })
  });
  vm.runInContext(clientSource.replace('export async function', 'async function') + '\nthis.prepare = prepareServiceWorkerDownload;', context);
  const sink = await context.prepare();
  assert.ok(sink);
  await sink.initialize('archive.zip', 4);
  await sink.write(new Uint8Array([1, 2]));
  await sink.write(new Uint8Array([3, 4]));
  await sink.close();
  await background;
  assert.deepEqual(saved, [1, 2, 3, 4]);
  assert.equal(events.size, 0);
  assert.equal(h.timers.size, 0);
});
