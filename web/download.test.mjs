import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
import { MessageChannel } from 'node:worker_threads';
import { webcrypto } from 'node:crypto';

const workerSource = await readFile(new URL('./download-worker.js', import.meta.url), 'utf8');
const clientSource = await readFile(new URL('./download.js', import.meta.url), 'utf8');
const origin = 'https://drive.example';
const token = 'a'.repeat(64);
const nonce = 'b'.repeat(64);

function harness() {
  const listeners = new Map();
  const timers = new Set();
  const owners = new Map([['owner', { id: 'owner', type: 'window', url: `${origin}/package/example` }]]);
  let claims = 0;
  const self = {
    location: { origin },
    clients: { get: async id => owners.get(id), claim: async () => { claims++; } },
    addEventListener: (name, callback) => listeners.set(name, callback)
  };
  vm.runInNewContext(workerSource, {
    self, URL, Response, ReadableStream, Uint8Array, Number, Error,
    setTimeout: callback => { timers.add(callback); return callback; },
    clearTimeout: callback => timers.delete(callback)
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
  return { self, listeners, owners, timers, fetchRoute, prepare, claims: () => claims };
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
