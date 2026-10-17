import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
import { MessageChannel } from 'node:worker_threads';
import { webcrypto } from 'node:crypto';
import { CHUNK_SIZE, MEMORY_LIMIT, encodeKey, decodeKey, importKey, decryptChunk, parseManifest, FramedReader, formatBytes, serializeManifest, encryptChunk, deriveClaimToken } from './crypto.js';
import { ZipWriter, archiveSize } from './zip.js';

const source = (await readFile(new URL('./download.js', import.meta.url), 'utf8')).replace('export async function', 'async function');

function client(worker, fetch) {
  const context = vm.createContext({
    window: { isSecureContext: true, addEventListener() {}, removeEventListener() {} },
    navigator: { serviceWorker: { controller: worker, register: async () => ({ active: worker }) } },
    location: { origin: 'https://drive.example' }, crypto: webcrypto,
    MessageChannel, ReadableStream, Uint8Array, URL, DOMException, setTimeout, clearTimeout, fetch
  });
  vm.runInContext(source + '\nthis.prepare = prepareServiceWorkerDownload;', context);
  return context.prepare;
}

test('a network 404 probe falls back before creating any plaintext stream session', async () => {
  let preparations = 0;
  const worker = {
    scriptURL: 'https://drive.example/download-worker.js',
    postMessage(message, [port]) {
      preparations++;
      assert.equal(message.probe, true);
      assert.match(message.token, /^[a-f0-9]{64}$/);
      assert.match(message.nonce, /^[a-f0-9]{64}$/);
      assert.notEqual(message.token, message.nonce);
      assert.deepEqual(Object.keys(message).sort(), ['nonce', 'probe', 'token', 'type']);
      port.on('message', data => { if (data.type === 'abort') port.close(); });
      port.postMessage({ type: 'ready', nonce: message.nonce });
    }
  };
  let requests = 0;
  const prepare = client(worker, async (url, options) => {
    requests++;
    assert.match(url, /^\/local-download\/[a-f0-9]{64}$/);
    assert.equal(options.credentials, 'omit');
    assert.equal(options.referrerPolicy, 'no-referrer');
    return new Response(null, { status: 404 });
  });
  assert.equal(await prepare(), null);
  assert.equal(preparations, 1);
  assert.equal(requests, 1);
});

test('terminated worker preparation falls back without dangling promise rejection', async () => {
  const prepare = client({
    scriptURL: 'https://drive.example/download-worker.js',
    postMessage() { throw new Error('Worker terminated'); }
  }, () => assert.fail('No probe should run'));
  assert.equal(await prepare(), null);
});

test('cancellation before preparation never probes or silently selects a fallback', async () => {
  const controller = new AbortController();
  controller.abort();
  const prepare = client({ scriptURL: 'https://drive.example/download-worker.js', postMessage() { assert.fail('Must not prepare a cancelled stream'); } }, () => assert.fail('Must not fetch'));
  await assert.rejects(prepare({ signal: controller.signal }), { name: 'AbortError' });
});

test('preclaim 429 aborts the prepared worker but preserves the key and proof for an explicit successful retry', async () => {
  const raw = new Uint8Array(32).fill(27);
  const id = 'retry-package';
  const files = [{ path: 'retry.txt', size: 0, lastModified: 0 }];
  const { plaintext } = serializeManifest(files);
  const encrypted = await encryptChunk(await importKey(raw), id, 0, plaintext);
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(encrypted.length);
  const body = Buffer.concat([prefix, encrypted]);
  const expectedToken = await deriveClaimToken(raw, id);
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, {
      hidden: false, checked: false, disabled: false, textContent: '',
      classList: { toggle() {} }, addEventListener() {}
    });
    return elements.get(id);
  };
  const sessions = [];
  const proofs = [];
  let claims = 0;
  let rejectedBodyCancelled = false;
  const location = { pathname: `/package/${id}`, search: '', hash: `#${encodeKey(raw)}` };
  const context = vm.createContext({
    CHUNK_SIZE, MEMORY_LIMIT, decodeKey, importKey, decryptChunk, parseManifest, FramedReader,
    formatBytes, ZipWriter, archiveSize, deriveClaimToken,
    prepareServiceWorkerDownload: async ({ signal }) => {
      const session = { signal, aborted: false, closed: false, initialized: false, parts: [] };
      sessions.push(session);
      return {
        async initialize() { session.initialized = true; },
        async write(bytes) { session.parts.push(Buffer.from(bytes)); },
        async close() { session.closed = true; },
        async abort() { session.aborted = true; }
      };
    },
    window: { isSecureContext: true, addEventListener() {} },
    navigator: { serviceWorker: {} }, MessageChannel, ReadableStream, AbortController,
    document: { getElementById: element }, location,
    history: { replaceState() { location.hash = ''; } }, crypto: webcrypto,
    fetch: async (path, options) => {
      assert.ok(!JSON.stringify([path, options]).includes(encodeKey(raw)));
      assert.equal(options.referrerPolicy, 'no-referrer');
      if (options.method !== 'POST') return Response.json({ status: 'ready', expiresAt: '2099-01-01T00:00:00Z' });
      assert.equal(path, `/api/packages/${id}/consume`);
      assert.equal(options.headers['X-Claim-Token'], expectedToken);
      proofs.push(options.headers['X-Claim-Token']);
      claims++;
      return claims === 1 ? new Response(new ReadableStream({ cancel() { rejectedBodyCancelled = true; } }), { status: 429 }) : new Response(body);
    }
  });
  const publicSource = await readFile(new URL('./public.js', import.meta.url), 'utf8');
  vm.runInContext(publicSource.replace(/^import .*;\n/gm, '') + '\nthis.state = () => ({ available, busy, key: keyBytes && [...keyBytes] });', context);
  for (let i = 0; i < 100 && element('package-state').textContent !== 'Ready'; i++) await new Promise(setImmediate);
  element('download-consent').checked = true;
  await context.download();
  assert.equal(claims, 1, '429 must not automatically retry');
  assert.equal(rejectedBodyCancelled, true);
  assert.equal(sessions[0].signal.aborted, true);
  assert.equal(sessions[0].aborted, true);
  assert.equal(sessions[0].initialized, false);
  assert.equal(sessions[0].parts.length, 0);
  assert.equal(context.state().available, true);
  assert.equal(context.state().busy, false);
  assert.deepEqual([...context.state().key], [...raw]);
  assert.equal(element('package-state').textContent, 'Ready');
  assert.equal(element('package-description').textContent, '');
  assert.equal(element('download-consent').disabled, false);
  assert.match(element('download-status').textContent, /server is busy.*not been claimed.*press Download/);
  assert.doesNotMatch(element('download-status').textContent, /cannot be resumed|new package/);
  assert.equal(element('download-progress').hidden, true);
  assert.equal(element('download-meter').value, 0);
  assert.equal(element('download-percent').textContent, '0%');
  assert.equal(element('download-stage').textContent, 'Not started');
  assert.equal(element('cancel-download').hidden, true);
  assert.equal(element('download-button').disabled, false);
  await context.download();
  assert.deepEqual(proofs, [expectedToken, expectedToken]);
  assert.equal(sessions.length, 2, 'retry must prepare a fresh worker session');
  assert.equal(sessions[1].initialized, true);
  assert.equal(sessions[1].closed, true);
  assert.equal(sessions[1].aborted, false);
  assert.equal(Buffer.concat(sessions[1].parts).length, archiveSize(files));
  assert.equal(element('package-state').textContent, 'Downloaded');
  assert.equal(context.state().key, null);
  assert.equal(context.state().available, false);
});

test('failed streaming preparation reveals the Blob limit and requires renewed consent without claiming or forgetting the key', async () => {
  const raw = new Uint8Array(32).fill(17);
  const id = 'small-test';
  const key = await importKey(raw);
  const files = [{ path: 'test.txt', size: 3, lastModified: 0 }];
  const { plaintext } = serializeManifest(files);
  const parts = [];
  for (const [index, bytes] of [plaintext, new Uint8Array([1, 2, 3])].entries()) {
    const ciphertext = await encryptChunk(key, id, index, bytes);
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32BE(ciphertext.byteLength);
    parts.push(prefix, ciphertext);
  }
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, {
      hidden: false, checked: false, disabled: false, textContent: '',
      handlers: new Map(), classList: { toggle() {} },
      addEventListener(type, callback) { this.handlers.set(type, callback); },
      click() { this.clicked = true; }
    });
    return elements.get(id);
  };
  let preparations = 0;
  let claims = 0;
  let imports = 0;
  let derivations = 0;
  const claimKey = await webcrypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']);
  const expectedToken = Buffer.from(await webcrypto.subtle.deriveBits({
    name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode(id),
    info: new TextEncoder().encode('drive.miszori.dev:package-claim:v1')
  }, claimKey, 256)).toString('base64url');
  const blobs = [];
  const location = { pathname: `/package/${id}`, search: '', hash: `#${encodeKey(raw)}` };
  const context = vm.createContext({
    CHUNK_SIZE, MEMORY_LIMIT, decodeKey, decryptChunk, parseManifest, FramedReader, formatBytes, ZipWriter, archiveSize,
    importKey: bytes => { imports++; return importKey(bytes); },
    deriveClaimToken: (bytes, packageID) => { derivations++; return deriveClaimToken(bytes, packageID); },
    prepareServiceWorkerDownload: async () => { preparations++; return null; },
    window: { isSecureContext: true, addEventListener() {} },
    navigator: { serviceWorker: {} }, MessageChannel, ReadableStream, AbortController,
    document: { getElementById: element }, location,
    history: { replaceState() { location.hash = ''; } },
    crypto: webcrypto, Blob, URL: { createObjectURL(blob) { blobs.push(blob); return 'blob:test'; }, revokeObjectURL() {} },
    fetch: async (path, options) => {
      assert.equal(options.referrerPolicy, 'no-referrer');
      assert.equal(options.credentials, 'omit');
      assert.equal(options.body, undefined);
      assert.ok(!JSON.stringify([path, options]).includes(encodeKey(raw)));
      if (options.method === 'POST') {
        assert.equal(path, `/api/packages/${id}/consume`);
        assert.equal(options.headers['X-Claim-Token'], expectedToken);
        assert.deepEqual(Object.keys(options.headers), ['X-Claim-Token']);
        claims++;
        return new Response(Buffer.concat(parts));
      }
      assert.equal(options.headers, undefined);
      return Response.json({ status: 'ready', expiresAt: '2099-01-01T00:00:00Z' });
    }
  });
  const publicSource = await readFile(new URL('./public.js', import.meta.url), 'utf8');
  vm.runInContext(publicSource.replace(/^import .*;\n/gm, '') + '\nthis.state = () => ({ available, busy, key: keyBytes && [...keyBytes] });', context);
  for (let i = 0; i < 100 && element('package-state').textContent !== 'Ready'; i++) await new Promise(setImmediate);
  assert.equal(element('package-state').textContent, 'Ready');
  assert.equal(element('fallback-warning').hidden, true);
  element('download-consent').checked = true;
  await context.download();
  assert.equal(preparations, 1);
  assert.equal(claims, 0);
  assert.equal(imports, 0);
  assert.equal(derivations, 0, 'failed preparation must return before deriving any claim proof');
  assert.equal(blobs.length, 0);
  assert.equal(element('fallback-warning').hidden, false);
  assert.equal(element('download-consent').checked, false);
  assert.equal(element('download-button').disabled, true);
  assert.match(element('download-status').textContent, /128 MiB/);
  assert.match(element('download-status').textContent, /Nothing has been claimed/);
  assert.equal(context.state().available, true);
  assert.equal(context.state().busy, false);
  assert.deepEqual([...context.state().key], [...raw]);
  await context.download();
  assert.equal(claims, 0, 'another click without renewed consent cannot consume');
  assert.equal(derivations, 0, 'renewed consent is required before deriving the claim proof');
  element('download-consent').checked = true;
  element('download-consent').handlers.get('change')();
  assert.equal(element('download-button').disabled, false);
  await context.download();
  assert.equal(preparations, 1, 'the explicitly accepted fallback need not retry a failed transport');
  assert.equal(claims, 1);
  assert.equal(imports, 1);
  assert.equal(derivations, 1);
  assert.equal(blobs.length, 1);
  assert.equal(blobs[0].size, archiveSize(files));
  assert.equal(element('package-state').textContent, 'Downloaded');
  assert.equal(context.state().key, null);
});
