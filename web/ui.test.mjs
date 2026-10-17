import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import { CHUNK_SIZE, MEMORY_LIMIT, encodeKey, decodeKey, importKey, encryptChunk, decryptChunk, parseManifest, serializeManifest } from './crypto.js';
import { archiveSize } from './zip.js';
import { encryptName, decryptName } from './names.js';
import { deriveAdminKeys, adminAuthorization } from './auth.js';
const labelKey = { version: 1, salt: 'AAAAAAAAAAAAAAAAAAAAAA', iterations: 600000 };
const adminPassword = 'admin:random-password:東京-strong-long';
const namePhrase = adminPassword;
const fixtureKeys = await deriveAdminKeys(adminPassword, labelKey);
const expectedAuthorization = adminAuthorization('admin-é', fixtureKeys.authentication);

// A minimal DOM harness exercises the real entry modules without a server or dependencies.
class Element {
  constructor(id = '') {
    this.id = id; this.value = ''; this.hidden = false; this.checked = false;
    this.disabled = false; this.textContent = ''; this.children = []; this.listeners = new Map();
    const classes = new Set();
    this.classList = { toggle(name, force) { if (force ?? !classes.has(name)) classes.add(name); else classes.delete(name); }, contains(name) { return classes.has(name); }, add(name) { classes.add(name); }, remove(name) { classes.delete(name); } };
  }
  addEventListener(type, handler) { this.listeners.set(type, [...(this.listeners.get(type) || []), handler]); }
  async dispatch(type, extra = {}) { for (const handler of this.listeners.get(type) || []) await handler({ target: this, preventDefault() {}, ...extra }); }
  append(...nodes) { this.children.push(...nodes.flatMap(node => node.isFragment ? node.children : [node])); }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
  setAttribute(name, value) { this[name] = value; }
  focus() { this.focused = true; }
  select() { this.selected = true; }
  click() { this.clicked = true; }
  contains() { return false; }
  showModal() { this.open = true; }
  close() { this.open = false; }
  querySelector() { return new Element(); }
}
let serial = 0;
const json = data => Response.json(data);
const ready = () => json({ expiresAt: '2099-01-01T00:00:00Z', status: 'ready' });
const tick = () => new Promise(resolve => setTimeout(resolve, 1));
async function until(predicate) {
  const deadline = Date.now() + 5000;
  while (!predicate()) { if (Date.now() > deadline) throw new Error('UI did not reach its expected state'); await tick(); }
}

async function harness(entry, fetcher, options = {}) {
  const html = await readFile(new URL(entry === 'public' ? './index.html' : './admin.html', import.meta.url), 'utf8');
  const elements = new Map([...html.matchAll(/<[^>]*\bid="([^"]+)"[^>]*>/g)].map(match => {
    const el = new Element(match[1]);
    el.hidden = /\shidden(?:\s|>)/.test(match[0]);
    el.disabled = /\sdisabled(?:\s|>)/.test(match[0]);
    return [match[1], el];
  }));
  const $ = id => { assert.ok(elements.has(id), `Element ${id} exists`); return elements.get(id); };
  const saved = new Map(['window', 'document', 'fetch', 'location', 'history', 'navigator'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  const win = new Element();
  win.isSecureContext = options.secureContext ?? true;
  if (options.picker) win.showSaveFilePicker = options.picker;
  const location = { pathname: entry === 'public' ? '/package/pkg-123' : '/admin/', hostname: options.hostname ?? 'localhost', search: '', hash: options.hash ?? '' };
  const replaced = [];
  Object.defineProperties(globalThis, {
    window: { configurable: true, value: win },
    document: { configurable: true, value: { getElementById: $, createElement: () => new Element(), createDocumentFragment: () => Object.assign(new Element(), { isFragment: true }) } },
    fetch: { configurable: true, value: (path, init) => entry === 'admin' && path === '/admin/api/auth' && options.auth !== false ? json({ initialized: true, username: 'admin-é', labelKey, publicOrigin: 'https://drive.example', ...options.auth }) : fetcher(path, init) },
    location: { configurable: true, value: location },
    history: { configurable: true, value: { replaceState(...args) { replaced.push(args); location.hash = ''; } } },
    navigator: { configurable: true, value: { clipboard: { async writeText(value) { win.clipboard = value; } } } }
  });
  const blobs = [];
  const oldCreateURL = URL.createObjectURL;
  const oldRevokeURL = URL.revokeObjectURL;
  URL.createObjectURL = blob => { blobs.push(blob); return 'blob:test-archive'; };
  URL.revokeObjectURL = () => {};
  await import(`./${entry}.js?ui-test=${++serial}`);
  if (entry === 'admin' && win.isSecureContext && options.waitForAuth !== false) await until(() => !$('login-button').disabled || !/Loading/.test($('login-status').textContent));
  return { $, win, blobs, replaced, restore() {
    URL.createObjectURL = oldCreateURL;
    URL.revokeObjectURL = oldRevokeURL;
    for (const [key, descriptor] of saved) { if (descriptor) Object.defineProperty(globalThis, key, descriptor); else delete globalThis[key]; }
  } };
}

async function packageStream(files, contents, raw = new Uint8Array(32).fill(29)) {
  const { plaintext } = serializeManifest(files);
  const key = await importKey(raw);
  const parts = [];
  for (const [index, bytes] of [plaintext, ...contents].entries()) {
    const ciphertext = await encryptChunk(key, 'pkg-123', index, bytes);
    const header = Buffer.alloc(4); header.writeUInt32BE(ciphertext.length);
    parts.push(header, ciphertext);
  }
  return { raw, body: Buffer.concat(parts) };
}

const files = [{ path: 'folder/hello.txt', size: 5, lastModified: 1720000000000 }, { path: '空.txt', size: 0, lastModified: 0 }];
const content = new TextEncoder().encode('hello');

function assertZip(archive, entries, payloads) {
  const end = archive.length - 22;
  assert.equal(archive.readUInt32LE(end), 0x06054b50);
  assert.equal(archive.readUInt16LE(end + 10), entries.length);
  let directory = archive.readUInt32LE(end + 16);
  for (const [index, file] of entries.entries()) {
    assert.equal(archive.readUInt32LE(directory), 0x02014b50);
    assert.ok(archive.readUInt16LE(directory + 8) & 0x0800, 'ZIP filenames use UTF-8');
    assert.equal(archive.readUInt32LE(directory + 24), file.size);
    const nameLength = archive.readUInt16LE(directory + 28);
    assert.equal(archive.subarray(directory + 46, directory + 46 + nameLength).toString('utf8'), file.path);
    const local = archive.readUInt32LE(directory + 42);
    assert.equal(archive.readUInt32LE(local), 0x04034b50);
    const start = local + 30 + archive.readUInt16LE(local + 26) + archive.readUInt16LE(local + 28);
    assert.deepEqual(archive.subarray(start, start + file.size), Buffer.from(payloads[index]));
    directory += 46 + nameLength + archive.readUInt16LE(directory + 30) + archive.readUInt16LE(directory + 32);
  }
  assert.equal(directory, end);
}

async function independentClaim(raw, id) {
  const key = await webcrypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']);
  const secret = await webcrypto.subtle.deriveBits({
    name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode(id),
    info: new TextEncoder().encode('drive.miszori.dev:package-claim:v1')
  }, key, 256);
  return {
    token: Buffer.from(secret).toString('base64url'),
    hash: Buffer.from(await webcrypto.subtle.digest('SHA-256', secret)).toString('hex')
  };
}

test('public opening removes the key and only explicit consent consumes; fallback saves ZIP', async () => {
  const data = await packageStream(files, [content]);
  const calls = [];
  const proof = await independentClaim(data.raw, 'pkg-123');
  const ui = await harness('public', async (path, options) => {
    assert.equal(location.hash, '');
    assert.equal(options.referrerPolicy, 'no-referrer');
    assert.equal(options.credentials, 'omit');
    assert.equal(options.body, undefined);
    if (options.method === 'POST') {
      assert.equal(path, '/api/packages/pkg-123/consume');
      assert.deepEqual(options.headers, { 'X-Claim-Token': proof.token });
    } else {
      assert.equal(options.headers, undefined, 'metadata checks must not send the claim proof');
    }
    assert.ok(!String(path).includes(encodeKey(data.raw)));
    assert.ok(!JSON.stringify(options).includes(encodeKey(data.raw)));
    calls.push([path, options]);
    return options.method === 'POST' ? new Response(data.body) : ready();
  }, { hash: `#${encodeKey(data.raw)}` });
  try {
    await until(() => ui.$('package-state').textContent === 'Ready');
    assert.equal(calls.length, 1);
    assert.equal(calls[0][1].method, undefined);
    assert.equal(ui.replaced.length, 1);
    assert.equal(ui.$('fallback-warning').hidden, false);
    await ui.$('download-button').dispatch('click');
    assert.equal(calls.length, 1);
    ui.$('download-consent').checked = true;
    await ui.$('download-consent').dispatch('change');
    assert.equal(ui.$('download-button').disabled, false);
    await ui.$('download-button').dispatch('click');
    assert.equal(calls.length, 2);
    assert.equal(ui.blobs.length, 1);
    assert.equal(ui.blobs[0].size, archiveSize(files));
    assert.equal(ui.blobs[0].type, 'application/zip');
    assert.equal(ui.$('save-archive').download, 'drive-pkg-123.zip');
    assertZip(Buffer.from(await ui.blobs[0].arrayBuffer()), files, [content, new Uint8Array()]);
    assert.equal(ui.$('package-state').textContent, 'Downloaded');
    assert.ok(ui.$('save-archive').clicked);
    assert.equal(ui.$('download-button').disabled, true);
    assert.match(ui.$('download-status').textContent, /Archive ready/);
  } finally { ui.restore(); }
});

test('only the checking card is visible until availability resolves, then ready or unavailable replaces it', async () => {
  const html = await readFile(new URL('./index.html', import.meta.url), 'utf8');
  assert.match(html, /id="checking-card"[^>]*>\s*<h1 id="checking-title">Checking package availability<\/h1>\s*<\/section>/);
  assert.match(html, /id="package-card"[^>]*hidden/);
  for (const found of [true, false]) {
    let resolveMetadata;
    const ui = await harness('public', () => new Promise(resolve => { resolveMetadata = resolve; }), { hash: `#${encodeKey(new Uint8Array(32).fill(2))}` });
    try {
      await until(() => resolveMetadata);
      assert.equal(ui.$('checking-card').hidden, false);
      assert.equal(ui.$('package-card').hidden, true);
      resolveMetadata(found ? ready() : new Response(null, { status: 404 }));
      await until(() => !ui.$('package-card').hidden);
      assert.equal(ui.$('checking-card').hidden, true);
      assert.equal(ui.$('package-title').textContent, found ? 'Package ready to download' : 'Package unavailable');
      assert.equal(ui.$('package-facts').hidden, !found);
      if (!found) {
        assert.equal(ui.$('fallback-warning').hidden, true);
        assert.equal(ui.$('consent-label').hidden, true);
        assert.equal(ui.$('download-warning').hidden, true);
      }
    } finally { ui.restore(); }
  }
});

test('missing-key and ready states have distinct colors and reset on a corrected link', async () => {
  let requests = 0;
  const ui = await harness('public', async () => { requests++; return ready(); });
  try {
    await until(() => ui.$('package-state').textContent === 'Unavailable');
    assert.equal(ui.$('download-status').textContent, '');
    assert.equal(ui.$('package-description').textContent, 'This package either does not exist or has already been downloaded.');
    assert.ok(ui.$('package-state').classList.contains('status-unavailable'));
    assert.equal(ui.$('package-state').classList.contains('status-ready'), false);
    assert.equal(requests, 0);
    location.hash = `#${encodeKey(new Uint8Array(32).fill(2))}`;
    await ui.win.dispatch('hashchange');
    await until(() => ui.$('package-state').textContent === 'Ready');
    assert.ok(ui.$('package-state').classList.contains('status-ready'));
    assert.equal(ui.$('package-state').classList.contains('status-unavailable'), false);
    assert.equal(requests, 1);
  } finally { ui.restore(); }
});

test('expired packages lose their ready color without starting a download', async () => {
  const expires = Date.now() + 60000;
  let claims = 0;
  const ui = await harness('public', async (path, options) => {
    if (options.method === 'POST') claims++;
    return json({ status: 'ready', expiresAt: new Date(expires).toISOString() });
  }, { hash: `#${encodeKey(new Uint8Array(32))}` });
  const originalNow = Date.now;
  try {
    await until(() => ui.$('package-state').textContent === 'Ready');
    ui.$('download-consent').checked = true;
    Date.now = () => expires;
    await ui.$('download-button').dispatch('click');
    assert.equal(ui.$('package-state').textContent, 'Unavailable');
    assert.ok(ui.$('package-state').classList.contains('status-unavailable'));
    assert.equal(ui.$('package-state').classList.contains('status-ready'), false);
    assert.equal(claims, 0);
  } finally { Date.now = originalNow; ui.restore(); }
});

test('save picker runs before consuming, and writable output is streamed without a Blob', async () => {
  const data = await packageStream(files, [content]);
  const sequence = [];
  const parts = [];
  const ui = await harness('public', async (path, options) => {
    if (options.method !== 'POST') return ready();
    assert.equal(ui.$('download-consent').disabled, true);
    assert.equal(ui.$('download-consent').checked, true);
    assert.equal(ui.$('package-state').textContent, 'Downloading');
    assert.ok(ui.$('package-state').classList.contains('status-downloading'));
    assert.equal(ui.$('package-state').classList.contains('status-ready'), false);
    assert.equal(ui.$('download-status').textContent, '');
    sequence.push('consume'); return new Response(data.body);
  }, { hash: `#${encodeKey(data.raw)}`, picker(options) {
    assert.equal(options.suggestedName, 'drive-pkg-123.zip');
    assert.deepEqual(options.types, [{ description: 'ZIP archive (all package files)', accept: { 'application/zip': ['.zip'] } }]);
    sequence.push('picker');
    return Promise.resolve({ async createWritable() {
      sequence.push('writable');
      return { async write(bytes) { parts.push(Buffer.from(bytes)); }, async close() { sequence.push('close'); }, async abort() { sequence.push('abort'); } };
    } });
  } });
  try {
    await until(() => ui.$('package-state').textContent === 'Ready');
    ui.$('download-consent').checked = true;
    assert.equal(ui.$('package-description').textContent, '');
    assert.equal(ui.$('package-title').textContent, 'Package ready to download');
    assert.equal(ui.$('download-status').textContent, '');
    assert.equal(ui.$('download-meter').classList.contains('is-complete'), false);
    assert.equal(ui.$('download-consent').disabled, false);
    const downloading = ui.$('download-button').dispatch('click');
    assert.equal(ui.$('download-consent').disabled, true);
    assert.deepEqual(sequence, ['picker']);
    await downloading;
    assert.deepEqual(sequence, ['picker', 'writable', 'consume', 'close']);
    const output = Buffer.concat(parts);
    assert.equal(output.length, archiveSize(files));
    assertZip(output, files, [content, new Uint8Array()]);
    assert.equal(ui.blobs.length, 0);
    assert.equal(ui.$('download-meter').classList.contains('is-complete'), true);
    assert.equal(ui.$('download-consent').disabled, true);
    assert.equal(ui.$('package-state').classList.contains('status-downloading'), false);
  } finally { ui.restore(); }
});

test('429 aborts a file destination and a new explicit attempt can save the package', async () => {
  const data = await packageStream(files, [content]);
  const proof = await independentClaim(data.raw, 'pkg-123');
  let requests = 0;
  let destinations = 0;
  let aborts = 0;
  let closes = 0;
  const parts = [];
  const ui = await harness('public', async (path, options) => {
    if (options.method !== 'POST') return ready();
    assert.deepEqual(options.headers, { 'X-Claim-Token': proof.token });
    return ++requests === 1 ? new Response(null, { status: 429 }) : new Response(data.body);
  }, { hash: `#${encodeKey(data.raw)}`, picker: async () => {
    destinations++;
    return { createWritable: async () => ({
      async write(bytes) { parts.push(Buffer.from(bytes)); },
      async close() { closes++; }, async abort() { aborts++; }
    }) };
  } });
  try {
    await until(() => ui.$('package-state').textContent === 'Ready');
    ui.$('download-consent').checked = true;
    await ui.$('download-button').dispatch('click');
    assert.equal(requests, 1);
    assert.equal(aborts, 1);
    assert.equal(closes, 0);
    assert.equal(parts.length, 0);
    assert.equal(ui.$('download-button').disabled, false);
    assert.equal(ui.$('package-state').textContent, 'Ready');
    assert.match(ui.$('download-status').textContent, /not been claimed/);
    await ui.$('download-button').dispatch('click');
    assert.equal(requests, 2);
    assert.equal(destinations, 2);
    assert.equal(closes, 1);
    assert.equal(aborts, 1);
    assertZip(Buffer.concat(parts), files, [content, new Uint8Array()]);
    assert.equal(ui.$('package-state').textContent, 'Downloaded');
  } finally { ui.restore(); }
});

test('network errors and 502 remain ambiguous irreversible failures, not safe retries', async () => {
  for (const failure of ['network', '502']) {
    let requests = 0;
    let aborts = 0;
    const raw = new Uint8Array(32).fill(9);
    const ui = await harness('public', async (path, options) => {
      if (options.method !== 'POST') return ready();
      requests++;
      if (failure === 'network') throw new TypeError('Network error');
      return new Response(null, { status: 502 });
    }, { hash: `#${encodeKey(raw)}`, picker: async () => ({ createWritable: async () => ({ async abort() { aborts++; } }) }) });
    try {
      await until(() => ui.$('package-state').textContent === 'Ready');
      ui.$('download-consent').checked = true;
      await ui.$('download-button').dispatch('click');
      assert.equal(ui.$('package-state').textContent, 'Unavailable', failure);
      assert.match(ui.$('download-status').textContent, /cannot be resumed/);
      assert.equal(ui.$('download-button').disabled, true);
      await ui.$('download-button').dispatch('click');
      assert.equal(requests, 1);
      assert.equal(aborts, 1);
    } finally { ui.restore(); }
  }
});

test('cancelling the save picker does not consume or invalidate the package', async () => {
  let consumes = 0;
  const raw = new Uint8Array(32);
  const ui = await harness('public', async (path, options) => { if (options.method === 'POST') consumes++; return ready(); }, {
    hash: `#${encodeKey(raw)}`, picker() { throw new DOMException('cancelled', 'AbortError'); }
  });
  try {
    await until(() => ui.$('package-state').textContent === 'Ready');
    ui.$('download-consent').checked = true;
    await ui.$('download-button').dispatch('click');
    assert.equal(consumes, 0);
    assert.equal(ui.$('download-button').disabled, false);
    assert.match(ui.$('download-status').textContent, /not been claimed/);
  } finally { ui.restore(); }
});

test('fallback rejects an oversized manifest before reading file records and cancels the stream', async () => {
  const large = [{ path: 'large.bin', size: MEMORY_LIMIT + 1, lastModified: 0 }];
  const data = await packageStream(large, []);
  let cancelled = false;
  const body = new ReadableStream({ start(controller) { controller.enqueue(data.body); }, cancel() { cancelled = true; } });
  const ui = await harness('public', async (path, options) => options.method === 'POST' ? new Response(body) : ready(), { hash: `#${encodeKey(data.raw)}` });
  try {
    await until(() => ui.$('package-state').textContent === 'Ready');
    ui.$('download-consent').checked = true;
    await ui.$('download-button').dispatch('click');
    assert.equal(cancelled, true);
    assert.equal(ui.blobs.length, 0);
    assert.match(ui.$('download-status').textContent, /128 MiB/);
    assert.equal(ui.$('download-button').disabled, true);
  } finally { ui.restore(); }
});

test('an incomplete transfer aborts the destination and can never be retried', async () => {
  const data = await packageStream(files, [content]);
  let aborts = 0; let closes = 0; let consumes = 0;
  const ui = await harness('public', async (path, options) => {
    if (options.method !== 'POST') return ready();
    consumes++; return new Response(data.body.subarray(0, data.body.length - 1));
  }, { hash: `#${encodeKey(data.raw)}`, picker: async () => ({ createWritable: async () => ({ async write() {}, async close() { closes++; }, async abort() { aborts++; } }) }) });
  try {
    await until(() => ui.$('package-state').textContent === 'Ready');
    ui.$('download-consent').checked = true;
    await ui.$('download-button').dispatch('click');
    await ui.$('download-button').dispatch('click');
    assert.equal(consumes, 1); assert.equal(aborts, 1); assert.equal(closes, 0);
    assert.equal(ui.$('download-meter').classList.contains('is-complete'), false);
    assert.equal(ui.$('package-state').textContent, 'Unavailable');
    assert.equal(ui.$('package-title').textContent, 'Package unavailable');
    assert.match(ui.$('package-description').textContent, /cannot be resumed/);
    assert.doesNotMatch(ui.$('package-description').textContent, /Ready to download/);
    assert.match(ui.$('download-status').textContent, /cannot be resumed/);
  } finally { ui.restore(); }
});

test('same-document reopening strips the key, resets consent, and reports consumed or nonexistent packages', async () => {
  const data = await packageStream(files, [content]);
  let gets = 0; let consumes = 0;
  const ui = await harness('public', async (path, options) => {
    assert.equal(location.hash, '');
    if (options.method === 'POST') { consumes++; return new Response(data.body); }
    gets++;
    return consumes ? new Response(null, { status: 404 }) : ready();
  });
  try {
    await until(() => ui.$('package-state').textContent === 'Unavailable');
    assert.equal(gets, 0);
    location.hash = `#${encodeKey(data.raw)}`;
    await ui.win.dispatch('hashchange');
    assert.equal(location.hash, '');
    await until(() => ui.$('package-state').textContent === 'Ready');
    assert.equal(ui.$('download-button').hidden, false);
    assert.equal(ui.$('download-consent').checked, false);
    ui.$('download-consent').checked = true;
    await ui.$('download-button').dispatch('click');
    assert.equal(consumes, 1);
    location.hash = `#${encodeKey(data.raw)}`;
    await ui.win.dispatch('hashchange');
    await until(() => ui.$('package-state').textContent === 'Unavailable');
    assert.equal(location.hash, '');
    assert.equal(gets, 2);
    assert.equal(ui.$('download-meter').classList.contains('is-complete'), false);
    assert.equal(consumes, 1);
    assert.equal(ui.$('save-archive').hidden, true);
    assert.equal(ui.$('download-consent').checked, false);
    assert.match(ui.$('download-status').textContent, /does not exist.*already been claimed.*expired.*deleted/);
  } finally { ui.restore(); }
});

test('same-document key replacement ignores stale metadata responses', async () => {
  const data = await packageStream(files, [content]);
  let release;
  let gets = 0;
  const ui = await harness('public', async (path, options) => {
    if (options.method === 'POST') return new Response(data.body);
    if (++gets === 1) return new Promise(resolve => { release = () => resolve(new Response(null, { status: 404 })); });
    return ready();
  }, { hash: `#${encodeKey(new Uint8Array(32))}` });
  try {
    await until(() => release);
    location.hash = `#${encodeKey(data.raw)}`;
    await ui.win.dispatch('hashchange');
    await until(() => ui.$('package-state').textContent === 'Ready');
    release();
    await tick();
    assert.equal(ui.$('package-state').textContent, 'Ready');
    ui.$('download-consent').checked = true;
    await ui.$('download-button').dispatch('click');
    assert.equal(ui.$('package-state').textContent, 'Downloaded');
    assert.equal(ui.blobs.length, 1);
  } finally { ui.restore(); }
});

test('hash changes during a save gesture are stripped without replacing the active key or restarting', async () => {
  const data = await packageStream(files, [content]);
  let releasePicker;
  let requests = 0;
  let closed = false;
  const ui = await harness('public', async (path, options) => {
    requests++;
    return options.method === 'POST' ? new Response(data.body) : ready();
  }, { hash: `#${encodeKey(data.raw)}`, picker() {
    return new Promise(resolve => { releasePicker = () => resolve({ createWritable: async () => ({ async write() {}, async close() { closed = true; }, async abort() {} }) }); });
  } });
  try {
    await until(() => ui.$('package-state').textContent === 'Ready');
    ui.$('download-consent').checked = true;
    const downloading = ui.$('download-button').dispatch('click');
    assert.ok(releasePicker);
    location.hash = `#${encodeKey(new Uint8Array(32))}`;
    await ui.win.dispatch('hashchange');
    assert.equal(location.hash, '');
    assert.equal(requests, 1);
    releasePicker();
    await downloading;
    assert.equal(closed, true);
    assert.equal(requests, 2);
    assert.equal(ui.$('package-state').textContent, 'Downloaded');
  } finally { ui.restore(); }
});

async function signedInAdmin(fetcher) {
  const ui = await harness('admin', fetcher);
  ui.$('username').value = 'admin-é';
  ui.$('password').value = adminPassword;
  await ui.$('login-form').dispatch('submit');
  assert.equal(ui.$('workspace').hidden, false);
  assert.equal(ui.$('password').value, '');
  ui.$('ttl').value = '86400';
  return ui;
}

function adminFetcher(onUpload) {
  return async (path, options) => {
    assert.equal(options.headers.Authorization, expectedAuthorization);
    assert.equal(options.credentials, 'omit');
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://drive.example', labelKey });
    if (path === '/admin/api/packages' && !options.method) return json({ packages: [] });
    return onUpload(path, options);
  };
}

test('audit shows compact nonwrapping package IDs but preserves full IDs for titles and deletion', async () => {
  const ids = ['abcdef0123456789'.repeat(4), 'exactly12-idz', 'short-id'];
  const deleted = [];
  const ui = await signedInAdmin(async (path, options) => {
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://drive.miszori.dev', labelKey });
    if (options.method === 'DELETE') { deleted.push(path); return new Response(null, { status: 204 }); }
    return json({ packages: ids.map(id => ({ id, status: 'ready' })) });
  });
  try {
    const rows = ui.$('audit-body').children;
    for (const [index, id] of ids.entries()) {
      const cell = rows[index].children[0];
      assert.equal(cell.children[0].textContent, id.length > 12 ? `${id.slice(0, 12)}…` : id);
      assert.equal(cell.title, id);
      assert.equal(cell.className, 'package-id');
    }
    const button = rows[0].children[5].children[0];
    assert.equal(button['aria-label'], `Delete package ${ids[0]}`);
    await button.dispatch('click');
    assert.equal(ui.$('delete-description').textContent, `Package ${ids[0]}`);
    ui.$('delete-dialog').returnValue = 'confirm';
    await ui.$('delete-dialog').dispatch('close');
    assert.deepEqual(deleted, [`/admin/api/packages/${ids[0]}`]);
    const css = await readFile(new URL('./styles.css', import.meta.url), 'utf8');
    assert.match(css, /\.package-id\s*\{[^}]*white-space:\s*nowrap/);
  } finally { ui.restore(); }
});

test('audit allows deletion only for active data while preserving historic name actions', async () => {
  const statuses = ['uploading', 'ready', 'consuming', 'consumed', 'failed', 'expired', 'deleted', 'future-status', undefined];
  const packages = statuses.map((status, index) => ({ id: `status-${index}`, status }));
  const ui = await signedInAdmin(async path => path.endsWith('/config')
    ? json({ publicOrigin: 'https://drive.example', labelKey }) : json({ packages }));
  try {
    for (const [index, status] of statuses.entries()) {
      const buttons = ui.$('audit-body').children[index].children[5].children;
      assert.deepEqual(buttons.map(button => button.textContent),
        status === 'uploading' || status === 'ready' ? ['Delete', 'Name'] : ['Name'], String(status));
      const name = buttons.at(-1);
      assert.equal(name['aria-label'], `Name package status-${index}`);
      await name.dispatch('click');
      assert.equal(ui.$('name-dialog').open, true);
      await ui.$('cancel-name').dispatch('click');
    }
  } finally { ui.restore(); }
});

test('admin validates upload paths, encrypts sequential records, finalizes and forgets credentials on signout', async () => {
  const uploads = [];
  let finalized;
  const ui = await signedInAdmin(adminFetcher(async (path, options) => {
    uploads.push([path, options]);
    if (options.method === 'POST' && path.endsWith('/packages')) {
      assert.deepEqual(JSON.parse(options.body), { ttlSeconds: 86400 });
      return json({ id: 'pkg-123', uploadToken: 'token', expiresAt: '2099-01-01T00:00:00Z' });
    }
    if (options.method === 'PUT') {
      assert.equal(options.headers['X-Upload-Token'], 'token');
      return new Response(null, { status: 204 });
    }
    if (path.endsWith('/finalize')) { finalized = JSON.parse(options.body); return new Response(null, { status: 204 }); }
    throw new Error(`Unexpected ${path}`);
  }));
  try {
    ui.$('file-input').files = [new File(['bad'], '../bad.txt', { lastModified: 0 })];
    await ui.$('file-input').dispatch('change');
    assert.match(ui.$('upload-status').textContent, /unsafe/);
    assert.equal(uploads.length, 0);
    const first = new File(['hello'], 'hello.txt', { lastModified: 1000 });
    Object.defineProperty(first, 'webkitRelativePath', { value: 'folder/hello.txt' });
    ui.$('file-input').files = [first, new File([], 'empty.txt', { lastModified: 0 })];
    await ui.$('file-input').dispatch('change');
    await ui.$('upload-button').dispatch('click');
    assert.equal(ui.$('result-panel').hidden, false);
    assert.match(finalized.claimHash, /^[a-f0-9]{64}$/);
    const puts = uploads.filter(([, options]) => options.method === 'PUT');
    assert.deepEqual(puts.map(([path]) => path), ['/admin/api/packages/pkg-123/chunks/0', '/admin/api/packages/pkg-123/chunks/1']);
    const link = ui.$('share-link').value;
    assert.ok(link.startsWith('https://drive.example/package/pkg-123#'));
    const keyText = link.split('#')[1];
    assert.match(keyText, /^[A-Za-z0-9_-]{43}$/);
    const proof = await independentClaim(decodeKey(keyText), 'pkg-123');
    assert.deepEqual(finalized, { chunks: 2, claimHash: proof.hash });
    for (const [path, options] of uploads) {
      assert.ok(!path.includes(keyText));
      assert.ok(!JSON.stringify(options.headers).includes(keyText));
      assert.equal(options.headers['X-Claim-Token'], undefined);
      assert.ok(!JSON.stringify(options).includes(proof.token), 'admin must send only the verifier, not the claim token');
      if (typeof options.body === 'string') assert.ok(!options.body.includes(keyText));
    }
    const key = await importKey(decodeKey(keyText));
    const validated = parseManifest(await decryptChunk(key, 'pkg-123', 0, puts[0][1].body));
    assert.equal(validated.manifest.chunkSize, CHUNK_SIZE);
    assert.deepEqual(validated.manifest.files.map(item => item.path), ['folder/hello.txt', 'empty.txt']);
    assert.equal(new TextDecoder().decode(await decryptChunk(key, 'pkg-123', 1, puts[1][1].body)), 'hello');
    await ui.$('copy-link').dispatch('click');
    assert.equal(ui.win.clipboard, link);
    await ui.$('logout').dispatch('click');
    assert.equal(ui.$('share-link').value, '');
    assert.equal(ui.$('workspace').hidden, true);
  } finally { ui.restore(); }
});

test('an ambiguous upload failure is never retried and deletes the partial package', async () => {
  const methods = [];
  const ui = await signedInAdmin(adminFetcher(async (path, options) => {
    methods.push([options.method, path]);
    if (options.method === 'POST') return json({ id: 'pkg-123', uploadToken: 'token', expiresAt: '2099-01-01T00:00:00Z' });
    if (path.endsWith('/chunks/1')) throw new TypeError('Connection lost');
    return new Response(null, { status: 204 });
  }));
  try {
    ui.$('file-input').files = [new File(['hello'], 'hello.txt', { lastModified: 0 })];
    await ui.$('file-input').dispatch('change');
    await ui.$('upload-button').dispatch('click');
    assert.deepEqual(methods.map(([method]) => method), ['POST', 'PUT', 'PUT', 'DELETE']);
    assert.equal(ui.$('result-panel').hidden, true);
    assert.equal(ui.$('share-link').value, '');
    assert.match(ui.$('upload-status').textContent, /server package was deleted/);
  } finally { ui.restore(); }
});

test('cancellation during creation waits for the ID and then deletes without uploading', async () => {
  let release;
  const methods = [];
  const ui = await signedInAdmin(adminFetcher(async (path, options) => {
    methods.push(options.method);
    if (options.method === 'POST') return new Promise(resolve => { release = () => resolve(json({ id: 'pkg-123', uploadToken: 'token', expiresAt: '2099-01-01T00:00:00Z' })); });
    return new Response(null, { status: 204 });
  }));
  try {
    ui.$('file-input').files = [new File(['hello'], 'hello.txt', { lastModified: 0 })];
    await ui.$('file-input').dispatch('change');
    const uploading = ui.$('upload-button').dispatch('click');
    await until(() => release);
    await ui.$('abort-upload').dispatch('click');
    release();
    await uploading;
    assert.deepEqual(methods, ['POST', 'DELETE']);
    assert.match(ui.$('upload-status').textContent, /Upload cancelled/);
  } finally { ui.restore(); }
});

test('HTTP public origins work only between recognized secure-context loopback hosts', async () => {
  for (const [publicOrigin, hostname, allowed] of [
    ['http://localhost:18080', 'localhost', true],
    ['http://127.0.0.1:18080', 'localhost', true],
    ['http://[::1]:18080', '[::1]', true],
    ['http://localhost:18080', 'drive.example', false],
    ['http://drive.example', 'localhost', false],
    ['http://localhost.example', 'localhost', false],
    ['http://localhost@drive.example', 'localhost', false],
    ['https://drive.example', 'drive.example', true]
  ]) {
    const ui = await harness('admin', async path => String(path).endsWith('/config') ? json({ publicOrigin, labelKey }) : json({ packages: [] }), { hostname });
    try {
      ui.$('username').value = 'preview';
      ui.$('password').value = adminPassword;
      await ui.$('login-form').dispatch('submit');
      assert.equal(ui.$('workspace').hidden, !allowed, `${hostname} → ${publicOrigin}`);
      if (!allowed) assert.match(ui.$('login-status').textContent, /valid HTTPS public origin/);
    } finally { ui.restore(); }
  }
});

test('an insecure admin page never sends credentials', async () => {
  let requests = 0;
  const ui = await harness('admin', async () => { requests++; return json({}); }, { secureContext: false });
  try {
    ui.$('username').value = 'preview';
    ui.$('password').value = adminPassword;
    await ui.$('login-form').dispatch('submit');
    assert.equal(requests, 0);
    assert.equal(ui.$('login-button').disabled, true);
    assert.equal(ui.$('crypto-warning').hidden, false);
  } finally { ui.restore(); }
});

test('entrypoints use the exact brand, dark scheme, and task-focused copy', async () => {
  for (const name of ['index', 'admin']) {
    const html = await readFile(new URL(`./${name}.html`, import.meta.url), 'utf8');
    assert.match(html, /<title>drive\.miszori\.dev<\/title>/);
    assert.doesNotMatch(html, /<header|class="brand"/);
    assert.doesNotMatch(html, /<a\b[^>]*\bhref="\/"/);
    assert.match(html, /<meta name="color-scheme" content="dark">/);
    assert.doesNotMatch(html, /A little less|Less exposure|Send it\.|Good things|Private by design|<footer|class="(?:hero|principles|privacy-panel|vault-art|workspace-badge)"/i);
    if (name === 'admin') assert.match(html, /Server logs include IP addresses/);
  }
  const publicHTML = await readFile(new URL('./index.html', import.meta.url), 'utf8');
  assert.match(publicHTML, /Checking package availability/);
  assert.doesNotMatch(publicHTML, /landing-card|Open your package link|Opening this page does not start/);
  assert.match(publicHTML, /even if the download fails or is cancelled/);
  assert.match(publicHTML, /id="download-warning" class="notice warning one-time-warning"/);
  assert.match(publicHTML, /128 MiB, including archive overhead/);
  assert.match(publicHTML, /unknown until you start and claim the one-time download/);
  assert.match(publicHTML, /desktop Chrome or Edge/);
  const adminHTML = await readFile(new URL('./admin.html', import.meta.url), 'utf8');
  assert.match(adminHTML, /Expiry starts at package creation and includes upload time/);
  assert.match(adminHTML, /class="notice warning one-time-warning"><p>One-time download:/);
  assert.match(adminHTML, /key is not saved and cannot be recovered/);
  assert.match(adminHTML, /id="result-panel"[^>]*hidden/);
});

test('share artwork includes the generic receipt message without adding card description text', async () => {
  const generator = await readFile(new URL('../tools/generate-preview.py', import.meta.url), 'utf8');
  const html = await readFile(new URL('./index.html', import.meta.url), 'utf8');
  assert.ok(generator.includes('"You have received an encrypted package."'));
  assert.equal((html.match(/share-preview\.png\?v=3/g) || []).length, 2);
  assert.match(html, /property="og:description" content=""/);
  assert.match(html, /name="twitter:description" content=""/);
});

test('dark palette provides readable text, blue controls and keyboard focus', async () => {
  const css = await readFile(new URL('./styles.css', import.meta.url), 'utf8');
  const colors = Object.fromEntries([...css.matchAll(/--([a-z-]+): (#[0-9a-f]{3,6});/g)].map(([, name, value]) => [name, value]));
  function luminance(color) {
    if (color.length === 4) color = '#' + [...color.slice(1)].map(char => char + char).join('');
    const rgb = color.slice(1).match(/../g).map(hex => {
      const channel = parseInt(hex, 16) / 255;
      return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
    });
    return rgb[0] * 0.2126 + rgb[1] * 0.7152 + rgb[2] * 0.0722;
  }
  function contrast(a, b) {
    const levels = [luminance(a), luminance(b)].sort((x, y) => y - x);
    return (levels[0] + 0.05) / (levels[1] + 0.05);
  }
  assert.match(css, /color-scheme: dark/);
  for (const name of ['background', 'surface', 'input']) assert.equal(colors[name], '#000');
  assert.equal(colors.text, '#fff');
  for (const name of ['muted', 'line', 'warning']) assert.match(colors[name], /^#([a-f0-9])\1{2}(?:\1{3})?$/);
  const channels = value => value.slice(1).match(/../g).map(channel => parseInt(channel, 16));
  const danger = channels(colors.danger), success = channels(colors.success);
  assert.ok(danger[0] > danger[1] && danger[0] > danger[2], 'danger is red');
  assert.ok(success[1] > success[0] && success[1] > success[2], 'ready is green');
  assert.match(css, /\.status-ready\s*\{[^}]*color: var\(--success\)/);
  assert.match(css, /\.status-downloading\s*\{[^}]*color: #facc15/);
  assert.ok(contrast('#facc15', colors.surface) >= 4.5, 'downloading yellow has readable contrast');
  assert.match(css, /#package-description:empty\s*\{[^}]*display: none/);
  for (const selector of ['progress.is-complete', 'progress.is-complete::-webkit-progress-value', 'progress.is-complete::-moz-progress-bar']) {
    assert.ok(css.includes(`${selector} { ${selector === 'progress.is-complete' ? 'accent-color' : 'background'}: var(--success); }`));
  }
  assert.match(css, /\.status-unavailable\s*\{[^}]*color: var\(--danger\)/);
  assert.match(css, /\.notice\.one-time-warning\s*\{[^}]*border-color: var\(--danger\); color: var\(--danger\)/);
  assert.match(css, /\.notice\.one-time-warning strong\s*\{[^}]*color: var\(--danger\)/);
  for (const name of ['text', 'muted', 'danger', 'warning', 'success', 'focus']) {
    assert.ok(contrast(colors[name], colors.surface) >= 4.5, `${name} has readable contrast`);
  }
  for (const name of ['blue', 'blue-hover']) {
    assert.ok(contrast('#ffffff', colors[name]) >= 4.5, `${name} has readable button contrast`);
    assert.ok(parseInt(colors[name].slice(5, 7), 16) > parseInt(colors[name].slice(1, 3), 16));
  }
  assert.match(css, /:focus-visible\s*\{[^}]*outline: 3px solid var\(--focus\)/);
  assert.match(css, /\.file-picker:focus-within/);
  assert.match(css, /@media \(max-width: 540px\)/);
});

test('mobile audit overflow stays inside its scroller, including positioned accessible labels', async () => {
  const css = await readFile(new URL('./styles.css', import.meta.url), 'utf8');
  const scroller = /\.table-scroll\s*\{([^}]+)\}/.exec(css)?.[1];
  assert.ok(scroller);
  // Screen-reader labels in wide columns must not use the page as their containing block.
  assert.match(scroller, /position:\s*relative/);
  assert.match(scroller, /min-width:\s*0/);
  assert.match(scroller, /max-width:\s*100%/);
  assert.match(scroller, /overflow-x:\s*auto/);
  const inputs = /input:not\(\[type="checkbox"\]\):not\(\[type="file"\]\), select\s*\{([^}]+)\}/.exec(css)?.[1];
  assert.ok(inputs);
  assert.match(inputs, /min-width:\s*0/);
  assert.match(inputs, /max-width:\s*100%/);
  assert.doesNotMatch(css, /(?:html|body)\s*\{[^}]*overflow(?:-x)?:\s*(?:hidden|clip)/);
});

test('production and test roots consistently redirect to the personal site', async () => {
  for (const [file, count] of [['../Caddyfile', 4], ['../tests/Caddyfile', 2]]) {
    const config = await readFile(new URL(file, import.meta.url), 'utf8');
    const roots = [...config.matchAll(/handle \/ \{([^}]+)\}/g)];
    assert.equal(roots.length, count);
    for (const [, body] of roots) assert.equal(body.trim(), 'redir https://gergo.miszori.dev 302');
    assert.match(config, /handle (?:@page|\/package\/\*)/);
  }
});

test('HTML entrypoints reference only the agreed self-hosted assets and contain no inline scripts or styles', async () => {
  for (const name of ['index', 'admin']) {
    const html = await readFile(new URL(`./${name}.html`, import.meta.url), 'utf8');
    assert.ok(!/<script(?![^>]*src=)|<style|\son\w+=|\sstyle=/i.test(html));
    assert.match(html, /Content-Security-Policy/);
    const references = [...html.matchAll(/(?:src|href)="([^"]+)"/g)].map(match => match[1]);
    assert.match(html, /<link rel="icon" type="image\/svg\+xml" href="\/favicon.svg">/);
    const allowed = new Set(['/styles.css', '/public.js', '/admin.js', '/favicon.svg', '/', '/admin/', '#main']);
    for (const reference of references) assert.ok(allowed.has(reference), `Allowed asset or navigation: ${reference}`);
  }
});

test('sign-in automatically enables names, upload PATCH precedes chunks, and secrets never enter requests or manifest', async () => {
  const calls = [];
  const ui = await signedInAdmin(adminFetcher(async (path, options) => {
    calls.push([path, options]);
    assert.ok(!JSON.stringify([path, options]).includes(namePhrase));
    assert.ok(!JSON.stringify([path, options]).includes('Private label 東京'));
    if (path.endsWith('/packages') && options.method === 'POST') return json({ id: 'pkg-123', uploadToken: 'token', expiresAt: '2099-01-01T00:00:00Z' });
    return new Response(null, { status: 204 });
  }));
  try {
    assert.equal(ui.$('password').value, '');
    assert.equal(ui.$('package-name').disabled, false);
    ui.$('package-name').value = 'Private label 東京';
    ui.$('file-input').files = [new File(['hello'], 'hello.txt', { lastModified: 0 })];
    await ui.$('file-input').dispatch('change');
    await ui.$('upload-button').dispatch('click');
    assert.deepEqual(calls.map(([, options]) => options.method), ['POST', 'PATCH', 'PUT', 'PUT', 'POST']);
    const patch = JSON.parse(calls[1][1].body);
    assert.deepEqual(Object.keys(patch), ['encryptedName']);
    const { nameKey: key } = fixtureKeys;
    assert.equal(await decryptName(key, 'pkg-123', patch.encryptedName), 'Private label 東京');
    const fileKey = await importKey(decodeKey(ui.$('share-link').value.split('#')[1]));
    const manifest = await decryptChunk(fileKey, 'pkg-123', 0, calls[2][1].body);
    assert.ok(!new TextDecoder().decode(manifest).includes('Private label'));
    assert.ok(!ui.$('share-link').value.includes('Private'));
    assert.equal(ui.$('package-name').value, '');
  } finally { ui.restore(); }
});

test('automatic name decryption tolerates unavailable old labels and supports rename and remove', async () => {
  const { nameKey: key } = fixtureKeys;
  const { nameKey: otherKey } = await deriveAdminKeys('a different historic password', labelKey);
  const packages = [
    { id: 'pkg-123', status: 'consumed', encryptedName: await encryptName(key, 'pkg-123', '<private name>') },
    { id: 'historic', status: 'deleted', encryptedName: await encryptName(otherKey, 'historic', 'historic secret') }
  ];
  const patches = [];
  const ui = await signedInAdmin(async (path, options) => {
    assert.ok(!JSON.stringify([path, options]).includes(namePhrase));
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://drive.example', labelKey });
    if (options.method === 'PATCH') { patches.push(JSON.parse(options.body)); return new Response(null, { status: 204 }); }
    return json({ packages });
  });
  const label = index => ui.$('audit-body').children[index].children[0].children[0].textContent;
  try {
    assert.equal(label(0), '<private name>');
    assert.equal(label(1), 'Name unavailable');
    assert.match(ui.$('audit-status').textContent, /name\(s\) unavailable/);
    const nameButton = ui.$('audit-body').children[0].children[5].children.at(-1);
    assert.equal(nameButton.textContent, 'Name');
    await nameButton.dispatch('click');
    ui.$('rename-name').value = 'New label';
    await ui.$('rename-form').dispatch('submit');
    assert.equal(await decryptName(key, 'pkg-123', patches[0].encryptedName), 'New label');
    await nameButton.dispatch('click');
    await ui.$('rename-form').dispatch('submit');
    assert.deepEqual(patches[1], { encryptedName: null });
  } finally { ui.restore(); }
});

test('signout and pagehide erase plaintext and reject late audit work', async () => {
  const key = fixtureKeys.nameKey;
  const packages = [{ id: 'pkg-123', encryptedName: await encryptName(key, 'pkg-123', 'Only in memory') }];
  let defer = false;
  let release;
  const ui = await signedInAdmin(async path => {
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://drive.example', labelKey });
    if (defer) return new Promise(resolve => { release = () => resolve(json({ packages })); });
    return json({ packages });
  });
  try {
    const oldLabel = ui.$('audit-body').children[0].children[0].children[0];
    assert.equal(oldLabel.textContent, 'Only in memory');
    defer = true;
    const refresh = ui.$('refresh-list').dispatch('click');
    await until(() => release);
    ui.$('package-name').value = 'Draft secret';
    await ui.$('logout').dispatch('click');
    assert.equal(ui.$('package-name').value, '');
    assert.equal(oldLabel.textContent, 'Name unavailable');
    release(); await refresh;
    assert.equal(ui.$('audit-body').children.length, 0);
    defer = false;
    ui.$('password').value = adminPassword;
    await ui.$('login-form').dispatch('submit');
    ui.$('package-name').value = 'Draft secret';
    await ui.win.dispatch('pagehide');
    assert.equal(ui.$('package-name').disabled, true);
    assert.equal(ui.$('package-name').value, '');
    assert.equal(ui.$('password').value, '');
    assert.equal(ui.$('audit-body').children.length, 0);
    assert.equal(ui.$('workspace').hidden, true);
  } finally { ui.restore(); }
});

test('failed encrypted name PATCH aborts and deletes before any file upload', async () => {
  const methods = [];
  const ui = await signedInAdmin(adminFetcher(async (path, options) => {
    methods.push(options.method);
    if (options.method === 'POST') return json({ id: 'pkg-123', uploadToken: 'token', expiresAt: '2099-01-01T00:00:00Z' });
    if (options.method === 'PATCH') return new Response(null, { status: 500 });
    return new Response(null, { status: 204 });
  }));
  try {
    ui.$('package-name').value = 'Private name';
    ui.$('file-input').files = [new File(['hello'], 'hello.txt', { lastModified: 0 })];
    await ui.$('file-input').dispatch('change');
    await ui.$('upload-button').dispatch('click');
    assert.deepEqual(methods, ['POST', 'PATCH', 'DELETE']);
    assert.equal(ui.$('result-panel').hidden, true);
    assert.match(ui.$('upload-status').textContent, /server package was deleted/);
  } finally { ui.restore(); }
});

test('passive recipient profile uses safe text nodes and old records show a dash', async () => {
  const hostile = '<img src=x onerror=alert(1)>';
  const ui = await signedInAdmin(async path => path.endsWith('/config') ? json({ publicOrigin: 'https://drive.example', labelKey }) : json({ packages: [
    { id: 'pkg', openedAt: '2026-01-01T00:00:00Z', openedIp: '192.0.2.1', openedBrowser: { browser: hostile, os: 'Windows', deviceType: 'desktop', userAgent: hostile } }, { id: 'old' }
  ] }));
  try {
    const profile = ui.$('audit-body').children[0].children[4].children[2];
    assert.equal(profile.textContent, `${hostile} / Windows / desktop`);
    assert.equal(profile.title, hostile);
    assert.equal(profile.children.length, 0);
    assert.equal(ui.$('audit-body').children[1].children[4].children[2].textContent, '—');
    const admin = await readFile(new URL('./admin.js', import.meta.url), 'utf8');
    assert.doesNotMatch(admin, /innerHTML|localStorage|sessionStorage|sendBeacon/);
    const html = await readFile(new URL('./admin.html', import.meta.url), 'utf8');
    assert.match(html, /Server logs include IP addresses, reported browser\/device details, encrypted sizes, and timing/);
    assert.match(html, /passive and may be spoofed/);
    assert.doesNotMatch(html, /names-passphrase|names-form|lock-names|unlock-names/);
  } finally { ui.restore(); }
});

test('late decryption cannot reinsert plaintext after signout, and detached labels are scrubbed', async () => {
  const { nameKey: key } = fixtureKeys;
  const packages = [{ id: 'pkg-123', encryptedName: await encryptName(key, 'pkg-123', 'Sensitive label') }];
  const ui = await signedInAdmin(async path => path.endsWith('/config') ? json({ publicOrigin: 'https://drive.example', labelKey }) : json({ packages }));
  const originalDecrypt = crypto.subtle.decrypt;
  let release;
  try {
    const oldLabel = ui.$('audit-body').children[0].children[0].children[0];
    assert.equal(oldLabel.textContent, 'Sensitive label');
    crypto.subtle.decrypt = function (...args) {
      return new Promise((resolve, reject) => { release = () => originalDecrypt.apply(this, args).then(resolve, reject); });
    };
    const refresh = ui.$('refresh-list').dispatch('click');
    await until(() => release);
    await ui.$('logout').dispatch('click');
    assert.equal(oldLabel.textContent, 'Name unavailable');
    release();
    await refresh;
    assert.equal(ui.$('audit-body').children.length, 0);
    assert.equal(ui.$('package-name').disabled, true);
  } finally { crypto.subtle.decrypt = originalDecrypt; ui.restore(); }
});


test('first login sets a password once and automatically enables private names without sending it', async () => {
  const calls = [];
  const token = 'one-time-private-setup-token';
  const ui = await harness('admin', async (path, options) => {
    calls.push([path, options]);
    assert.ok(!JSON.stringify([path, options]).includes(adminPassword));
    if (path.endsWith('/auth')) {
      assert.equal(options.headers, undefined);
      return json({ initialized: false, username: 'admin-é', labelKey, publicOrigin: 'https://drive.example' });
    }
    if (path.endsWith('/setup')) {
      assert.deepEqual(JSON.parse(options.body), { setupToken: token, authentication: fixtureKeys.authentication });
      assert.equal(options.headers.Authorization, undefined);
      return new Response(null, { status: 204 });
    }
    assert.equal(options.headers.Authorization, expectedAuthorization);
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://drive.example', labelKey });
    return json({ packages: [] });
  }, { auth: false });
  try {
    assert.equal(ui.$('setup-fields').hidden, false);
    assert.equal(ui.$('confirm-field').hidden, false);
    assert.equal(ui.$('login-title').textContent, 'Set admin password');
    ui.$('username').value = 'ignored-client-username';
    ui.$('setup-token').value = token;
    ui.$('password').value = adminPassword;
    ui.$('confirm-password').value = adminPassword;
    const signingIn = ui.$('login-form').dispatch('submit');
    assert.equal(ui.$('setup-token').value, '');
    assert.equal(ui.$('password').value, '');
    assert.equal(ui.$('confirm-password').value, '');
    await signingIn;
    assert.equal(ui.$('workspace').hidden, false);
    assert.equal(ui.$('package-name').disabled, false);
    assert.deepEqual(calls.map(([path]) => path), ['/admin/api/auth', '/admin/api/setup', '/admin/api/config', '/admin/api/packages']);
    await ui.$('logout').dispatch('click');
    assert.equal(ui.$('setup-fields').hidden, true);
    assert.equal(ui.$('confirm-field').hidden, true);
    ui.$('password').value = adminPassword;
    await ui.$('login-form').dispatch('submit');
    assert.equal(ui.$('workspace').hidden, false);
    assert.equal(calls.filter(([path]) => path.endsWith('/setup')).length, 1);
  } finally { ui.restore(); }
});

test('setup confirmation and token failures clear all input without silently reusing secrets', async () => {
  let setupRequests = 0;
  const ui = await harness('admin', async (path, options) => {
    assert.ok(!JSON.stringify([path, options]).includes(adminPassword));
    assert.ok(path.endsWith('/setup'));
    ++setupRequests;
    return new Response(null, { status: 403 });
  }, { auth: { initialized: false } });
  try {
    ui.$('setup-token').value = 'one-use-token';
    ui.$('password').value = adminPassword;
    ui.$('confirm-password').value = 'different password';
    await ui.$('login-form').dispatch('submit');
    assert.match(ui.$('login-status').textContent, /Passwords must match/);
    assert.equal(setupRequests, 0);
    assert.equal(ui.$('setup-token').value, '');
    assert.equal(ui.$('password').value, '');
    assert.equal(ui.$('confirm-password').value, '');
    ui.$('setup-token').value = 'wrong-token';
    ui.$('password').value = adminPassword;
    ui.$('confirm-password').value = adminPassword;
    await ui.$('login-form').dispatch('submit');
    assert.equal(setupRequests, 1);
    assert.match(ui.$('login-status').textContent, /token was not accepted/);
    assert.equal(ui.$('setup-token').value, '');
    assert.equal(ui.$('workspace').hidden, true);
    assert.equal(ui.$('package-name').disabled, true);
    ui.$('password').value = adminPassword;
    ui.$('confirm-password').value = adminPassword;
    await ui.$('login-form').dispatch('submit');
    assert.match(ui.$('login-status').textContent, /one-time setup token/);
    assert.equal(setupRequests, 1);
  } finally { ui.restore(); }
});

test('wrong passwords and later 401 responses cannot unlock names or retain a session', async () => {
  const packages = [{ id: 'pkg-123', encryptedName: await encryptName(fixtureKeys.nameKey, 'pkg-123', 'Secret name') }];
  let expired = false;
  const calls = [];
  const ui = await harness('admin', async (path, options) => {
    calls.push([path, options]);
    assert.ok(!JSON.stringify([path, options]).includes(adminPassword));
    assert.ok(!JSON.stringify([path, options]).includes('wrong-but-long-password'));
    if (expired || options.headers.Authorization !== expectedAuthorization) return new Response(null, { status: 401 });
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://drive.example', labelKey });
    return json({ packages });
  });
  try {
    ui.$('password').value = 'wrong-but-long-password';
    await ui.$('login-form').dispatch('submit');
    assert.equal(ui.$('workspace').hidden, true);
    assert.equal(ui.$('package-name').disabled, true);
    assert.equal(ui.$('audit-body').children.length, 0);
    assert.equal(calls.length, 1);
    assert.match(ui.$('login-status').textContent, /Sign-in failed/);
    ui.$('password').value = adminPassword;
    await ui.$('login-form').dispatch('submit');
    const oldLabel = ui.$('audit-body').children[0].children[0].children[0];
    const oldNameButton = ui.$('audit-body').children[0].children[5].children.at(-1);
    assert.equal(oldLabel.textContent, 'Secret name');
    expired = true;
    await ui.$('refresh-list').dispatch('click');
    assert.equal(oldLabel.textContent, 'Name unavailable');
    assert.equal(ui.$('audit-body').children.length, 0);
    assert.equal(ui.$('workspace').hidden, true);
    assert.equal(ui.$('package-name').disabled, true);
    assert.match(ui.$('login-status').textContent, /Sign-in failed/);
    await oldNameButton.dispatch('click');
    assert.ok(!ui.$('name-dialog').open);
    assert.ok(calls.every(([, options]) => options.method !== 'PATCH'));
  } finally { ui.restore(); }
});

test('initial auth configuration is awaited and malformed KDF settings never permit sign-in', async () => {
  let release;
  let requests = 0;
  const ui = await harness('admin', async path => {
    ++requests;
    assert.equal(path, '/admin/api/auth');
    return new Promise(resolve => { release = () => resolve(json({ initialized: true, username: 'admin', labelKey: { ...labelKey, iterations: 1 } })); });
  }, { auth: false, waitForAuth: false });
  try {
    assert.equal(ui.$('login-button').disabled, true);
    ui.$('password').value = adminPassword;
    await ui.$('login-form').dispatch('submit');
    assert.equal(requests, 1);
    release();
    await until(() => /Invalid/.test(ui.$('login-status').textContent));
    assert.equal(ui.$('login-button').disabled, true);
    await ui.win.dispatch('pagehide');
    assert.equal(ui.$('password').value, '');
  } finally { ui.restore(); }
});

test('pagehide during password derivation discards late keys and never authenticates', async () => {
  let requests = 0;
  const ui = await harness('admin', async () => { ++requests; return json({}); });
  const originalDerive = crypto.subtle.deriveBits;
  let release;
  try {
    crypto.subtle.deriveBits = function (algorithm, ...args) {
      if (algorithm.name !== 'PBKDF2') return originalDerive.call(this, algorithm, ...args);
      return new Promise((resolve, reject) => { release = () => originalDerive.call(this, algorithm, ...args).then(resolve, reject); });
    };
    ui.$('password').value = adminPassword;
    const signingIn = ui.$('login-form').dispatch('submit');
    assert.equal(ui.$('password').value, '');
    await until(() => release);
    await ui.win.dispatch('pagehide');
    release();
    await signingIn;
    assert.equal(requests, 0);
    assert.equal(ui.$('workspace').hidden, true);
    assert.equal(ui.$('package-name').disabled, true);
    assert.equal(ui.$('audit-body').children.length, 0);
  } finally { crypto.subtle.deriveBits = originalDerive; ui.restore(); }
});

test('pagehide during label encryption prevents late PATCH and plaintext rendering', async () => {
  let patches = 0;
  const ui = await signedInAdmin(async (path, options) => {
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://drive.example', labelKey });
    if (options.method === 'PATCH') { ++patches; return new Response(null, { status: 204 }); }
    return json({ packages: [{ id: 'pkg-123' }] });
  });
  const originalEncrypt = crypto.subtle.encrypt;
  let release;
  try {
    await ui.$('audit-body').children[0].children[5].children.at(-1).dispatch('click');
    ui.$('rename-name').value = 'Draft secret';
    crypto.subtle.encrypt = function (...args) {
      return new Promise((resolve, reject) => { release = () => originalEncrypt.apply(this, args).then(resolve, reject); });
    };
    const saving = ui.$('rename-form').dispatch('submit');
    await until(() => release);
    await ui.win.dispatch('pagehide');
    release();
    await saving;
    assert.equal(patches, 0);
    assert.equal(ui.$('rename-name').value, '');
    assert.equal(ui.$('rename-status').textContent, '');
    assert.equal(ui.$('audit-body').children.length, 0);
  } finally { crypto.subtle.encrypt = originalEncrypt; ui.restore(); }
});

test('public and admin panels use matching narrower shells without branding headers', async () => {
  const css = await readFile(new URL('./styles.css', import.meta.url), 'utf8');
  const html = await readFile(new URL('./admin.html', import.meta.url), 'utf8');
  assert.match(css, /\.admin-body\s*\{[^}]*max-width:\s*1100px;[^}]*padding:\s*0 24px 40px/);
  assert.match(css, /\.public-shell\s*\{[^}]*max-width:\s*1100px;[^}]*min-height: 100dvh;[^}]*padding:\s*32px 24px;[^}]*display: flex/);
  assert.match(css, /\.public-main\s*\{[^}]*margin-block: auto/);
  assert.match(css, /\.login-panel, \.composer, \.result-panel, \.audit-panel\s*\{\s*width:\s*100%/);
  assert.doesNotMatch(css, /(?:\.composer|\.result-panel|\.login-panel|\.audit-panel)[^{]*\{[^}]*max-width/);
  assert.doesNotMatch(css, /\.site-header, \.admin-header\s*\{[^}]*border-bottom/);
  assert.match(html, /id="username"[^>]*readonly/);
  assert.doesNotMatch(html, /names-form|names-passphrase|unlock-names|lock-names|Separate name encryption/);
});

test('late rename completion cannot close a newer dialog and refreshed detached labels are scrubbed', async () => {
  const encryptedName = await encryptName(fixtureKeys.nameKey, 'pkg-123', 'Original name');
  let release;
  const ui = await signedInAdmin(async (path, options) => {
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://drive.example', labelKey });
    if (options.method === 'PATCH') return new Promise(resolve => { release = () => resolve(new Response(null, { status: 204 })); });
    return json({ packages: [{ id: 'pkg-123', encryptedName }] });
  });
  try {
    const oldLabel = ui.$('audit-body').children[0].children[0].children[0];
    await ui.$('refresh-list').dispatch('click');
    assert.equal(oldLabel.textContent, 'Name unavailable');
    const button = ui.$('audit-body').children[0].children[5].children.at(-1);
    await button.dispatch('click');
    ui.$('rename-name').value = 'First draft';
    const saving = ui.$('rename-form').dispatch('submit');
    await until(() => release);
    await ui.$('cancel-name').dispatch('click');
    await button.dispatch('click');
    ui.$('rename-name').value = 'Second draft';
    release();
    await saving;
    assert.equal(ui.$('name-dialog').open, true);
    assert.equal(ui.$('rename-name').value, 'Second draft');
    assert.equal(ui.$('save-name').disabled, false);
  } finally { ui.restore(); }
});

test('enrollment rejects reusing the server-known setup token before deriving or sending credentials', async () => {
  let requests = 0;
  let derivations = 0;
  const ui = await harness('admin', async () => { ++requests; throw new Error('Enrollment must not send credentials'); }, { auth: { initialized: false } });
  const originalDerive = crypto.subtle.deriveBits;
  try {
    crypto.subtle.deriveBits = function (...args) { ++derivations; return originalDerive.apply(this, args); };
    ui.$('setup-token').value = adminPassword;
    ui.$('password').value = adminPassword;
    ui.$('confirm-password').value = adminPassword;
    await ui.$('login-form').dispatch('submit');
    assert.equal(requests, 0);
    assert.equal(derivations, 0);
    assert.match(ui.$('login-status').textContent, /password different from the setup token/);
    for (const id of ['setup-token', 'password', 'confirm-password']) assert.equal(ui.$(id).value, '');
    assert.equal(ui.$('workspace').hidden, true);
    assert.equal(ui.$('package-name').disabled, true);
    assert.equal(ui.$('audit-body').children.length, 0);
    assert.equal(ui.$('login-button').disabled, false);
  } finally { crypto.subtle.deriveBits = originalDerive; ui.restore(); }
});
