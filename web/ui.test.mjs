import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import { CHUNK_SIZE, MEMORY_LIMIT, encodeKey, decodeKey, importKey, encryptChunk, decryptChunk, parseManifest, serializeManifest, serializeText, parseTextManifest, MAX_TEXT_BYTES } from './crypto.js';
import { archiveSize } from './zip.js';
import { encryptName, decryptName } from './names.js';
import { deriveAdminKeys, adminAuthorization } from './auth.js';
import { createAuditKey } from './audit.js';
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
    fetch: { configurable: true, value: (path, init) => entry === 'admin' && path === '/admin/api/auth' && options.auth !== false ? json({ initialized: true, username: 'admin-é', labelKey, publicOrigin: 'https://vault.example', ...options.auth }) : fetcher(path, init) },
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
    info: new TextEncoder().encode('vault.miszori.dev:package-claim:v1')
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
    assert.equal(ui.$('download-button').textContent, 'Download package');
    assert.equal(ui.$('consent-text').textContent, 'I understand that this is a one-time download package.');
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
    assert.equal(ui.$('save-archive').download, 'vault-pkg-123.zip');
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
        assert.equal(ui.$('download-status').textContent, '');
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
    assert.equal(options.suggestedName, 'vault-pkg-123.zip');
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
    assert.equal(ui.$('download-status').textContent, '');
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
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://vault.example', labelKey });
    if (path === '/admin/api/packages' && !options.method) return json({ packages: [] });
    return onUpload(path, options);
  };
}

test('transfer activity displays server storage and configured quota in GB, refreshes, and clears on logout', async () => {
  let usedBytes = 1500000000;
  const ui = await signedInAdmin(async path => {
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://vault.example', labelKey });
    return json({ packages: [], storage: { usedBytes, maxBytes: 100000000000 } });
  });
  try {
    assert.equal(ui.$('storage-usage').textContent, 'Storage: 1.50 GB / 100.00 GB');
    usedBytes = 0;
    await ui.$('refresh-list').dispatch('click');
    assert.equal(ui.$('storage-usage').textContent, 'Storage: 0.00 GB / 100.00 GB');
    await ui.$('logout').dispatch('click');
    assert.equal(ui.$('storage-usage').textContent, '');
  } finally { ui.restore(); }
});

test('audit shows compact nonwrapping package IDs but preserves full IDs for titles and deletion', async () => {
  const ids = ['abcdef0123456789'.repeat(4), 'exactly12-idz', 'short-id'];
  const deleted = [];
  const ui = await signedInAdmin(async (path, options) => {
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://vault.miszori.dev', labelKey });
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
    ? json({ publicOrigin: 'https://vault.example', labelKey }) : json({ packages }));
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

test('admin custom expiry selects a local date and minute and sends remaining seconds', async () => {
  let created;
  let ui;
  ui = await signedInAdmin(adminFetcher(async (path, options) => {
    if (path.endsWith('/packages') && options.method === 'POST') {
      created = JSON.parse(options.body);
      assert.equal(ui.$('expiry-date').disabled, true);
      return new Response('Stopped after creation check', { status: 400 });
    }
    throw new Error(`Unexpected ${path}`);
  }));
  try {
    const html = await readFile(new URL('./admin.html', import.meta.url), 'utf8');
    assert.match(html, /id="expiry-date" type="datetime-local" step="60"/);
    assert.doesNotMatch(html, /custom-ttl|Custom duration|Minutes \(1/);
    ui.$('ttl').value = 'custom';
    await ui.$('ttl').dispatch('change');
    assert.equal(ui.$('expiry-date-field').hidden, false);
    const expiry = new Date(ui.$('expiry-date').value).getTime();
    assert.ok(expiry > Date.now() + 86300000 && expiry <= Date.now() + 86400000);
    assert.ok(ui.$('expiry-date').min);
    assert.ok(ui.$('expiry-date').max);
    ui.$('file-input').files = [new File(['hello'], 'hello.txt')];
    await ui.$('file-input').dispatch('change');
    const before = Date.now();
    await ui.$('upload-button').dispatch('click');
    assert.equal(created.oneTime, true);
    assert.equal(created.format, 'files');
    assert.ok(created.ttlSeconds <= Math.floor((expiry - before) / 1000));
    assert.ok(created.ttlSeconds >= Math.floor((expiry - Date.now()) / 1000));
    assert.equal(ui.$('expiry-date').disabled, false);
    ui.$('ttl').value = '86400';
    await ui.$('ttl').dispatch('change');
    assert.equal(ui.$('expiry-date-field').hidden, true);
  } finally { ui.restore(); }
});

test('admin rejects missing, invalid, past, too-near and too-distant custom expirations before upload', async () => {
  const ui = await signedInAdmin(adminFetcher(async path => { throw new Error(`Unexpected upload ${path}`); }));
  const local = date => {
    const pad = value => String(value).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  };
  try {
    ui.$('package-format').value = 'text';
    ui.$('package-text').value = 'secret';
    ui.$('ttl').value = 'custom';
    for (const value of ['', 'not-a-date', '2099-02-30T12:00', '2099-01-01T12:00:30', local(new Date(Date.now() - 60000)), local(new Date(Date.now() + 30000)), local(new Date(Date.now() + 31 * 86400000))]) {
      ui.$('expiry-date').value = value;
      await ui.$('upload-button').dispatch('click');
      assert.match(ui.$('upload-status').textContent, /Choose (?:a valid expiration date and time|an expiry between 1 minute and 30 days from now)/, value);
      assert.equal(ui.$('upload-progress').hidden, true);
    }
  } finally { ui.restore(); }
});

test('admin validates upload paths, encrypts sequential records, finalizes and forgets credentials on signout', async () => {
  const uploads = [];
  let finalized;
  const ui = await signedInAdmin(adminFetcher(async (path, options) => {
    uploads.push([path, options]);
    if (options.method === 'POST' && path.endsWith('/packages')) {
      assert.deepEqual(JSON.parse(options.body), { ttlSeconds: 86400, oneTime: true, format: 'files' });
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
    assert.ok(link.startsWith('https://vault.example/package/pkg-123#'));
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
    ['http://localhost:18080', 'vault.example', false],
    ['http://vault.example', 'localhost', false],
    ['http://localhost.example', 'localhost', false],
    ['http://localhost@vault.example', 'localhost', false],
    ['https://vault.example', 'vault.example', true]
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

test('entrypoints use the exact brand, system color scheme, and task-focused copy', async () => {
  for (const name of ['index', 'admin']) {
    const html = await readFile(new URL(`./${name}.html`, import.meta.url), 'utf8');
    assert.match(html, /<title>vault\.miszori\.dev<\/title>/);
    assert.doesNotMatch(html, /<header|class="brand"/);
    assert.doesNotMatch(html, /<a\b[^>]*\bhref="\/"/);
    assert.match(html, /<meta name="color-scheme" content="light dark">/);
    // The only footer is the miszori.dev endorsement.
    assert.deepEqual(html.match(/<footer[\s\S]*?<\/footer>/g), ['<footer class="project-footer"><span>vault</span><span class="endorse">by <a href="https://miszori.dev">miszori.dev</a><span class="gm-tile" aria-hidden="true">GM</span></span></footer>']);
    assert.doesNotMatch(html, /A little less|Less exposure|Send it\.|Good things|Private by design|class="(?:hero|principles|privacy-panel|vault-art|workspace-badge)"/i);
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
  assert.match(adminHTML, /Includes upload time/);
  assert.match(adminHTML, /class="upload-options"/);
  assert.doesNotMatch(adminHTML, /one-time-warning/);
  assert.match(adminHTML, /key is not saved and cannot be recovered/);
  assert.match(adminHTML, /id="result-panel"[^>]*hidden/);
});

test('deployment and module defaults consistently use the vault namespace', async () => {
  const compose = await readFile(new URL('../compose.yaml', import.meta.url), 'utf8');
  const env = await readFile(new URL('../.env.example', import.meta.url), 'utf8');
  const docker = await readFile(new URL('../Dockerfile', import.meta.url), 'utf8');
  const go = await readFile(new URL('../go.mod', import.meta.url), 'utf8');
  const pkg = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
  assert.match(compose, /^name: vault-miszori-dev\n/);
  assert.equal((compose.match(/https:\/\/\$\{DOMAIN:-vault\.miszori\.dev\}/g) || []).length, 3);
  assert.match(env, /^DOMAIN=vault\.miszori\.dev\n/);
  assert.match(go, /^module vault\.miszori\.dev\n/);
  assert.equal(pkg.name, 'vault.miszori.dev');
  assert.match(docker, /-o \/vault \.\/cmd\/vault/);
  assert.match(docker, /ENTRYPOINT \["\/vault"\]/);
});

test('messaging previews advertise only the text banner with no square touch-image fallback', async () => {
  const generator = await readFile(new URL('../tools/generate-preview.py', import.meta.url), 'utf8');
  const html = await readFile(new URL('./index.html', import.meta.url), 'utf8');
  const png = await readFile(new URL('./share-preview.png', import.meta.url));
  assert.deepEqual([...png.subarray(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10]);
  assert.equal(png.readUInt32BE(16), 1200);
  assert.equal(png.readUInt32BE(20), 630);
  await assert.rejects(readFile(new URL('./share-icon.png', import.meta.url)), { code: 'ENOENT' });
  assert.doesNotMatch(generator, /share-icon/);
  assert.ok(generator.includes('"Encrypted file and secret sharing system."'));
  assert.equal((html.match(/share-preview\.png\?v=9/g) || []).length, 2);
  assert.match(html, /property="og:image:width" content="1200"/);
  assert.match(html, /property="og:image:height" content="630"/);
  assert.equal((html.match(/property="og:image"/g) || []).length, 1);
  assert.equal((html.match(/name="twitter:image"/g) || []).length, 1);
  assert.doesNotMatch(html, /<meta[^>]+content=['"][^'"\n]*share-icon\.png/);
  for (const field of ['type', 'width', 'height', 'alt']) assert.equal((html.match(new RegExp(`property="og:image:${field}"`, 'g')) || []).length, 1);
  assert.doesNotMatch(html, /apple-touch-icon|share-icon/);
  assert.match(html, /name="twitter:card" content="summary_large_image"/);
  assert.match(html, /property="og:description" content=""/);
  assert.match(html, /name="twitter:description" content=""/);
});

test('light and dark palettes provide readable text, blue project controls and keyboard focus', async () => {
  const css = await readFile(new URL('./styles.css', import.meta.url), 'utf8');
  const palette = block => Object.fromEntries([...block.matchAll(/--([a-z-]+): (#[0-9a-f]{3,6});/g)].map(([, name, value]) => [name, value]));
  const light = palette(/:root \{([^}]+)\}/.exec(css)[1]);
  const dark = palette(/@media \(prefers-color-scheme: dark\) \{\s*:root \{([^}]+)\}/.exec(css)[1]);
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
  const channels = value => value.slice(1).match(/../g).map(channel => parseInt(channel, 16));
  assert.match(css, /color-scheme: light dark/);
  for (const [colors, background, text] of [[light, '#ffffff', '#0a0a0a'], [dark, '#000000', '#f5f5f5']]) {
    for (const name of ['background', 'surface', 'input']) assert.equal(colors[name], background);
    assert.equal(colors.text, text);
    const danger = channels(colors.danger), success = channels(colors.success);
    assert.ok(danger[0] > danger[1] && danger[0] > danger[2], 'danger is red');
    assert.ok(success[1] > success[0] && success[1] > success[2], 'ready is green');
    for (const name of ['text', 'muted', 'sub', 'danger', 'warning', 'success', 'pending', 'focus']) {
      assert.ok(contrast(colors[name], colors.surface) >= 4.5, `${name} has readable contrast on ${background}`);
    }
    assert.ok(contrast(colors.line, colors.surface) >= 3, `control borders are visible on ${background}`);
    assert.ok(contrast(colors['on-blue'], colors.blue) >= 4.5, 'blue buttons have readable text');
    assert.ok(contrast(colors.blue, colors.surface) >= 4.5, `blue accents are readable on ${background}`);
    assert.ok(parseInt(colors.blue.slice(5, 7), 16) > parseInt(colors.blue.slice(1, 3), 16), 'vault is blue');
  }
  assert.match(css, /\.status-ready\s*\{[^}]*color: var\(--success\)/);
  assert.match(css, /\.status-downloading\s*\{[^}]*color: var\(--pending\)/);
  assert.match(css, /#package-description:empty\s*\{[^}]*display: none/);
  for (const selector of ['progress.is-complete', 'progress.is-complete::-webkit-progress-value', 'progress.is-complete::-moz-progress-bar']) {
    assert.ok(css.includes(`${selector} { ${selector === 'progress.is-complete' ? 'accent-color' : 'background'}: var(--success); }`));
  }
  assert.match(css, /\.status-unavailable\s*\{[^}]*color: var\(--danger\)/);
  assert.match(css, /\.notice\.one-time-warning\s*\{[^}]*border-color: var\(--danger\); color: var\(--danger\)/);
  assert.match(css, /\.notice\.one-time-warning strong\s*\{[^}]*color: var\(--danger\)/);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\)/);
  assert.match(css, /:focus-visible\s*\{[^}]*outline: 2px solid var\(--focus\)/);
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

test('public roots serve the homepage and VPN roots redirect to the admin page', async () => {
  const home = 'rewrite * /home.html templates file_server';
  for (const [file, expected] of [['../Caddyfile', [home]], ['../Caddyfile.vpn', ['redir https://{$VPN_BIND_IP:10.13.13.1}/admin 302', 'redir * /admin 302']], ['../tests/Caddyfile', [home, 'redir * /admin 302']]]) {
    const config = await readFile(new URL(file, import.meta.url), 'utf8');
    const roots = [...config.matchAll(/handle \/ \{\n([\s\S]*?)\n\t\}/g)].map(([, body]) => body.trim().replace(/\s+/g, ' '));
    assert.deepEqual(roots, expected, file);
    assert.match(config, /handle (?:@page|\/package\/\*)/);
    assert.match(config, /\/fonts\/instrument-sans\.woff2 \/fonts\/instrument-sans-ext\.woff2 \/fonts\/jetbrains-mono\.woff2/);
  }
});

test('homepage explains the encryption flow without scripts, inline styles, or admin links', async () => {
  const html = await readFile(new URL('./home.html', import.meta.url), 'utf8');
  assert.match(html, /<title>vault\.miszori\.dev<\/title>/);
  assert.match(html, /<h1 class="home-title">vault\.miszori\.dev<\/h1>/);
  assert.match(html, /script-src 'none'/);
  assert.ok(!/<script|<style|\son\w+=|\sstyle=/i.test(html));
  assert.doesNotMatch(html, /href="\/admin/);
  for (const zone of ['Sender', 'Server', 'Recipient']) assert.match(html, new RegExp(`<h3 class="zone-head"><span>${zone}</span>`));
  assert.match(html, /<span class="zone-tag">vpn only<\/span>/);
  for (const step of ['Your data', 'Encrypt', 'Ciphertext', 'Decrypt', 'Delivered']) assert.match(html, new RegExp(`<h4>${step}</h4>`));
  assert.match(html, /#&lt;key&gt;/);
  const references = [...html.matchAll(/(?:src|href)="([^"]+)"/g)].map(match => match[1]);
  assert.deepEqual(references, ['/favicon.svg', '/styles.css?v=1', '#main', 'https://github.com/gmiszori/vault.miszori.dev', 'https://miszori.dev']);
});

test('VPN admin uses a local IP certificate and redirects to the IP without changing the public origin', async () => {
  const config = await readFile(new URL('../Caddyfile.vpn', import.meta.url), 'utf8');
  const publicConfig = await readFile(new URL('../Caddyfile', import.meta.url), 'utf8');
  assert.doesNotMatch(publicConfig, /VPN_BIND_IP|tls internal|:8443|:8081/);
  const compose = await readFile(new URL('../compose.yaml', import.meta.url), 'utf8');
  assert.match(config, /default_sni \{\$VPN_BIND_IP:10\.13\.13\.1\}/);
  assert.match(config, /^:80 \{\s*bind \{\$VPN_BIND_IP:10\.13\.13\.1\}/m);
  assert.match(config, /^https:\/\/\{\$VPN_BIND_IP:10\.13\.13\.1\}(?::443)? \{\s*bind \{\$VPN_BIND_IP:10\.13\.13\.1\}\s*tls internal/m);
  assert.match(config, /redir https:\/\/\{\$VPN_BIND_IP:10\.13\.13\.1\}\{uri\} 308/);
  assert.doesNotMatch(config, /:8443|:8081/);
  const privateProxy = /^  caddy-vpn:\n([\s\S]*?)(?=^  [a-z][\w-]*:|^[^\s])/m.exec(compose)?.[1];
  assert.ok(privateProxy);
  assert.match(privateProxy, /VPN_BIND_IP: \$\{VPN_BIND_IP:-10\.13\.13\.1\}/);
  assert.match(privateProxy, /^    network_mode: service:wireguard$/m);
  assert.doesNotMatch(privateProxy, /^    (?:ports|networks):/m);
  assert.match(privateProxy, /PUBLIC_ORIGIN: https:\/\/\$\{DOMAIN:-vault\.miszori\.dev\}/);
});

test('HTML entrypoints reference only the agreed self-hosted assets and contain no inline scripts or styles', async () => {
  for (const name of ['index', 'admin']) {
    const html = await readFile(new URL(`./${name}.html`, import.meta.url), 'utf8');
    assert.ok(!/<script(?![^>]*src=)|<style|\son\w+=|\sstyle=/i.test(html));
    assert.match(html, /Content-Security-Policy/);
    const references = [...html.matchAll(/(?:src|href)="([^"]+)"/g)].map(match => match[1]);
    assert.match(html, /<link rel="icon" type="image\/svg\+xml" href="\/favicon.svg">/);
    const allowed = new Set(['/styles.css?v=1', '/public.js', '/admin.js', '/favicon.svg', '/', '/admin/', '#main', 'https://miszori.dev']);
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
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://vault.example', labelKey });
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
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://vault.example', labelKey });
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
  const ui = await signedInAdmin(async path => path.endsWith('/config') ? json({ publicOrigin: 'https://vault.example', labelKey }) : json({ packages: [
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
  const ui = await signedInAdmin(async path => path.endsWith('/config') ? json({ publicOrigin: 'https://vault.example', labelKey }) : json({ packages }));
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
      return json({ initialized: false, username: 'admin-é', labelKey, publicOrigin: 'https://vault.example' });
    }
    if (path.endsWith('/setup')) {
      assert.deepEqual(JSON.parse(options.body), { setupToken: token, authentication: fixtureKeys.authentication });
      assert.equal(options.headers.Authorization, undefined);
      return new Response(null, { status: 204 });
    }
    assert.equal(options.headers.Authorization, expectedAuthorization);
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://vault.example', labelKey });
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
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://vault.example', labelKey });
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
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://vault.example', labelKey });
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

test('public cards use a narrower centered shell while admin width stays unchanged', async () => {
  const css = await readFile(new URL('./styles.css', import.meta.url), 'utf8');
  const html = await readFile(new URL('./admin.html', import.meta.url), 'utf8');
  assert.match(css, /\.admin-body\s*\{[^}]*max-width:\s*1100px;[^}]*padding:\s*0 24px 40px/);
  assert.match(css, /body\s*\{[^}]*display: flex; flex-direction: column;[^}]*min-height: 100dvh/);
  assert.match(css, /\.public-shell\s*\{[^}]*flex: 1 0 auto;[^}]*max-width:\s*900px;[^}]*padding:\s*32px 24px;[^}]*display: flex/);
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
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://vault.example', labelKey });
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

test('reusable packages hide destructive consent and can download repeatedly without losing the key', async () => {
  const data = await packageStream(files, [content]);
  let claims = 0;
  const ui = await harness('public', async (_, options) => {
    if (options.method === 'POST') { claims++; return new Response(data.body); }
    return json({ status: 'ready', oneTime: false, expiresAt: '2099-01-01T00:00:00Z' });
  }, { hash: `#${encodeKey(data.raw)}` });
  try {
    await until(() => !ui.$('download-button').disabled);
    assert.equal(ui.$('download-warning').hidden, true);
    assert.equal(ui.$('consent-label').hidden, true);
    assert.equal(ui.$('download-consent').checked, false);
    assert.equal(ui.$('download-button').textContent, 'Download');
    assert.doesNotMatch(ui.$('fallback-description').textContent, /lost|one-time/);
    for (let i = 0; i < 2; i++) {
      await ui.$('download-button').dispatch('click');
      assert.equal(ui.$('download-button').disabled, false);
      assert.equal(ui.$('download-button').hidden, false);
      assert.equal(ui.$('download-meter').classList.contains('is-complete'), true);
      assert.doesNotMatch(ui.$('package-description').textContent, /destroyed/);
    }
    assert.equal(claims, 2);
    assert.equal(ui.blobs.length, 2);
    assertZip(Buffer.from(await ui.blobs[1].arrayBuffer()), files, [content, new Uint8Array()]);
  } finally { ui.restore(); }
});

test('failed reusable downloads retain the key for retry but a missing package disables further attempts', async () => {
  const data = await packageStream(files, [content]);
  let mode = 'network';
  const ui = await harness('public', async (_, options) => {
    if (!options.method) return json({ status: 'ready', oneTime: false, expiresAt: '2099-01-01T00:00:00Z' });
    if (mode === 'network') throw new TypeError('Network failed');
    if (mode === 'missing') return new Response(null, { status: 404 });
    return new Response(data.body);
  }, { hash: `#${encodeKey(data.raw)}` });
  try {
    await until(() => !ui.$('download-button').disabled);
    await ui.$('download-button').dispatch('click');
    assert.equal(ui.$('download-button').disabled, false);
    assert.match(ui.$('download-status').textContent, /try again before expiry/);
    assert.doesNotMatch(ui.$('download-status').textContent, /cannot be resumed/);
    mode = 'success';
    await ui.$('download-button').dispatch('click');
    assert.equal(ui.blobs.length, 1);
    mode = 'missing';
    await ui.$('download-button').dispatch('click');
    assert.equal(ui.$('download-button').disabled, true);
    assert.equal(ui.$('package-state').textContent, 'Unavailable');
  } finally { ui.restore(); }
});

test('admin sends selected reusable mode and displays non-destructive link expiry', async () => {
  let createBody;
  const ui = await signedInAdmin(adminFetcher(async (path, options) => {
    if (options.method === 'POST' && path.endsWith('/packages')) {
      createBody = JSON.parse(options.body);
      return json({ id: 'pkg-123', uploadToken: 'token', expiresAt: '2099-01-01T00:00:00Z' });
    }
    return new Response(null, { status: 204 });
  }));
  try {
    ui.$('package-mode').value = 'until-expiry';
    ui.$('file-input').files = [new File(['hello'], 'hello.txt', { lastModified: 0 })];
    await ui.$('file-input').dispatch('change');
    await ui.$('upload-button').dispatch('click');
    assert.deepEqual(createBody, { ttlSeconds: 86400, oneTime: false, format: 'files' });
    assert.match(ui.$('link-expiry').textContent, /repeated downloads/);
    assert.doesNotMatch(ui.$('link-expiry').textContent, /claimed/);
  } finally { ui.restore(); }
});

test('retrieval activity is paginated, rendered safely, and cleared on signout including late results', async () => {
  let resolveLate;
  const calls = [];
  const ui = await signedInAdmin(async path => {
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://vault.example', labelKey });
    if (path.includes('/retrievals?')) {
      calls.push(path);
      if (path.includes('cursor=next')) return new Promise(resolve => { resolveLate = resolve; });
      return json({ retrievals: [{ openedAt: '2026-01-01T00:00:00Z', openedIp: '<script>bad</script>', openedBrowser: { browser: 'Chrome', os: 'Linux', deviceType: 'desktop' } }], nextCursor: 'next' });
    }
    return json({ packages: [{ id: 'pkg-123', status: 'ready', oneTime: false, retrievalCount: 101 }] });
  });
  try {
    const row = ui.$('audit-body').children[0];
    assert.equal(row.children[1].children[1].textContent, 'Until expiry');
    const activity = row.children[5].children.find(button => button.textContent === 'Activity (101)');
    await activity.dispatch('click');
    await until(() => ui.$('retrieval-body').children.length === 1);
    assert.equal(ui.$('retrieval-body').children[0].children[1].children[0].textContent, '<script>bad</script>');
    assert.equal(ui.$('retrieval-next').hidden, false);
    const next = ui.$('retrieval-next').dispatch('click');
    await until(() => Boolean(resolveLate));
    await ui.$('logout').dispatch('click');
    resolveLate(json({ retrievals: [{ openedIp: 'private' }], nextCursor: '' }));
    await next;
    assert.equal(ui.$('retrieval-body').children.length, 0);
    assert.equal(ui.$('retrieval-dialog').open, false);
    assert.match(calls[0], /cursor=0&limit=100/);
    assert.match(calls[1], /cursor=next&limit=100/);
  } finally { ui.restore(); }
});

// Mirrors the Go server's seal() in cmd/vault/audit.go.
async function sealActivity(auditConfig, id, retrieval) {
  const P256 = { name: 'ECDH', namedCurve: 'P-256' };
  const encoder = new TextEncoder();
  const audit = await crypto.subtle.importKey('raw', Buffer.from(auditConfig.publicKey, 'base64url'), P256, false, []);
  const ephemeral = await crypto.subtle.generateKey(P256, true, ['deriveBits']);
  const ephemeralKey = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: audit }, ephemeral.privateKey, 256);
  const material = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: ephemeralKey, info: encoder.encode('vault.miszori.dev:audit-record:v1') }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(`vault.miszori.dev:audit-record:v1:${id}`) }, key, encoder.encode(JSON.stringify(retrieval).padEnd(1024, ' ')));
  return { version: 1, ephemeralKey: Buffer.from(ephemeralKey).toString('base64url'), iv: Buffer.from(iv).toString('base64url'), ciphertext: Buffer.from(ciphertext).toString('base64url') };
}

test('first sign-in enrolls a wrapped activity key and sealed activity is decrypted only in the browser', async () => {
  let enrolled = null;
  const calls = [];
  const opened = { openedAt: '2026-01-01T00:00:00Z', openedIp: '198.51.100.7', openedBrowser: { browser: 'Firefox', os: 'Linux', deviceType: 'desktop', userAgent: 'UA' } };
  const fetcher = async (path, options = {}) => {
    calls.push([path, options.method]);
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://vault.example', labelKey, auditKey: enrolled });
    if (path.endsWith('/audit-key')) { enrolled = JSON.parse(options.body); return new Response(null, { status: 204 }); }
    if (path.includes('/retrievals?')) {
      const other = await sealActivity(enrolled, 'pkg-other', opened);
      return json({ retrievals: [await sealActivity(enrolled, 'pkg-123', { ...opened, openedIp: '198.51.100.8' }), other], nextCursor: '' });
    }
    return json({ packages: [{ id: 'pkg-123', status: 'ready', oneTime: false, retrievalCount: 2, sealedRetrieval: await sealActivity(enrolled, 'pkg-123', opened) }] });
  };
  let ui = await signedInAdmin(fetcher);
  try {
    assert.deepEqual(calls.filter(([, method]) => method === 'PUT').map(([path]) => path), ['/admin/api/audit-key']);
    assert.deepEqual(Object.keys(enrolled).sort(), ['iv', 'publicKey', 'version', 'wrappedKey']);
    const row = ui.$('audit-body').children[0];
    assert.equal(row.children[4].children[1].textContent, '198.51.100.7');
    assert.equal(row.children[4].children[2].textContent, 'Firefox / Linux / desktop');
    await row.children[5].children.find(button => button.textContent === 'Activity (2)').dispatch('click');
    await until(() => ui.$('retrieval-body').children.length === 2);
    assert.equal(ui.$('retrieval-body').children[0].children[1].children[0].textContent, '198.51.100.8');
    // A record sealed for another package does not open here.
    assert.equal(ui.$('retrieval-body').children[1].children[0].children[0].textContent, 'Unavailable');
    assert.match(ui.$('retrieval-status').textContent, /1 activity record\(s\) could not be decrypted/);
  } finally { ui.restore(); }
  calls.length = 0;
  ui = await signedInAdmin(fetcher);
  try {
    assert.equal(calls.filter(([, method]) => method === 'PUT').length, 0);
    assert.equal(ui.$('audit-body').children[0].children[4].children[1].textContent, '198.51.100.7');
  } finally { ui.restore(); }
});

test('sealed activity is shown as unavailable when the activity key cannot be unwrapped', async () => {
  const { config } = await createAuditKey(await crypto.subtle.importKey('raw', new Uint8Array(32), 'AES-GCM', false, ['encrypt']));
  const ui = await signedInAdmin(async path => path.endsWith('/config')
    ? json({ publicOrigin: 'https://vault.example', labelKey, auditKey: config })
    : json({ packages: [{ id: 'pkg-123', status: 'consumed', retrievalCount: 1, sealedRetrieval: await sealActivity(config, 'pkg-123', { openedAt: '2026-01-01T00:00:00Z', openedIp: '198.51.100.7' }) }] }));
  try {
    assert.equal(ui.$('audit-body').children[0].children[4].children[0].textContent, 'Unavailable');
    assert.match(ui.$('audit-status').textContent, /1 activity record\(s\) could not be decrypted/);
  } finally { ui.restore(); }
});

async function textStream(value, options = {}) {
  const raw = new Uint8Array(32).fill(17);
  const key = await importKey(raw);
  const encoded = serializeText(value);
  const parts = [];
  for (const [index, bytes] of [encoded.plaintext, options.bytes || encoded.text].entries()) {
    const ciphertext = await encryptChunk(key, 'pkg-123', index, bytes);
    const header = Buffer.alloc(4); header.writeUInt32BE(ciphertext.length);
    parts.push(header, ciphertext);
  }
  if (options.surplus) parts.push(Buffer.from([1]));
  return { raw, body: Buffer.concat(parts) };
}

test('one-time text requires explicit view consent, renders literally without downloading, copies and clears on pagehide', async () => {
  const value = '\ufeffFirst line\n秘密 🔐\n<script>alert(1)</script>';
  const data = await textStream(value);
  let claims = 0;
  const ui = await harness('public', async (_, options) => {
    if (options.method === 'POST') { claims++; return new Response(data.body); }
    return json({ status: 'ready', format: 'text', oneTime: true, expiresAt: '2099-01-01T00:00:00Z' });
  }, { hash: `#${encodeKey(data.raw)}`, picker: () => { throw new Error('Text must not open a save picker'); } });
  try {
    await until(() => ui.$('package-state').textContent === 'Ready');
    assert.equal(claims, 0);
    assert.equal(ui.$('package-format').textContent, 'Plain TXT');
    assert.equal(ui.$('download-button').textContent, 'Reveal secret');
    assert.equal(ui.$('package-title').textContent, 'Secret ready to view');
    assert.match(ui.$('warning-description').textContent, /Viewing this secret destroys/);
    assert.equal(ui.$('consent-text').textContent, 'I understand that this is a one-time reveal secret.');
    assert.equal(ui.$('download-button').disabled, true);
    assert.equal(ui.$('fallback-warning').hidden, true);
    ui.$('download-consent').checked = true;
    await ui.$('download-button').dispatch('click');
    assert.equal(claims, 1);
    assert.equal(ui.$('text-result').hidden, false);
    assert.equal(ui.$('revealed-text').value, value);
    assert.equal(ui.blobs.length, 0);
    assert.equal(ui.$('download-button').hidden, true);
    await ui.$('copy-text').dispatch('click');
    assert.equal(ui.win.clipboard, value);
    assert.equal(ui.$('copy-text-status').textContent, 'Copied.');
    await ui.win.dispatch('pagehide');
    assert.equal(ui.$('revealed-text').value, '');
    assert.equal(ui.$('text-result').hidden, true);
    assert.equal(ui.$('copy-text-status').textContent, '');
  } finally { ui.restore(); }
});

test('reusable text can be viewed repeatedly without consent and clipboard failure offers manual copying', async () => {
  const data = await textStream('First\nSecond');
  let claims = 0;
  const ui = await harness('public', async (_, options) => {
    if (options.method === 'POST') { claims++; return new Response(data.body); }
    return json({ status: 'ready', format: 'text', oneTime: false, expiresAt: '2099-01-01T00:00:00Z' });
  }, { hash: `#${encodeKey(data.raw)}` });
  try {
    await until(() => !ui.$('download-button').disabled);
    assert.equal(ui.$('download-warning').hidden, true);
    assert.equal(ui.$('consent-label').hidden, true);
    for (let i = 0; i < 2; i++) await ui.$('download-button').dispatch('click');
    assert.equal(claims, 2);
    assert.equal(ui.$('download-button').disabled, false);
    assert.equal(ui.$('revealed-text').value, 'First\nSecond');
    navigator.clipboard.writeText = async () => { throw new Error('Denied'); };
    await ui.$('copy-text').dispatch('click');
    assert.equal(ui.$('revealed-text').selected, true);
    assert.match(ui.$('copy-text-status').textContent, /Copy command/);
    assert.equal(ui.blobs.length, 0);
  } finally { ui.restore(); }
});

test('text 429 preserves proof for a new explicit view; extra data and malformed UTF-8 never render plaintext', async () => {
  for (const corrupt of [{ surplus: true }, { bytes: new Uint8Array([255]) }]) {
    const data = await textStream('a', corrupt);
    let claims = 0;
    const ui = await harness('public', async (_, options) => {
      if (options.method === 'POST') { claims++; return claims === 1 ? new Response(null, { status: 429 }) : new Response(data.body); }
      return json({ status: 'ready', format: 'text', oneTime: true, expiresAt: '2099-01-01T00:00:00Z' });
    }, { hash: `#${encodeKey(data.raw)}` });
    try {
      await until(() => ui.$('package-state').textContent === 'Ready');
      ui.$('download-consent').checked = true;
      await ui.$('download-button').dispatch('click');
      assert.equal(ui.$('download-button').disabled, false);
      assert.equal(ui.$('text-result').hidden, true);
      await ui.$('download-button').dispatch('click');
      assert.equal(claims, 2);
      assert.equal(ui.$('text-result').hidden, true);
      assert.equal(ui.$('revealed-text').value, '');
      assert.equal(ui.$('download-button').disabled, true);
    } finally { ui.restore(); }
  }
});

test('text upload sends only encrypted records and metadata, rejects oversized UTF-8 text locally, and clears its editor', async () => {
  const uploads = [];
  let created;
  const ui = await signedInAdmin(adminFetcher(async (path, options) => {
    uploads.push([path, options]);
    if (options.method === 'POST' && path.endsWith('/packages')) {
      created = JSON.parse(options.body);
      return json({ id: 'pkg-123', uploadToken: 'token', expiresAt: '2099-01-01T00:00:00Z' });
    }
    return new Response(null, { status: 204 });
  }));
  try {
    ui.$('package-format').value = 'text';
    await ui.$('package-format').dispatch('change');
    assert.equal(ui.$('drop-zone').hidden, true);
    assert.equal(ui.$('text-editor').hidden, false);
    ui.$('package-text').value = 'é'.repeat(MAX_TEXT_BYTES / 2 + 1);
    await ui.$('package-text').dispatch('input');
    await ui.$('upload-button').dispatch('click');
    assert.equal(uploads.length, 0);
    assert.match(ui.$('upload-status').textContent, /8 MiB/);
    const value = 'Secret multiline\n東京 🔐';
    ui.$('package-text').value = value;
    await ui.$('package-text').dispatch('input');
    await ui.$('upload-button').dispatch('click');
    assert.deepEqual(created, { ttlSeconds: 86400, oneTime: true, format: 'text' });
    const puts = uploads.filter(([, options]) => options.method === 'PUT');
    assert.equal(puts.length, 2);
    const key = await importKey(decodeKey(ui.$('share-link').value.split('#')[1]));
    const manifest = parseTextManifest(await decryptChunk(key, 'pkg-123', 0, puts[0][1].body));
    const text = await decryptChunk(key, 'pkg-123', 1, puts[1][1].body);
    assert.equal(manifest.size, text.length);
    assert.equal(new TextDecoder().decode(text), value);
    assert.ok(!JSON.stringify(uploads).includes(value));
    assert.equal(ui.$('package-text').value, '');
    assert.equal(ui.$('upload-button').disabled, true);
    ui.$('package-text').value = 'Clear on leaving';
    await ui.win.dispatch('pagehide');
    assert.equal(ui.$('package-text').value, '');
  } finally { ui.restore(); }
});

test('pagehide invalidates a pending file destination without disturbing a restored transfer', async () => {
  const data = await packageStream(files, [content]);
  let releasePicker;
  let releaseBody;
  let picks = 0;
  let claims = 0;
  let oldAborts = 0;
  let newAborts = 0;
  const ui = await harness('public', async (_, options) => {
    if (options.method === 'POST') {
      claims++;
      return new Promise(resolve => { releaseBody = resolve; });
    }
    return json({ status: 'ready', oneTime: false, expiresAt: '2099-01-01T00:00:00Z' });
  }, { hash: `#${encodeKey(data.raw)}`, picker() {
    if (++picks === 1) return new Promise(resolve => { releasePicker = resolve; });
    return { createWritable: async () => ({ async write() {}, async close() {}, async abort() { newAborts++; } }) };
  } });
  let oldDownload;
  let newDownload;
  try {
    await until(() => !ui.$('download-button').disabled);
    oldDownload = ui.$('download-button').dispatch('click');
    assert.ok(releasePicker);
    await ui.win.dispatch('pagehide');
    await ui.win.dispatch('pageshow', { persisted: true });
    location.hash = `#${encodeKey(data.raw)}`;
    await ui.win.dispatch('hashchange');
    await until(() => !ui.$('download-button').disabled);
    newDownload = ui.$('download-button').dispatch('click');
    await until(() => releaseBody);
    releasePicker({ createWritable: async () => ({ async abort() { oldAborts++; } }) });
    await oldDownload;
    assert.equal(claims, 1, 'a stale save gesture must never consume after returning');
    assert.equal(oldAborts, 1);
    assert.equal(newAborts, 0);
    assert.equal(ui.$('download-button').disabled, true);
    assert.equal(ui.$('cancel-download').hidden, false);
    assert.equal(ui.$('package-state').textContent, 'Downloading');
    releaseBody(new Response(data.body));
    await newDownload;
    assert.equal(ui.$('package-state').textContent, 'Ready');
    assert.equal(ui.$('download-button').disabled, false);
    assert.equal(newAborts, 0);
  } finally {
    releasePicker?.({ createWritable: async () => ({ async abort() {} }) });
    releaseBody?.(new Response(data.body));
    await Promise.all([oldDownload, newDownload]);
    ui.restore();
  }
});

for (const failure of ['finalize failure', 'finalize cancellation']) {
  test(`text ${failure} preserves the draft for a fresh upload`, async () => {
    const value = 'Only draft\n秘密 🔐';
    const calls = [];
    let creations = 0;
    let finish;
    const ui = await signedInAdmin(adminFetcher(async (path, options) => {
      calls.push([path, options]);
      if (path.endsWith('/packages') && options.method === 'POST') {
        return json({ id: `draft-${++creations}`, uploadToken: `token-${creations}`, expiresAt: '2099-01-01T00:00:00Z' });
      }
      if (path === '/admin/api/packages/draft-1/finalize') return new Promise(resolve => { finish = resolve; });
      return new Response(null, { status: 204 });
    }));
    let pending;
    try {
      ui.$('package-format').value = 'text';
      await ui.$('package-format').dispatch('change');
      ui.$('package-text').value = value;
      await ui.$('package-text').dispatch('input');
      pending = ui.$('upload-button').dispatch('click');
      await until(() => finish);
      assert.equal(ui.$('package-text').value, value, 'keep the only draft while finalization is pending');
      if (failure === 'finalize cancellation') await ui.$('abort-upload').dispatch('click');
      finish(new Response(null, { status: failure === 'finalize failure' ? 500 : 204 }));
      await pending;
      assert.equal(ui.$('package-text').value, value);
      assert.equal(ui.$('package-text').disabled, false);
      assert.equal(ui.$('upload-button').disabled, false);
      assert.equal(ui.$('share-link').value, '');
      assert.equal(ui.$('result-panel').hidden, true);
      assert.deepEqual(calls.map(([path, options]) => [options.method, path]), [
        ['POST', '/admin/api/packages'], ['PUT', '/admin/api/packages/draft-1/chunks/0'],
        ['PUT', '/admin/api/packages/draft-1/chunks/1'], ['POST', '/admin/api/packages/draft-1/finalize'],
        ['DELETE', '/admin/api/packages/draft-1']
      ]);
      assert.match(ui.$('upload-status').textContent, failure === 'finalize failure' ? /HTTP 500/ : /Upload cancelled/);
      await ui.$('upload-button').dispatch('click');
      assert.equal(creations, 2, 'explicit retry creates a new upload rather than resuming the deleted package');
      const key = await importKey(decodeKey(ui.$('share-link').value.split('#')[1]));
      const ciphertext = calls.find(([path]) => path === '/admin/api/packages/draft-2/chunks/1')[1].body;
      assert.equal(new TextDecoder().decode(await decryptChunk(key, 'draft-2', 1, ciphertext)), value);
      assert.equal(ui.$('package-text').value, '', 'successful finalization clears the draft');
      ui.$('package-text').value = 'Scrub on signout';
      await ui.$('logout').dispatch('click');
      assert.equal(ui.$('package-text').value, '');
    } finally {
      finish?.(new Response(null, { status: 500 }));
      await pending;
      ui.restore();
    }
  });
}

for (const staleTiming of ['before restoration', 'during the new reveal']) {
  test(`reusable text can reopen after pagehide with stale completion ${staleTiming}`, async () => {
    const data = await textStream('Reveal only the current operation');
    const releases = [];
    let gets = 0;
    const ui = await harness('public', async (_, options) => {
      if (options.method === 'POST') return new Promise(resolve => { releases.push(resolve); });
      gets++;
      return json({ status: 'ready', format: 'text', oneTime: false, expiresAt: '2099-01-01T00:00:00Z' });
    }, { hash: `#${encodeKey(data.raw)}` });
    let oldReveal;
    let newReveal;
    try {
      await until(() => !ui.$('download-button').disabled);
      oldReveal = ui.$('download-button').dispatch('click');
      await until(() => releases.length === 1);
      await ui.win.dispatch('pagehide');
      assert.equal(ui.$('cancel-download').hidden, true);
      if (staleTiming === 'before restoration') {
        releases[0](new Response(data.body));
        await oldReveal;
      }
      await ui.win.dispatch('pageshow', { persisted: true });
      assert.equal(ui.$('revealed-text').value, '');
      assert.equal(ui.$('text-result').hidden, true);
      assert.equal(ui.$('download-button').disabled, true);
      location.hash = `#${encodeKey(data.raw)}`;
      await ui.win.dispatch('hashchange');
      assert.equal(location.hash, '');
      await until(() => !ui.$('download-button').disabled);
      assert.equal(gets, 2);
      newReveal = ui.$('download-button').dispatch('click');
      await until(() => releases.length === 2);
      if (staleTiming === 'during the new reveal') {
        releases[0](new Response(data.body));
        await oldReveal;
        assert.equal(ui.$('download-button').disabled, true, 'stale finally must not clear the new busy state');
        assert.equal(ui.$('cancel-download').hidden, false);
        assert.equal(ui.$('download-status').textContent, 'Decrypting secret…');
        assert.equal(ui.$('revealed-text').value, '');
        assert.equal(ui.$('text-result').hidden, true);
      }
      releases[1](new Response(data.body));
      await newReveal;
      assert.equal(ui.$('revealed-text').value, 'Reveal only the current operation');
      assert.equal(ui.$('text-result').hidden, false);
      assert.equal(ui.$('download-button').disabled, false);
      assert.equal(ui.$('cancel-download').hidden, true);
    } finally {
      for (const release of releases) release(new Response(data.body));
      await Promise.all([oldReveal, newReveal]);
      ui.restore();
    }
  });
}

for (const staleTiming of ['before restoration', 'after restoration']) {
  test(`admin auth reloads on BFCache restoration when the stale response settles ${staleTiming}`, async () => {
    const releases = [];
    const config = { initialized: true, username: 'admin-é', labelKey, publicOrigin: 'https://vault.example' };
    const ui = await harness('admin', async path => {
      if (path === '/admin/api/auth') return new Promise(resolve => { releases.push(resolve); });
      if (path.endsWith('/config')) return json({ publicOrigin: 'https://vault.example', labelKey });
      return json({ packages: [] });
    }, { auth: false, waitForAuth: false });
    try {
      assert.equal(releases.length, 1);
      assert.equal(ui.$('login-button').disabled, true);
      await ui.win.dispatch('pagehide');
      if (staleTiming === 'before restoration') {
        releases[0](json({ ...config, username: 'stale-user' }));
        await tick();
      }
      await ui.win.dispatch('pageshow', { persisted: true });
      assert.equal(releases.length, 2, 'restore must start a fresh configuration request');
      if (staleTiming === 'after restoration') {
        releases[0](json({ ...config, username: 'stale-user' }));
        await tick();
      }
      assert.equal(ui.$('login-button').disabled, true, 'old finally must not release the new load');
      assert.equal(ui.$('login-status').textContent, 'Loading sign-in settings…');
      assert.notEqual(ui.$('username').value, 'stale-user');
      ui.$('password').value = adminPassword;
      await ui.$('login-form').dispatch('submit');
      assert.equal(ui.$('workspace').hidden, true);
      releases[1](json(config));
      await until(() => !ui.$('login-button').disabled);
      assert.equal(ui.$('username').value, 'admin-é');
      await ui.$('login-form').dispatch('submit');
      assert.equal(ui.$('workspace').hidden, false);
      await ui.win.dispatch('pagehide');
    } finally {
      for (const release of releases) release(json(config));
      await tick();
      ui.restore();
    }
  });
}

test('leaving while text arrives cannot restore plaintext or copy controls afterward', async () => {
  const data = await textStream('Never restore this text');
  let resolveBody;
  const ui = await harness('public', async (_, options) => {
    if (options.method === 'POST') return new Promise(resolve => { resolveBody = resolve; });
    return json({ status: 'ready', format: 'text', oneTime: false, expiresAt: '2099-01-01T00:00:00Z' });
  }, { hash: `#${encodeKey(data.raw)}` });
  try {
    await until(() => !ui.$('download-button').disabled);
    const pending = ui.$('download-button').dispatch('click');
    await until(() => Boolean(resolveBody));
    await ui.win.dispatch('pagehide');
    resolveBody(new Response(data.body));
    await pending;
    assert.equal(ui.$('revealed-text').value, '');
    assert.equal(ui.$('text-result').hidden, true);
    assert.equal(ui.$('download-button').disabled, true);
  } finally { ui.restore(); }
});
