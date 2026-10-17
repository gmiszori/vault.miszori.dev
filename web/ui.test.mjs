import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { CHUNK_SIZE, MEMORY_LIMIT, encodeKey, decodeKey, importKey, encryptChunk, decryptChunk, parseManifest, serializeManifest } from './crypto.js';
import { archiveSize } from './zip.js';
import { deriveNameKey, encryptName, decryptName } from './names.js';
const labelKey = { version: 1, salt: 'AAAAAAAAAAAAAAAAAAAAAA', iterations: 600000 };
const namePhrase = 'separate random name phrase 東京';

// A minimal DOM harness exercises the real entry modules without a server or dependencies.
class Element {
  constructor(id = '') {
    this.id = id; this.value = ''; this.hidden = false; this.checked = false;
    this.disabled = false; this.textContent = ''; this.children = []; this.listeners = new Map();
    const classes = new Set();
    this.classList = { toggle(name, force) { if (force ?? !classes.has(name)) classes.add(name); else classes.delete(name); }, add(name) { classes.add(name); }, remove(name) { classes.delete(name); } };
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
    fetch: { configurable: true, value: fetcher },
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

test('public opening removes the key and only explicit consent consumes; fallback saves ZIP', async () => {
  const data = await packageStream(files, [content]);
  const calls = [];
  const ui = await harness('public', async (path, options) => {
    assert.equal(location.hash, '');
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

test('save picker runs before consuming, and writable output is streamed without a Blob', async () => {
  const data = await packageStream(files, [content]);
  const sequence = [];
  const parts = [];
  const ui = await harness('public', async (path, options) => {
    if (options.method !== 'POST') return ready();
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
    const downloading = ui.$('download-button').dispatch('click');
    assert.deepEqual(sequence, ['picker']);
    await downloading;
    assert.deepEqual(sequence, ['picker', 'writable', 'consume', 'close']);
    const output = Buffer.concat(parts);
    assert.equal(output.length, archiveSize(files));
    assertZip(output, files, [content, new Uint8Array()]);
    assert.equal(ui.blobs.length, 0);
  } finally { ui.restore(); }
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
  ui.$('password').value = 'secret-東京';
  await ui.$('login-form').dispatch('submit');
  assert.equal(ui.$('workspace').hidden, false);
  assert.equal(ui.$('password').value, '');
  ui.$('ttl').value = '86400';
  return ui;
}

function adminFetcher(onUpload) {
  return async (path, options) => {
    assert.equal(Buffer.from(options.headers.Authorization.slice(6), 'base64').toString('utf8'), 'admin-é:secret-東京');
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

test('admin validates upload paths, encrypts sequential records, finalizes and forgets credentials on lock', async () => {
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
    assert.deepEqual(finalized, { chunks: 2 });
    const puts = uploads.filter(([, options]) => options.method === 'PUT');
    assert.deepEqual(puts.map(([path]) => path), ['/admin/api/packages/pkg-123/chunks/0', '/admin/api/packages/pkg-123/chunks/1']);
    const link = ui.$('share-link').value;
    assert.ok(link.startsWith('https://drive.example/package/pkg-123#'));
    const keyText = link.split('#')[1];
    for (const [path, options] of uploads) {
      assert.ok(!path.includes(keyText));
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
      ui.$('password').value = 'preview';
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
    ui.$('password').value = 'preview';
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
    assert.match(html, /class="brand"[^>]*>drive\.miszori\.dev<\/a>/);
    assert.match(html, /<meta name="color-scheme" content="dark">/);
    assert.doesNotMatch(html, /A little less|Less exposure|Send it\.|Good things|Private by design|<footer|class="(?:hero|principles|privacy-panel|vault-art|workspace-badge)"/i);
    assert.match(html, /Server logs include IP addresses/);
  }
  const publicHTML = await readFile(new URL('./index.html', import.meta.url), 'utf8');
  assert.match(publicHTML, /Open your package link/);
  assert.match(publicHTML, /even if the download fails or is cancelled/);
  assert.match(publicHTML, /128 MiB, including archive overhead/);
  assert.match(publicHTML, /unknown until you start and claim the one-time download/);
  assert.match(publicHTML, /desktop Chrome or Edge/);
  const adminHTML = await readFile(new URL('./admin.html', import.meta.url), 'utf8');
  assert.match(adminHTML, /Expiry starts at package creation and includes upload time/);
  assert.match(adminHTML, /key is not saved and cannot be recovered/);
  assert.match(adminHTML, /id="result-panel"[^>]*hidden/);
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
  for (const name of ['muted', 'line', 'warning', 'danger', 'success']) assert.match(colors[name], /^#([a-f0-9])\1{2}(?:\1{3})?$/);
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

test('HTML entrypoints reference only the agreed self-hosted assets and contain no inline scripts or styles', async () => {
  for (const name of ['index', 'admin']) {
    const html = await readFile(new URL(`./${name}.html`, import.meta.url), 'utf8');
    assert.ok(!/<script(?![^>]*src=)|<style|\son\w+=|\sstyle=/i.test(html));
    assert.match(html, /Content-Security-Policy/);
    const references = [...html.matchAll(/(?:src|href)="([^"]+)"/g)].map(match => match[1]);
    const allowed = new Set(['/styles.css', '/public.js', '/admin.js', '/', '/admin/', '#main']);
    for (const reference of references) assert.ok(allowed.has(reference), `Allowed asset or navigation: ${reference}`);
  }
});

async function unlockAdminNames(ui, phrase = namePhrase, confirmation = phrase) {
  ui.$('names-passphrase').value = phrase;
  ui.$('names-confirm').value = confirmation;
  const pending = ui.$('names-form').dispatch('submit');
  assert.equal(ui.$('names-passphrase').value, '', 'passphrase cleared immediately');
  assert.equal(ui.$('names-confirm').value, '');
  await pending;
}

test('names unlock independently, upload PATCH precedes chunks, and secrets never enter requests or manifest', async () => {
  const calls = [];
  const ui = await signedInAdmin(adminFetcher(async (path, options) => {
    calls.push([path, options]);
    assert.ok(!JSON.stringify([path, options]).includes(namePhrase));
    assert.ok(!JSON.stringify([path, options]).includes('Private label 東京'));
    if (path.endsWith('/packages') && options.method === 'POST') return json({ id: 'pkg-123', uploadToken: 'token', expiresAt: '2099-01-01T00:00:00Z' });
    return new Response(null, { status: 204 });
  }));
  try {
    assert.equal(ui.$('package-name').disabled, true);
    await unlockAdminNames(ui, namePhrase, 'different confirmation');
    assert.match(ui.$('names-status').textContent, /same new passphrase twice/);
    assert.equal(ui.$('package-name').disabled, true);
    await unlockAdminNames(ui);
    assert.equal(ui.$('package-name').disabled, false);
    ui.$('package-name').value = 'Private label 東京';
    ui.$('file-input').files = [new File(['hello'], 'hello.txt', { lastModified: 0 })];
    await ui.$('file-input').dispatch('change');
    await ui.$('upload-button').dispatch('click');
    assert.deepEqual(calls.map(([, options]) => options.method), ['POST', 'PATCH', 'PUT', 'PUT', 'POST']);
    const patch = JSON.parse(calls[1][1].body);
    assert.deepEqual(Object.keys(patch), ['encryptedName']);
    const key = await deriveNameKey(namePhrase, labelKey);
    assert.equal(await decryptName(key, 'pkg-123', patch.encryptedName), 'Private label 東京');
    const fileKey = await importKey(decodeKey(ui.$('share-link').value.split('#')[1]));
    const manifest = await decryptChunk(fileKey, 'pkg-123', 0, calls[2][1].body);
    assert.ok(!new TextDecoder().decode(manifest).includes('Private label'));
    assert.ok(!ui.$('share-link').value.includes('Private'));
    assert.equal(ui.$('package-name').value, '');
  } finally { ui.restore(); }
});

test('wrong passphrases cannot unlock or rename existing labels; mixed historic keys warn without replacement', async () => {
  const key = await deriveNameKey(namePhrase, labelKey);
  const otherKey = await deriveNameKey('a different historic passphrase', labelKey);
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
    assert.equal(label(0), 'Locked name');
    await unlockAdminNames(ui, 'wrong but sufficiently long phrase');
    assert.match(ui.$('names-status').textContent, /could not unlock/);
    assert.equal(label(0), 'Locked name');
    assert.equal(ui.$('package-name').disabled, true);
    assert.equal(patches.length, 0);
    await unlockAdminNames(ui);
    assert.equal(label(0), '<private name>');
    assert.equal(label(1), 'Locked name');
    assert.match(ui.$('names-status').textContent, /historic name/);
    const nameButton = ui.$('audit-body').children[0].children[5].children.at(-1);
    assert.equal(nameButton.textContent, 'Name');
    await nameButton.dispatch('click');
    ui.$('rename-name').value = 'New label';
    await ui.$('rename-form').dispatch('submit');
    assert.equal(await decryptName(key, 'pkg-123', patches[0].encryptedName), 'New label');
    await nameButton.dispatch('click');
    await ui.$('rename-form').dispatch('submit');
    assert.deepEqual(patches[1], { encryptedName: null });
    await ui.$('lock-names').dispatch('click');
    assert.equal(label(0), 'Locked name');
    assert.equal(ui.$('rename-name').value, '');
    assert.equal(ui.$('package-name').disabled, true);
  } finally { ui.restore(); }
});

test('locking, signout and pagehide erase plaintext and reject late audit and unlock work', async () => {
  const key = await deriveNameKey(namePhrase, labelKey);
  const packages = [{ id: 'pkg-123', encryptedName: await encryptName(key, 'pkg-123', 'Only in memory') }];
  let defer = false;
  let release;
  const ui = await signedInAdmin(async path => {
    if (path.endsWith('/config')) return json({ publicOrigin: 'https://drive.example', labelKey });
    if (defer) return new Promise(resolve => { release = () => resolve(json({ packages })); });
    return json({ packages });
  });
  try {
    await unlockAdminNames(ui);
    assert.equal(ui.$('audit-body').children[0].children[0].children[0].textContent, 'Only in memory');
    defer = true;
    const refresh = ui.$('refresh-list').dispatch('click');
    await until(() => release);
    ui.$('package-name').value = 'Draft secret';
    await ui.$('lock-names').dispatch('click');
    assert.equal(ui.$('package-name').value, '');
    assert.equal(ui.$('audit-body').children[0].children[0].children[0].textContent, 'Locked name');
    release(); await refresh;
    assert.equal(ui.$('audit-body').children[0].children[0].children[0].textContent, 'Locked name');
    defer = false;
    await unlockAdminNames(ui);
    ui.$('package-name').value = 'Draft secret';
    ui.$('names-passphrase').value = namePhrase;
    await ui.$('logout').dispatch('click');
    assert.equal(ui.$('package-name').value, '');
    assert.equal(ui.$('names-passphrase').value, '');
    assert.equal(ui.$('audit-body').children.length, 0);
    ui.$('username').value = 'admin-é'; ui.$('password').value = 'secret-東京';
    await ui.$('login-form').dispatch('submit');
    ui.$('names-passphrase').value = namePhrase;
    const unlocking = ui.$('names-form').dispatch('submit');
    await ui.win.dispatch('pagehide');
    await unlocking;
    assert.equal(ui.$('package-name').disabled, true);
    assert.equal(ui.$('audit-body').children.length, 0);
    assert.equal(ui.$('names-passphrase').value, '');
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
    await unlockAdminNames(ui);
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
    assert.match(html, /id="names-passphrase"[^>]*autocomplete="off"/);
  } finally { ui.restore(); }
});

test('late decryption cannot reinsert plaintext after lock, and detached labels are scrubbed', async () => {
  const key = await deriveNameKey(namePhrase, labelKey);
  const packages = [{ id: 'pkg-123', encryptedName: await encryptName(key, 'pkg-123', 'Sensitive label') }];
  const ui = await signedInAdmin(async path => path.endsWith('/config') ? json({ publicOrigin: 'https://drive.example', labelKey }) : json({ packages }));
  const originalDecrypt = crypto.subtle.decrypt;
  let release;
  try {
    await unlockAdminNames(ui);
    const oldLabel = ui.$('audit-body').children[0].children[0].children[0];
    assert.equal(oldLabel.textContent, 'Sensitive label');
    crypto.subtle.decrypt = function (...args) {
      return new Promise((resolve, reject) => { release = () => originalDecrypt.apply(this, args).then(resolve, reject); });
    };
    const refresh = ui.$('refresh-list').dispatch('click');
    await until(() => release);
    await ui.$('lock-names').dispatch('click');
    assert.equal(oldLabel.textContent, 'Locked name');
    release();
    await refresh;
    assert.equal(ui.$('audit-body').children[0].children[0].children[0].textContent, 'Locked name');
    assert.equal(ui.$('package-name').disabled, true);
  } finally { crypto.subtle.decrypt = originalDecrypt; ui.restore(); }
});

test('name unlock rejects the UTF-8 admin password including colons without additional requests', async () => {
  const password = 'admin:password:東京-strong-long';
  let requests = 0;
  const ui = await harness('admin', async (path, options) => {
    ++requests;
    assert.equal(Buffer.from(options.headers.Authorization.slice(6), 'base64').toString('utf8'), `admin-é:${password}`);
    return path.endsWith('/config') ? json({ publicOrigin: 'https://drive.example', labelKey }) : json({ packages: [] });
  });
  try {
    ui.$('username').value = 'admin-é';
    ui.$('password').value = password;
    await ui.$('login-form').dispatch('submit');
    assert.equal(ui.$('workspace').hidden, false);
    assert.equal(requests, 2);
    await unlockAdminNames(ui, password);
    assert.match(ui.$('names-status').textContent, /different name passphrase, not the admin access password/);
    assert.equal(ui.$('package-name').disabled, true);
    assert.equal(ui.$('names-form').hidden, false);
    assert.equal(ui.$('lock-names').hidden, true);
    assert.equal(requests, 2, 'reused credential is rejected before fetching or saving names');
    await unlockAdminNames(ui);
    assert.equal(ui.$('package-name').disabled, false);
    assert.equal(requests, 3);
    const html = await readFile(new URL('./admin.html', import.meta.url), 'utf8');
    assert.match(html, /strong random passphrase different from the admin access password/);
    assert.match(html, /package names become unrecoverable, but file decryption using the share link is unaffected/);
  } finally { ui.restore(); }
});
