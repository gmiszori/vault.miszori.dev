import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, webcrypto } from 'node:crypto';
import { mkdtemp, open, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { ZipWriter, archiveSize } from '../web/zip.js';
import { adminSession } from './auth-helper.mjs';
import { protectPackage } from './claim-helper.mjs';

const execute = promisify(execFile);

const pub = process.env.TEST_PUBLIC_URL || 'http://localhost:18080';
const admin = process.env.TEST_ADMIN_URL || 'http://localhost:18081';
const { auth } = await adminSession(admin);
const chunkSize = 8 * 1024 * 1024;
async function adminFetch(path, method = 'GET', body, extra = {}) {
  return fetch(`${admin}/admin/api/${path}`, { method, headers: { ...auth, ...extra }, body });
}
async function create(ttlSeconds = 3600) {
  const r = await adminFetch('packages', 'POST', JSON.stringify({ ttlSeconds }));
  assert.equal(r.status, 201); return protectPackage(await r.json());
}
async function upload(p, n, ciphertext) {
  const r = await adminFetch(`packages/${p.id}/chunks/${n}`, 'PUT', ciphertext, { 'X-Upload-Token': p.uploadToken });
  assert.equal(r.status, 204, await r.text());
}
async function finalize(p, chunks) {
  const r = await adminFetch(`packages/${p.id}/finalize`, 'POST', JSON.stringify({ chunks, claimHash: p.claimHash }), { 'X-Upload-Token': p.uploadToken });
  assert.equal(r.status, 204, await r.text());
}
function parameters(id, index) {
  const iv = new Uint8Array(12); new DataView(iv.buffer).setBigUint64(4, BigInt(index));
  return { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(`${id}:${index}`) };
}
async function* records(response) {
  assert.equal(response.status, 200);
  const reader = response.body.getReader(); let buffer = new Uint8Array(); let offset = 0;
  async function exact(n) {
    const out = new Uint8Array(n); let pos = 0;
    while (pos < n) {
      if (offset === buffer.length) {
        const next = await reader.read(); assert.equal(next.done, false, 'truncated response'); buffer = next.value; offset = 0;
      }
      const take = Math.min(n - pos, buffer.length - offset); out.set(buffer.subarray(offset, offset + take), pos); offset += take; pos += take;
    }
    return out;
  }
  for (;;) {
    if (offset === buffer.length) { const next = await reader.read(); if (next.done) break; buffer = next.value; offset = 0; }
    const len = new DataView((await exact(4)).buffer).getUint32(0);
    assert.ok(len >= 16 && len <= chunkSize + 16); yield await exact(len);
  }
}

test('Caddy isolates admin routes and supplies privacy headers', async () => {
  for (const path of ['/admin', '/admin/', '/admin.html', '/admin.js', '/api/admin/packages', '/admin/api/packages', '/api/admin']) {
    const r = await fetch(pub + path, { headers: auth }); assert.equal(r.status, 404, path);
  }
  for (const origin of [pub, admin]) {
    const root = await fetch(origin, { redirect: 'manual' });
    assert.equal(root.status, 302);
    assert.equal(root.headers.get('location'), 'https://gergo.miszori.dev');
    const favicon = await fetch(`${origin}/favicon.svg`);
    assert.equal(favicon.status, 200);
    assert.match(favicon.headers.get('content-type'), /image\/svg\+xml/);
    assert.match(await favicon.text(), /<svg/);
    const unusedStream = await fetch(`${origin}/local-download/${'0'.repeat(64)}`);
    assert.equal(unusedStream.status, 404); assert.equal(await unusedStream.text(), '');
  }
  const home = await fetch(`${pub}/package/${'0'.repeat(64)}`); assert.equal(home.status, 200);
  assert.equal((await fetch(`${pub}/zip.js`)).status, 200);
  for (const path of ['/download.js', '/download-worker.js']) {
    assert.equal((await fetch(pub + path)).status, 200);
    assert.equal((await fetch(admin + path)).status, 200);
  }
  assert.equal((await fetch(`${pub}/auth.js`)).status, 404);
  assert.equal((await fetch(`${admin}/auth.js`)).status, 200);
  assert.equal((await fetch(`${admin}/zip.js`)).status, 200);
  assert.equal((await fetch(`${pub}/tar.js`)).status, 404);
  assert.match(home.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(home.headers.get('referrer-policy'), 'no-referrer');
  assert.equal((await fetch(`${admin}/admin`)).status, 200);
  assert.equal((await fetch(`${admin}/package/${'0'.repeat(64)}`)).status, 200, 'VPN users can also open public package pages');
  assert.equal((await fetch(`${admin}/api/admin/packages`, { headers: auth })).status, 404);
  assert.equal((await fetch(`${admin}/admin/api/packages`)).status, 401);
  const activity = await (await adminFetch('packages')).json();
  assert.ok(Number.isSafeInteger(activity.storage.usedBytes) && activity.storage.usedBytes >= 0);
  assert.equal(activity.storage.maxBytes, 107374182400);
  assert.equal((await adminFetch('packages', 'POST', '{"ttlSeconds":3600}', { Origin: 'https://evil.example' })).status, 403);
  const invalid = await fetch(`${pub}/api/packages/${'0'.repeat(64)}`); assert.equal(invalid.status, 404);
});

test('browser-compatible AES-GCM package streams once, with audit and key-bound authentication', async () => {
  const p = await create(); const rawKey = p.rawKey;
  const key = await webcrypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const manifest = { version: 1, files: [{ path: 'private/folder/秘密.txt', size: chunkSize + 17, lastModified: Date.now() }], chunkSize };
  const plaintext = [new TextEncoder().encode(JSON.stringify(manifest)), randomBytes(chunkSize), randomBytes(17)];
  for (let i = 0; i < plaintext.length; i++) {
    const encrypted = new Uint8Array(await webcrypto.subtle.encrypt(parameters(p.id, i), key, plaintext[i]));
    assert.equal(Buffer.from(encrypted).includes(Buffer.from('private/folder')), false);
    await upload(p, i, encrypted);
  }
  await finalize(p, plaintext.length);
  assert.equal((await fetch(`${pub}/api/packages/${p.id}`)).status, 200);
  assert.equal((await fetch(`${pub}/api/packages/${p.id}`)).status, 200, 'previews must not consume');
  const response = await fetch(`${pub}/api/packages/${p.id}/consume`, { method: 'POST', headers: { ...p.claimHeaders, 'X-Real-IP': '1.2.3.4', 'X-Forwarded-For': '1.2.3.4' } });
  let i = 0;
  for await (const encrypted of records(response)) {
    const decoded = await webcrypto.subtle.decrypt(parameters(p.id, i), key, encrypted);
    assert.deepEqual(Buffer.from(decoded), Buffer.from(plaintext[i]));
    const tampered = encrypted.slice(); tampered[0] ^= 1;
    await assert.rejects(webcrypto.subtle.decrypt(parameters(p.id, i), key, tampered));
    await assert.rejects(webcrypto.subtle.decrypt(parameters(p.id, i + 1), key, encrypted));
    i++;
  }
  assert.equal(i, plaintext.length);
  assert.equal((await fetch(`${pub}/api/packages/${p.id}/consume`, { method: 'POST' })).status, 404);
  const audit = (await (await adminFetch('packages')).json()).packages.find(x => x.id === p.id);
  assert.equal(audit.status, 'consumed'); assert.ok(audit.openedAt); assert.ok(audit.openedIp); assert.notEqual(audit.openedIp, '1.2.3.4');
  assert.equal(JSON.stringify(audit).includes(p.uploadToken), false);
});

test('concurrent claims allow exactly one response', async () => {
  const p = await create(); await upload(p, 0, randomBytes(32)); await finalize(p, 1);
  const responses = await Promise.all(Array.from({ length: 8 }, () => fetch(`${pub}/api/packages/${p.id}/consume`, { method: 'POST', headers: p.claimHeaders })));
  assert.equal(responses.filter(r => r.status === 200).length, 1);
  assert.equal(responses.filter(r => r.status === 404 || r.status === 429).length, 7);
  await Promise.all(responses.map(r => r.arrayBuffer()));
});

test('unfinished packages, expired TTL input, and explicit deletion are safe', async () => {
  assert.equal((await adminFetch('packages', 'POST', '{"ttlSeconds":0}')).status, 400);
  const p = await create();
  assert.equal((await fetch(`${pub}/api/packages/${p.id}`)).status, 404);
  assert.equal((await adminFetch(`packages/${p.id}/chunks/0`, 'PUT', randomBytes(32), { 'X-Upload-Token': 'invalid' })).status, 403);
  await upload(p, 0, randomBytes(32)); await finalize(p, 1);
  assert.equal((await adminFetch(`packages/${p.id}`, 'DELETE')).status, 204);
  assert.equal((await fetch(`${pub}/api/packages/${p.id}/consume`, { method: 'POST' })).status, 404);
});

test('real expiry makes a package unavailable and the background worker deletes it', { timeout: 85000 }, async () => {
  const p = await create(60); await upload(p, 0, randomBytes(32)); await finalize(p, 1);
  const delay = Math.max(0, Date.parse(p.expiresAt) - Date.now() + 50);
  await new Promise(resolve => setTimeout(resolve, delay));
  assert.equal((await fetch(`${pub}/api/packages/${p.id}`)).status, 404);
  const deadline = Date.now() + 17000; let status;
  do {
    status = (await (await adminFetch('packages')).json()).packages.find(x => x.id === p.id).status;
    if (status === 'expired') break;
    await new Promise(resolve => setTimeout(resolve, 1000));
  } while (Date.now() < deadline);
  assert.equal(status, 'expired', 'cleanup worker must persist completed deletion');
});

test('optional large transfer produces a native-compatible streaming ZIP64 archive', { skip: !process.env.LARGE_TEST_MIB }, async () => {
  const mib = Number(process.env.LARGE_TEST_MIB); assert.ok(Number.isInteger(mib) && mib > 0 && mib <= 20480);
  const recordDelay = Number(process.env.SLOW_RECORD_MS || 0);
  assert.ok(Number.isInteger(recordDelay) && recordDelay >= 0 && recordDelay <= 10000);
  const directory = await mkdtemp(join(tmpdir(), 'vault-zip-test-'));
  const filename = join(directory, 'package.zip');
  let p;
  let handle;
  try {
    p = await create(86400);
    const key = await webcrypto.subtle.importKey('raw', p.rawKey, 'AES-GCM', false, ['encrypt', 'decrypt']);
    const data = randomBytes(chunkSize);
    const marker = Buffer.from('Nested ZIP64 marker: 世界\n');
    const files = [
      { path: 'large.bin', size: mib * 1024 * 1024 - marker.length, lastModified: 1720000000000 },
      { path: 'nested/世界.txt', size: marker.length, lastModified: 1720000000000 },
      { path: 'empty.txt', size: 0, lastModified: 0 }
    ];
    let count = 0;
    const meta = new TextEncoder().encode(JSON.stringify({ version: 1, chunkSize, files }));
    await upload(p, count, new Uint8Array(await webcrypto.subtle.encrypt(parameters(p.id, count++), key, meta)));
    for (const [index, file] of files.entries()) {
      let left = file.size;
      while (left) {
        const part = (index === 0 ? data : marker).subarray(0, Math.min(left, chunkSize));
        const n = count++;
        await upload(p, n, new Uint8Array(await webcrypto.subtle.encrypt(parameters(p.id, n), key, part)));
        left -= part.length;
      }
    }
    await finalize(p, count);
    handle = await open(filename, 'w');
    const zip = new ZipWriter({ async write(bytes) { await handle.writeFile(bytes); }, async close() { await handle.close(); handle = null; } });
    const downloadStarted = performance.now();
    const response = await fetch(`${pub}/api/packages/${p.id}/consume`, { method: 'POST', headers: p.claimHeaders });
    const framed = records(response)[Symbol.asyncIterator]();
    const nextPlain = async index => {
      const frame = await framed.next(); assert.equal(frame.done, false);
      return new Uint8Array(await webcrypto.subtle.decrypt(parameters(p.id, index), key, frame.value));
    };
    assert.deepEqual(JSON.parse(new TextDecoder().decode(await nextPlain(0))).files, files);
    let n = 1; let bytes = 0;
    for (const [index, file] of files.entries()) {
      await zip.startFile(file);
      for (let left = file.size; left > 0;) {
        const decoded = await nextPlain(n++);
        assert.equal(decoded.length, Math.min(left, chunkSize));
        assert.deepEqual(Buffer.from(decoded), (index === 0 ? data : marker).subarray(0, decoded.length));
        await zip.write(decoded); left -= decoded.length; bytes += decoded.length;
        if (recordDelay) await new Promise(resolve => setTimeout(resolve, recordDelay));
      }
      await zip.endFile();
    }
    assert.equal((await framed.next()).done, true);
    await zip.close();
    const elapsed = performance.now() - downloadStarted;
    if (recordDelay) {
      assert.ok(elapsed >= (count - 1) * recordDelay);
      console.log(`Throttled authenticated download completed in ${Math.round(elapsed / 1000)} seconds`);
    }
    assert.equal(bytes, mib * 1024 * 1024); assert.equal(n, count);
    assert.equal((await stat(filename)).size, archiveSize(files));
    const verification = await execute('python3', ['-c', `
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as archive:
    entries = archive.infolist()
    assert [f.filename for f in entries] == ['large.bin', 'nested/世界.txt', 'empty.txt']
    assert sum(f.file_size for f in entries) == int(sys.argv[2])
    assert all(f.compress_type == zipfile.ZIP_STORED for f in entries)
    if int(sys.argv[2]) > 0xffffffff:
        assert entries[0].file_size > 0xffffffff
        assert entries[1].header_offset > 0xffffffff
    assert archive.read('nested/世界.txt') == 'Nested ZIP64 marker: 世界\\n'.encode()
    assert archive.read('empty.txt') == b''
    assert archive.testzip() is None
print('Native Python ZIP reader verified every entry CRC, archive sizes/offsets, Unicode, and empty files')
`, filename, String(bytes)]);
    console.log(verification.stdout.trim());
  } finally {
    try {
      await handle?.close();
      if (p) await adminFetch(`packages/${p.id}`, 'DELETE');
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }
});

test('reusable ciphertext survives repeated downloads and records every proof-authorized start privately', async () => {
  const created = await adminFetch('packages', 'POST', JSON.stringify({ ttlSeconds: 3600, oneTime: false }));
  assert.equal(created.status, 201);
  const p = await protectPackage(await created.json());
  try {
    const ciphertext = randomBytes(128);
    await upload(p, 0, ciphertext);
    await finalize(p, 1);
    const info = await (await fetch(`${pub}/api/packages/${p.id}`)).json();
    assert.equal(info.oneTime, false);
    assert.equal(info.openedIp, undefined);
    const bad = await fetch(`${pub}/api/packages/${p.id}/consume`, { method: 'POST' });
    assert.equal(bad.status, 404);
    for (let n = 0; n < 3; n++) {
      const response = await fetch(`${pub}/api/packages/${p.id}/consume`, { method: 'POST', headers: { 'X-Claim-Token': p.claimToken, 'User-Agent': n ? 'Mozilla/5.0 Chrome/130.0 Linux' : 'Mozilla/5.0 Version/18.0 Safari/605.1 Macintosh' } });
      const parts = [];
      for await (const record of records(response)) parts.push(record);
      assert.deepEqual(Buffer.from(parts[0]), ciphertext);
      assert.equal((await fetch(`${pub}/api/packages/${p.id}`)).status, 200);
    }
    const list = await (await adminFetch('packages')).json();
    const item = list.packages.find(item => item.id === p.id);
    assert.equal(item.status, 'ready');
    assert.equal(item.retrievalCount, 3);
    const activity = await (await adminFetch(`packages/${p.id}/retrievals?limit=2`)).json();
    assert.equal(activity.retrievals.length, 2);
    assert.ok(activity.retrievals.every(item => item.openedAt && item.openedIp && item.openedBrowser));
    assert.equal(activity.retrievals[0].openedBrowser.browser, 'Safari');
    assert.equal(activity.retrievals[1].openedBrowser.browser, 'Chrome');
    assert.ok(activity.nextCursor);
    const next = await (await adminFetch(`packages/${p.id}/retrievals?limit=2&cursor=${encodeURIComponent(activity.nextCursor)}`)).json();
    assert.equal(next.retrievals.length, 1);
    assert.equal(next.nextCursor, '');
    assert.equal((await fetch(`${admin}/admin/api/packages/${p.id}/retrievals`)).status, 401);
    assert.equal((await fetch(`${pub}/admin/api/packages/${p.id}/retrievals`, { headers: auth })).status, 404);
  } finally {
    await adminFetch(`packages/${p.id}`, 'DELETE');
  }
});
