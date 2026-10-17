import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, webcrypto } from 'node:crypto';

const pub = process.env.TEST_PUBLIC_URL || 'http://localhost:18080';
const admin = process.env.TEST_ADMIN_URL || 'http://localhost:18081';
const credentials = Buffer.from('admin:integration-only-password-please-never-deploy').toString('base64');
const auth = { Authorization: `Basic ${credentials}` };
const chunkSize = 8 * 1024 * 1024;
async function adminFetch(path, method = 'GET', body, extra = {}) {
  return fetch(`${admin}/admin/api/${path}`, { method, headers: { ...auth, ...extra }, body });
}
async function create(ttlSeconds = 3600) {
  const r = await adminFetch('packages', 'POST', JSON.stringify({ ttlSeconds }));
  assert.equal(r.status, 201); return r.json();
}
async function upload(p, n, ciphertext) {
  const r = await adminFetch(`packages/${p.id}/chunks/${n}`, 'PUT', ciphertext, { 'X-Upload-Token': p.uploadToken });
  assert.equal(r.status, 204, await r.text());
}
async function finalize(p, chunks) {
  const r = await adminFetch(`packages/${p.id}/finalize`, 'POST', JSON.stringify({ chunks }), { 'X-Upload-Token': p.uploadToken });
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
  const home = await fetch(pub); assert.equal(home.status, 200);
  assert.match(home.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(home.headers.get('referrer-policy'), 'no-referrer');
  assert.equal((await fetch(`${admin}/admin`)).status, 200);
  assert.equal((await fetch(`${admin}/package/${'0'.repeat(64)}`)).status, 200, 'VPN users can also open public package pages');
  assert.equal((await fetch(`${admin}/api/admin/packages`, { headers: auth })).status, 404);
  assert.equal((await fetch(`${admin}/admin/api/packages`)).status, 401);
  assert.equal((await adminFetch('packages', 'POST', '{"ttlSeconds":3600}', { Origin: 'https://evil.example' })).status, 403);
  const invalid = await fetch(`${pub}/api/packages/${'0'.repeat(64)}`); assert.equal(invalid.status, 404);
});

test('browser-compatible AES-GCM package streams once, with audit and key-bound authentication', async () => {
  const p = await create(); const rawKey = randomBytes(32);
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
  const response = await fetch(`${pub}/api/packages/${p.id}/consume`, { method: 'POST', headers: { 'X-Real-IP': '1.2.3.4', 'X-Forwarded-For': '1.2.3.4' } });
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
  const responses = await Promise.all(Array.from({ length: 8 }, () => fetch(`${pub}/api/packages/${p.id}/consume`, { method: 'POST' })));
  assert.equal(responses.filter(r => r.status === 200).length, 1);
  assert.equal(responses.filter(r => r.status === 404).length, 7);
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

test('optional large transfer remains streaming', { skip: !process.env.LARGE_TEST_MIB }, async () => {
  const mib = Number(process.env.LARGE_TEST_MIB); assert.ok(Number.isInteger(mib) && mib > 0 && mib <= 20480);
  const p = await create(86400); const key = await webcrypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const data = randomBytes(chunkSize); let left = mib * 1024 * 1024; let count = 0;
  const meta = new TextEncoder().encode(JSON.stringify({ version: 1, chunkSize, files: [{ path: 'large.bin', size: left, lastModified: 0 }] }));
  await upload(p, count, new Uint8Array(await webcrypto.subtle.encrypt(parameters(p.id, count++), key, meta)));
  while (left) { const part = data.subarray(0, Math.min(left, chunkSize)); const n = count++; await upload(p, n, new Uint8Array(await webcrypto.subtle.encrypt(parameters(p.id, n), key, part))); left -= part.length; }
  await finalize(p, count);
  let n = 0; let bytes = 0;
  for await (const encrypted of records(await fetch(`${pub}/api/packages/${p.id}/consume`, { method: 'POST' }))) {
    const decoded = new Uint8Array(await webcrypto.subtle.decrypt(parameters(p.id, n), key, encrypted));
    if (n > 0) { assert.deepEqual(Buffer.from(decoded), data.subarray(0, decoded.length)); bytes += decoded.length; } n++;
  }
  assert.equal(bytes, mib * 1024 * 1024); assert.equal(n, count);
});
