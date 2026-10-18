import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, webcrypto } from 'node:crypto';
import { adminSession, testPassword } from './auth-helper.mjs';
import { protectPackage } from './claim-helper.mjs';

const pub = process.env.TEST_PUBLIC_URL || 'http://localhost:18080';
const admin = process.env.TEST_ADMIN_URL || 'http://localhost:18081';
const { auth, nameKey } = await adminSession(admin);
const encode = bytes => Buffer.from(bytes).toString('base64url');
async function api(path, method = 'GET', body, extra = {}) {
  return fetch(`${admin}/admin/api/${path}`, { method, headers: { ...auth, ...extra }, body: body === undefined ? undefined : JSON.stringify(body) });
}
async function create() {
  const r = await api('packages', 'POST', { ttlSeconds: 3600 }); assert.equal(r.status, 201); return protectPackage(await r.json());
}
async function ready(p) {
  const upload = await fetch(`${admin}/admin/api/packages/${p.id}/chunks/0`, { method: 'PUT', headers: { ...auth, 'X-Upload-Token': p.uploadToken }, body: randomBytes(32) });
  assert.equal(upload.status, 204);
  assert.equal((await api(`packages/${p.id}/finalize`, 'POST', { chunks: 1, claimHash: p.claimHash }, { 'X-Upload-Token': p.uploadToken })).status, 204);
}
async function entry(id) { return (await (await api('packages')).json()).packages.find(p => p.id === id); }
async function encryptedName(id, text) {
  const config = await (await api('config')).json();
  assert.equal(config.labelKey.version, 1); assert.equal(config.labelKey.iterations, 600000);
  assert.equal(Buffer.from(config.labelKey.salt, 'base64url').length, 16);
  const key = nameKey;
  const iv = randomBytes(12); const params = { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(`vault.miszori.dev:admin-name:v1:${id}`) };
  const ciphertext = await webcrypto.subtle.encrypt(params, key, new TextEncoder().encode(text));
  return { envelope: { version: 1, iv: encode(iv), ciphertext: encode(ciphertext) }, key, params };
}

test('enrollment is one-time and login accepts only the independently derived authentication value', async () => {
  const discovered = await (await fetch(`${admin}/admin/api/auth`)).json();
  assert.equal(discovered.initialized, true);
  assert.equal(JSON.stringify(discovered).includes(testPassword), false);
  assert.equal('verifier' in discovered, false);
  const raw = { Authorization: `Basic ${Buffer.from(`${discovered.username}:${testPassword}`).toString('base64')}` };
  assert.equal((await fetch(`${admin}/admin/api/config`, { headers: raw })).status, 401);
  assert.equal((await api('config')).status, 200);
  const repeated = await fetch(`${admin}/admin/api/setup`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ setupToken: 'not-an-enrollment-token', authentication: encode(randomBytes(32)) }) });
  assert.equal(repeated.status, 409);
});

test('admin labels stay encrypted, private, and independent of the package payload', async () => {
  const p = await create(); const label = 'Private admin name: 秘密';
  try {
    const { envelope, key, params } = await encryptedName(p.id, label);
    assert.equal((await api(`packages/${p.id}`, 'PATCH', { encryptedName: envelope })).status, 204);
    await ready(p);
    const listed = await entry(p.id);
    assert.deepEqual(listed.encryptedName, envelope);
    assert.equal(JSON.stringify(listed).includes(label), false);
    const plain = await webcrypto.subtle.decrypt(params, key, Buffer.from(listed.encryptedName.ciphertext, 'base64url'));
    assert.equal(new TextDecoder().decode(plain), label);
    const publicInfo = await (await fetch(`${pub}/api/packages/${p.id}`)).json();
    assert.deepEqual(Object.keys(publicInfo).sort(), ['expiresAt', 'format', 'oneTime', 'status']);
    assert.equal((await fetch(`${pub}/names.js`)).status, 404);
    assert.equal((await fetch(`${admin}/names.js`)).status, 200);
    const claim = await fetch(`${pub}/api/packages/${p.id}/consume`, { method: 'POST', headers: p.claimHeaders });
    assert.equal(claim.status, 200); assert.equal((await claim.arrayBuffer()).byteLength, 36);
    assert.deepEqual((await entry(p.id)).encryptedName, envelope, 'names remain available in the historical audit');
    assert.equal((await api(`packages/${p.id}`, 'PATCH', { encryptedName: null })).status, 204);
    assert.equal((await entry(p.id)).encryptedName, undefined);
  } finally { await api(`packages/${p.id}`, 'DELETE'); }
});

test('knowing the package ID or stored verifier cannot claim or destroy it', async () => {
  const p = await create();
  try {
    await ready(p);
    for (const token of ['', p.claimHash, encode(randomBytes(32))]) {
      const response = await fetch(`${pub}/api/packages/${p.id}/consume`, { method: 'POST', headers: token ? { 'X-Claim-Token': token } : {} });
      assert.equal(response.status, 404);
      const info = await entry(p.id);
      assert.equal(info.status, 'ready'); assert.equal(info.openedAt, undefined); assert.equal(info.openedBrowser, undefined);
      assert.equal((await fetch(`${pub}/api/packages/${p.id}`)).status, 200);
    }
    const withBody = await fetch(`${pub}/api/packages/${p.id}/consume`, { method: 'POST', headers: p.claimHeaders, body: 'unexpected' });
    assert.equal(withBody.status, 400); assert.equal((await entry(p.id)).status, 'ready');
    const success = await fetch(`${pub}/api/packages/${p.id}/consume`, { method: 'POST', headers: p.claimHeaders });
    assert.equal(success.status, 200); assert.equal((await success.arrayBuffer()).byteLength, 36);
    const replay = await fetch(`${pub}/api/packages/${p.id}/consume`, { method: 'POST', headers: p.claimHeaders });
    assert.equal(replay.status, 404);
    const listed = await entry(p.id);
    assert.equal(JSON.stringify(listed).includes(p.claimToken), false);
    assert.equal(JSON.stringify(listed).includes(encode(p.rawKey)), false);
  } finally { await api(`packages/${p.id}`, 'DELETE'); }
});

test('name API rejects plaintext, malformed envelopes, and unauthenticated updates', async () => {
  const p = await create();
  try {
    const { envelope } = await encryptedName(p.id, 'Validation name');
    for (const body of [
      { name: 'plaintext must never be accepted' },
      { encryptedName: { ...envelope, version: 2 } },
      { encryptedName: { ...envelope, iv: encode(randomBytes(11)) } },
      { encryptedName: { ...envelope, ciphertext: encode(randomBytes(16)) } },
      { encryptedName: { ...envelope, ciphertext: encode(randomBytes(513)) } },
      { encryptedName: { ...envelope, extra: 'unknown' } }
    ]) assert.equal((await api(`packages/${p.id}`, 'PATCH', body)).status, 400);
    assert.equal((await fetch(`${admin}/admin/api/packages/${p.id}`, { method: 'PATCH', body: JSON.stringify({ encryptedName: envelope }) })).status, 401);
    assert.equal((await api(`packages/${p.id}`, 'PATCH', { encryptedName: envelope }, { Origin: 'https://evil.example' })).status, 403);
  } finally { await api(`packages/${p.id}`, 'DELETE'); }
});

test('messaging previews are generic, server-rendered, and never claim or audit a package', async () => {
  const p = await create();
  try {
    const { envelope } = await encryptedName(p.id, 'Do not disclose this package name');
    await api(`packages/${p.id}`, 'PATCH', { encryptedName: envelope }); await ready(p);
    const headers = { 'User-Agent': 'facebookexternalhit/1.1 (+https://example.invalid/bot)' };
    for (const origin of [pub, admin]) {
      const response = await fetch(`${origin}/package/${p.id}?private=do-not-reflect-this`, { headers });
      assert.equal(response.status, 200); const html = await response.text();
      assert.match(html, /property="og:title" content="vault\.miszori\.dev"/);
      assert.match(html, /name="twitter:card" content="summary_large_image"/);
      assert.ok(html.includes(`content='${pub}/share-preview.png?v=4'`));
      assert.match(html, /property="og:description" content=""/);
      assert.match(html, /name="twitter:description" content=""/);
      assert.equal(html.includes('Server logs include'), false);
      assert.equal(html.includes('{{env'), false, 'templates must be expanded before bots read HTML');
      assert.equal(html.includes('Do not disclose this package name'), false);
      assert.equal(html.includes(envelope.ciphertext), false);
      assert.equal(html.includes('do-not-reflect-this'), false);
      assert.equal(/property="og:url"|rel="canonical"/.test(html), false, 'do not replace the original fragment-bearing share link');
    }
    const png = await fetch(`${pub}/share-preview.png`, { headers }); assert.equal(png.status, 200);
    assert.match(png.headers.get('content-type'), /image\/png/);
    const bytes = Buffer.from(await png.arrayBuffer()); assert.equal(bytes.subarray(1, 4).toString(), 'PNG');
    assert.equal(bytes.readUInt32BE(16), 1200); assert.equal(bytes.readUInt32BE(20), 630);
    const info = await entry(p.id); assert.equal(info.status, 'ready');
    assert.equal(info.openedAt, undefined); assert.equal(info.openedIp, undefined); assert.equal(info.openedBrowser, undefined);
  } finally { await api(`packages/${p.id}`, 'DELETE'); }
});

test('only an explicit claim records passive browser and device headers in the private audit', async () => {
  const p = await create();
  try {
    await ready(p);
    const userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0';
    await fetch(`${pub}/api/packages/${p.id}`, { headers: { 'User-Agent': userAgent } });
    assert.equal((await entry(p.id)).openedBrowser, undefined);
    const response = await fetch(`${pub}/api/packages/${p.id}/consume`, { method: 'POST', headers: { ...p.claimHeaders, 'User-Agent': userAgent } });
    assert.equal(response.status, 200); await response.arrayBuffer();
    const info = await entry(p.id);
    assert.match(info.openedBrowser.browser, /Firefox/i); assert.match(info.openedBrowser.os, /Windows/i);
    assert.equal(info.openedBrowser.deviceType, 'desktop'); assert.equal(info.openedBrowser.userAgent, userAgent);
    assert.ok(info.openedAt); assert.ok(info.openedIp);
    assert.equal((await fetch(`${pub}/api/packages/${p.id}`)).status, 404);
  } finally { await api(`packages/${p.id}`, 'DELETE'); }
});
