import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

export const testPassword = 'integration-admin-password-with-zero-server-knowledge';
export const testSetupToken = 'integration-setup-token-never-deploy-1234567890';
const encoder = new TextEncoder();
const sessions = new Map();

export async function deriveTestKeys(password, labelKey) {
  assert.equal(labelKey.version, 1);
  assert.equal(labelKey.iterations, 600000);
  const salt = Buffer.from(labelKey.salt, 'base64url'); assert.equal(salt.length, 16);
  const material = await webcrypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const root = new Uint8Array(await webcrypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 }, material, 256));
  try {
    const hkdf = await webcrypto.subtle.importKey('raw', root, 'HKDF', false, ['deriveBits', 'deriveKey']);
    const parameters = info => ({ name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode(info) });
    const authentication = Buffer.from(await webcrypto.subtle.deriveBits(parameters('drive.miszori.dev:admin-auth:v1'), hkdf, 256)).toString('base64url');
    const nameKey = await webcrypto.subtle.deriveKey(parameters('drive.miszori.dev:admin-names:v1'), hkdf, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    return { authentication, nameKey };
  } finally { root.fill(0); }
}

export function adminSession(origin) {
  if (!sessions.has(origin)) sessions.set(origin, (async () => {
    const response = await fetch(`${origin}/admin/api/auth`); assert.equal(response.status, 200);
    const info = await response.json();
    const keys = await deriveTestKeys(testPassword, info.labelKey);
    if (!info.initialized) {
      const setup = await fetch(`${origin}/admin/api/setup`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ setupToken: testSetupToken, authentication: keys.authentication }) });
      assert.ok(setup.status === 204 || setup.status === 409, `Test enrollment failed: ${setup.status}`);
    }
    const auth = { Authorization: `Basic ${Buffer.from(`${info.username}:${keys.authentication}`).toString('base64')}` };
    const config = await fetch(`${origin}/admin/api/config`, { headers: auth }); assert.equal(config.status, 200);
    assert.deepEqual((await config.json()).labelKey, info.labelKey);
    return { ...keys, auth, info };
  })());
  return sessions.get(origin);
}
