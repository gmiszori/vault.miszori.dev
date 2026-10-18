import test from 'node:test';
import assert from 'node:assert/strict';
import { pbkdf2Sync, hkdfSync } from 'node:crypto';
import { deriveAdminKeys, adminAuthorization, validateAuthConfig } from './auth.js';
import { encryptName, decryptName } from './names.js';

const salt = Buffer.from('0123456789abcdef');
const config = { version: 1, salt: salt.toString('base64url'), iterations: 600000 };
const password = 'a strong random admin password 東京🔒';

test('password-derived authentication and names match independent PBKDF2/HKDF domains', async () => {
  const root = pbkdf2Sync(password, salt, 600000, 32, 'sha256');
  const auth = Buffer.from(hkdfSync('sha256', root, salt, 'vault.miszori.dev:admin-auth:v1', 32));
  const names = Buffer.from(hkdfSync('sha256', root, salt, 'vault.miszori.dev:admin-names:v1', 32));
  const keys = await deriveAdminKeys(password, config);
  assert.equal(keys.authentication, auth.toString('base64url'));
  assert.notDeepEqual(auth, names);
  assert.equal(keys.nameKey.extractable, false);
  assert.deepEqual(keys.nameKey.usages, ['encrypt', 'decrypt']);
  assert.equal(keys.nameKey.algorithm.name, 'AES-GCM');
  assert.equal(keys.nameKey.algorithm.length, 256);
  await assert.rejects(crypto.subtle.exportKey('raw', keys.nameKey));
  const envelope = await encryptName(keys.nameKey, 'package-123', 'Private name');
  const independent = await crypto.subtle.importKey('raw', names, 'AES-GCM', false, ['decrypt']);
  assert.equal(await decryptName(independent, 'package-123', envelope), 'Private name');
  const authMaterial = await crypto.subtle.importKey('raw', auth, 'HKDF', false, ['deriveKey']);
  const authNames = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('vault.miszori.dev:admin-names:v1') }, authMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  await assert.rejects(decryptName(authNames, 'package-123', envelope));
  const directAuth = await crypto.subtle.importKey('raw', auth, 'AES-GCM', false, ['decrypt']);
  await assert.rejects(decryptName(directAuth, 'package-123', envelope));
  const wrong = await deriveAdminKeys('another strong random password', config);
  assert.notEqual(wrong.authentication, keys.authentication);
  await assert.rejects(decryptName(wrong.nameKey, 'package-123', envelope));
  const header = adminAuthorization('admin-é', keys.authentication);
  assert.equal(Buffer.from(header.slice(6), 'base64').toString('utf8'), `admin-é:${auth.toString('base64url')}`);
  assert.ok(!header.includes(password));
});

test('authentication configuration and password Unicode bounds are strict', async () => {
  const auth = { initialized: false, username: 'admin-é', labelKey: config, publicOrigin: 'https://vault.example' };
  assert.deepEqual(validateAuthConfig(auth), auth);
  for (const bad of [null, {}, { ...auth, initialized: 0 }, { ...auth, username: '' }, { ...auth, username: 'a:b' }, { ...auth, username: 'a\nb' }, { ...auth, labelKey: { ...config, iterations: 599999 } }, { ...auth, labelKey: { ...config, salt: 'AA' } }]) assert.throws(() => validateAuthConfig(bad));
  for (const bad of ['', 'x'.repeat(15), 'x'.repeat(1025), '🔒'.repeat(1025), '\ud800'.repeat(16), null]) await assert.rejects(deriveAdminKeys(bad, config));
  assert.equal((await deriveAdminKeys('🔒'.repeat(1024), config)).authentication.length, 43);
  for (const [username, secret] of [['a:b', 'A'.repeat(43)], ['a\nb', 'A'.repeat(43)], ['admin', 'short'], ['admin', '+'.repeat(43)]]) assert.throws(() => adminAuthorization(username, secret));
});
