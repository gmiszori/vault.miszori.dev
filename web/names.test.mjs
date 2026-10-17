import test from 'node:test';
import assert from 'node:assert/strict';
import { deriveNameKey, validateLabelKey, validateName, encryptName, decryptName } from './names.js';

const config = { version: 1, salt: 'AAAAAAAAAAAAAAAAAAAAAA', iterations: 600000 };
const phrase = 'a separate random passphrase 東京';

test('name crypto interoperates with independent Web Crypto PBKDF2 and AES-GCM', async () => {
  const key = await deriveNameKey(phrase, config);
  assert.equal(key.extractable, false);
  assert.equal(key.algorithm.length, 256);
  const name = '  Private transfer 🔒  ';
  const envelope = await encryptName(key, 'package-123', name);
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(phrase), 'PBKDF2', false, ['deriveKey']);
  const independent = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', iterations: 600000, salt: new Uint8Array(16) }, material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(envelope.iv, 'base64url'), additionalData: new TextEncoder().encode('drive.miszori.dev:admin-name:v1:package-123'), tagLength: 128 }, independent, Buffer.from(envelope.ciphertext, 'base64url'));
  assert.equal(new TextDecoder().decode(plaintext), name.trim());
  assert.equal(await decryptName(key, 'package-123', envelope), name.trim());
  assert.equal(Buffer.from(envelope.iv, 'base64url').length, 12);
  const next = await encryptName(key, 'package-123', name);
  assert.notEqual(next.iv, envelope.iv);
  assert.notEqual(next.ciphertext, envelope.ciphertext);
  await assert.rejects(decryptName(key, 'other-package', envelope));
  const wrong = await deriveNameKey('another random separate phrase', config);
  await assert.rejects(decryptName(wrong, 'package-123', envelope));
  const tampered = Buffer.from(envelope.ciphertext, 'base64url'); tampered[0] ^= 1;
  await assert.rejects(decryptName(key, 'package-123', { ...envelope, ciphertext: tampered.toString('base64url') }));
  await assert.rejects(decryptName(key, 'package-123', { ...envelope, version: 2 }));
  await assert.rejects(decryptName(key, 'package-123', { ...envelope, iv: envelope.iv + '=' }));
});

test('strict KDF configuration, passphrase and Unicode name validation', async () => {
  assert.deepEqual(validateLabelKey(config), config);
  for (const invalid of [null, {}, { ...config, version: 2 }, { ...config, iterations: 1 }, { ...config, iterations: '600000' }, { ...config, salt: config.salt + '=' }, { ...config, salt: 'AAAAAAAAAAAAAAAAAAAAAB' }, { ...config, salt: 'AA' }]) assert.throws(() => validateLabelKey(invalid));
  for (const invalid of ['', 'too short', 'x'.repeat(1025)]) await assert.rejects(deriveNameKey(invalid, config));
  assert.equal(validateName('  hello  '), 'hello');
  assert.equal(validateName('🔒'.repeat(120)), '🔒'.repeat(120));
  assert.equal(validateName('   '), '');
  for (const invalid of ['a'.repeat(121), '🔒'.repeat(121), 'a\nb', 'a\u0000', '\u202eabc', '\ud800']) assert.throws(() => validateName(invalid));
  const key = await deriveNameKey(phrase, config);
  await assert.rejects(encryptName(key, 'pkg', '  '));
  await assert.rejects(encryptName(key, '../unsafe', 'name'));
  const envelope = await encryptName(key, 'pkg', '🔒'.repeat(120));
  assert.equal(Buffer.from(envelope.ciphertext, 'base64url').length, 496);
});
