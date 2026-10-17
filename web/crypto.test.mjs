import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv } from 'node:crypto';
import { CHUNK_SIZE, MAX_CIPHERTEXT, MAX_BYTES, MAX_FILES, encodeKey, decodeKey, importKey, chunkParameters, encryptChunk, decryptChunk, validatePath, validateManifest, serializeManifest, parseManifest, FramedReader } from './crypto.js';

const entry = (path = 'folder/hello.txt', size = 10) => ({ path, size, lastModified: 1720000000123 });
const manifest = files => ({ version: 1, files, chunkSize: CHUNK_SIZE });

function stream(bytes, split = 3) {
  let offset = 0;
  return new ReadableStream({ pull(controller) {
    if (offset === bytes.length) return controller.close();
    controller.enqueue(bytes.subarray(offset, offset + split));
    offset = Math.min(bytes.length, offset + split);
  } });
}

function framed(...records) {
  return Buffer.concat(records.map(record => {
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32BE(record.length);
    return Buffer.concat([prefix, record]);
  }));
}

test('keys are canonical 256-bit base64url values', () => {
  const bytes = Uint8Array.from({ length: 32 }, (_, i) => i);
  assert.equal(encodeKey(bytes), 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8');
  assert.deepEqual(decodeKey(encodeKey(bytes)), bytes);
  for (const value of ['', 'a'.repeat(42), 'a'.repeat(44), '+'.repeat(43), 'A'.repeat(42) + 'B']) assert.throws(() => decodeKey(value));
  assert.throws(() => decodeKey(''), { message: 'This link is missing a valid decryption key.' });
});

test('AES-GCM matches an independent implementation with big-endian IV and AAD', async () => {
  const raw = Uint8Array.from({ length: 32 }, (_, i) => i);
  const key = await importKey(raw);
  const id = 'package-123';
  const index = 0x102030405;
  const plaintext = new TextEncoder().encode('Private files, never public keys.');
  const iv = Buffer.from('000000000000000102030405', 'hex');
  assert.deepEqual(Buffer.from(chunkParameters(id, index).iv), iv);
  const cipher = createCipheriv('aes-256-gcm', raw, iv);
  cipher.setAAD(Buffer.from(`${id}:${index}`));
  const expected = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  const encrypted = await encryptChunk(key, id, index, plaintext);
  assert.deepEqual(Buffer.from(encrypted), expected);
  assert.deepEqual(await decryptChunk(key, id, index, encrypted), plaintext);
  assert.equal(key.extractable, false);
  assert.notDeepEqual(chunkParameters(id, 0).iv, chunkParameters(id, 1).iv);
  await assert.rejects(decryptChunk(key, 'other-id', index, encrypted));
  await assert.rejects(decryptChunk(key, id, index + 1, encrypted));
  encrypted[0] ^= 1;
  await assert.rejects(decryptChunk(key, id, index, encrypted));
  assert.throws(() => chunkParameters(id, -1));
  assert.throws(() => chunkParameters(id, 1.5));
});

test('full-size chunks round-trip; oversized and short chunks are rejected', async () => {
  const key = await importKey(new Uint8Array(32));
  const plaintext = new Uint8Array(CHUNK_SIZE).fill(73);
  const encrypted = await encryptChunk(key, 'id', 1, plaintext);
  assert.equal(encrypted.length, MAX_CIPHERTEXT);
  assert.deepEqual(await decryptChunk(key, 'id', 1, encrypted), plaintext);
  await assert.rejects(encryptChunk(key, 'id', 2, new Uint8Array(CHUNK_SIZE + 1)));
  await assert.rejects(decryptChunk(key, 'id', 1, new Uint8Array(15)));
  await assert.rejects(decryptChunk(key, 'id', 1, new Uint8Array(MAX_CIPHERTEXT + 1)));
});

test('safe paths support nested Unicode; traversal and ambiguous paths are rejected', () => {
  for (const path of ['file.txt', 'photos/été/東京.jpg', 'a b/.hidden', 'a'.repeat(100)]) assert.equal(validatePath(path), path);
  for (const path of ['', '/', '/etc/passwd', '../secret', 'a/../b', './a', 'a//b', 'a/', 'C:/a', 'a\\b', 'a\0b', 'a\nb', 'a\u007fb', '\ud800', 'é'.repeat(2049), null]) {
    assert.throws(() => validatePath(path), undefined, String(path));
  }
});

test('manifest validates sizes, ordering, path conflicts and limits before upload', () => {
  const files = [entry('empty', 0), entry('a', CHUNK_SIZE + 1), entry('nested/b', CHUNK_SIZE)];
  const { plaintext, bytes, chunks } = serializeManifest(files);
  assert.equal(bytes, CHUNK_SIZE * 2 + 1);
  assert.equal(chunks, 4);
  assert.deepEqual(parseManifest(plaintext).manifest.files, files);
  assert.equal(validateManifest(manifest([entry('large', MAX_BYTES)])).bytes, MAX_BYTES);
  for (const bad of [null, {}, manifest([]), { ...manifest(files), version: 2 }, { ...manifest(files), chunkSize: 1 }, manifest([entry('a', -1)]), manifest([entry('a', 1.1)]), manifest([entry('a', MAX_BYTES + 1)]), manifest([entry('a', MAX_BYTES), entry('b', 1)]), manifest([entry('a'), entry('a')]), manifest([entry('a'), entry('a/b')]), manifest([entry('a/b'), entry('a')]), manifest([entry('é'), entry('e\u0301')]), manifest([{ ...entry(), lastModified: NaN }]), manifest([{ ...entry(), lastModified: -1 }]), manifest([{ ...entry(), lastModified: 8640000000000001 }]), manifest(Array(MAX_FILES + 1).fill(entry()))]) assert.throws(() => validateManifest(bad));
  const hugeNames = Array.from({ length: 2100 }, (_, i) => entry(`${i}/${'x'.repeat(4000)}`, 0));
  assert.throws(() => serializeManifest(hugeNames), /manifest too large/);
  assert.throws(() => parseManifest(new TextEncoder().encode('not JSON')));
  assert.throws(() => parseManifest(new Uint8Array([0xff])));
});

test('framed reader handles split prefixes, arbitrary chunk boundaries and EOF', async () => {
  const first = new Uint8Array(17).fill(5);
  const second = new Uint8Array(100).fill(9);
  for (const split of [1, 2, 4, 16, 200]) {
    const reader = new FramedReader(stream(framed(first, second), split));
    assert.deepEqual(await reader.record(), first);
    assert.deepEqual(await reader.record(), second);
    await reader.end();
  }
});

test('framed reader rejects truncated, oversized and surplus records', async () => {
  for (const bytes of [new Uint8Array(), new Uint8Array([0, 0]), new Uint8Array([0, 0, 0, 16, 1])]) {
    const reader = new FramedReader(stream(bytes));
    await assert.rejects(reader.record(), /ended early/);
  }
  for (const size of [0, 15, MAX_CIPHERTEXT + 1, 0xffffffff]) {
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32BE(size);
    const reader = new FramedReader(stream(prefix));
    await assert.rejects(reader.record(), /invalid record length/);
  }
  const reader = new FramedReader(stream(framed(new Uint8Array(16), new Uint8Array(16))));
  await reader.record();
  await assert.rejects(reader.end(), /extra data/);
});
