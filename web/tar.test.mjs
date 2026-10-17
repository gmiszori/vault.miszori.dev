import test from 'node:test';
import assert from 'node:assert/strict';
import { archiveSize, fileHeaders, padding, paxRecord, TarWriter } from './tar.js';

const decoder = new TextDecoder();
const field = (bytes, start, length) => decoder.decode(bytes.subarray(start, start + length)).replace(/\0.*$/s, '');
const octal = (bytes, start, length) => parseInt(field(bytes, start, length).trim(), 8);
const file = (path, size, lastModified = 1720000000000) => ({ path, size, lastModified });

function pax(bytes) {
  const result = {};
  let offset = 0;
  while (offset < bytes.length) {
    const separator = bytes.indexOf(32, offset);
    const length = Number(decoder.decode(bytes.subarray(offset, separator)));
    assert.ok(length > 0 && offset + length <= bytes.length);
    const text = decoder.decode(bytes.subarray(separator + 1, offset + length));
    assert.ok(text.endsWith('\n'));
    const equal = text.indexOf('=');
    result[text.slice(0, equal)] = text.slice(equal + 1, -1);
    offset += length;
  }
  assert.equal(offset, bytes.length);
  return result;
}

function parseTar(bytes) {
  const entries = [];
  let attrs = {};
  let offset = 0;
  while (offset < bytes.length - 1024) {
    const block = bytes.subarray(offset, offset + 512);
    const saved = octal(block, 148, 8);
    const checksum = block.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0);
    assert.equal(saved, checksum);
    assert.equal(field(block, 257, 6), 'ustar');
    const type = field(block, 156, 1);
    const size = type === 'x' ? octal(block, 124, 12) : Number(attrs.size ?? octal(block, 124, 12));
    offset += 512;
    const content = bytes.subarray(offset, offset + size);
    if (type === 'x') attrs = pax(content);
    else {
      entries.push({ name: attrs.path || field(block, 0, 100), size, content, mtime: Number(attrs.mtime ?? octal(block, 136, 12)) });
      attrs = {};
    }
    offset += size + padding(size);
  }
  assert.equal(offset, bytes.length - 1024);
  assert.ok(bytes.subarray(offset).every(byte => byte === 0));
  return entries;
}

test('PAX lengths count UTF-8 bytes and handle digit-width changes', () => {
  for (const path of ['é/東京.txt', 'a'.repeat(89), 'a'.repeat(90), 'a'.repeat(990)]) {
    const record = paxRecord('path', path);
    assert.equal(Number(decoder.decode(record).split(' ')[0]), record.length);
    assert.deepEqual(pax(record), { path });
  }
});

test('streaming TAR writes nested, empty, aligned, Unicode and long files', async () => {
  const files = [file('empty.txt', 0), file('nested/data.bin', 513), file('other/exact.bin', 512), file('日本語/été.txt', 3, 1720000000123), file(`${'long/'.repeat(30)}end.txt`, 1)];
  const chunks = [];
  let closed = false;
  const tar = new TarWriter({ async write(part) { chunks.push(Buffer.from(part)); }, async close() { closed = true; } });
  for (const item of files) {
    await tar.startFile(item);
    if (item.size) {
      await tar.write(new Uint8Array(Math.min(100, item.size)).fill(7));
      if (item.size > 100) await tar.write(new Uint8Array(item.size - 100).fill(7));
    }
    await tar.endFile();
  }
  await tar.close();
  assert.ok(closed);
  const bytes = Buffer.concat(chunks);
  assert.equal(bytes.length, archiveSize(files));
  assert.equal(bytes.length % 512, 0);
  const entries = parseTar(bytes);
  assert.equal(entries.length, files.length);
  entries.forEach((entry, index) => {
    assert.equal(entry.name, files[index].path);
    assert.equal(entry.size, files[index].size);
    assert.equal(entry.mtime, files[index].lastModified / 1000);
    assert.equal(entry.content.length, files[index].size);
    assert.ok(entry.content.every(byte => byte === 7));
  });
});

test('PAX encodes files above 8 GiB without allocating their contents', () => {
  const item = file('large.bin', 20 * 1024 ** 3, 8640000000000000);
  const headers = fileHeaders(item);
  assert.equal(field(headers[0], 156, 1), 'x');
  const size = octal(headers[0], 124, 12);
  const extended = pax(Buffer.concat(headers.slice(1)).subarray(0, size));
  assert.equal(extended.size, String(item.size));
  assert.equal(extended.mtime, '8640000000000');
  const regular = headers.at(-1);
  assert.equal(octal(regular, 124, 12), 0);
  assert.equal(octal(regular, 136, 12), 0);
  assert.equal(archiveSize([item]), headers.reduce((sum, part) => sum + part.length, 0) + item.size + 1024);
});

test('TAR enforces ordered, complete writes and output backpressure', async () => {
  let writes = 0;
  const tar = new TarWriter({ async write() { writes++; await new Promise(resolve => setImmediate(resolve)); }, async close() {} });
  await assert.rejects(tar.write(new Uint8Array(1)));
  await tar.startFile(file('one', 2));
  assert.equal(writes, 1);
  await assert.rejects(tar.startFile(file('two', 0)));
  await assert.rejects(tar.write(new Uint8Array(3)));
  await assert.rejects(tar.endFile());
  await assert.rejects(tar.close());
  await tar.write(new Uint8Array(2));
  await tar.endFile();
  await tar.close();
  assert.equal(writes, 5);
  await assert.rejects(tar.close());
});
