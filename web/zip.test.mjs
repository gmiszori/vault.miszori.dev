import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { archiveSize, ZipWriter } from './zip.js';

const U32_MAX = 0xffffffff;
const GiB = 1024 ** 3;
const file = (path, size, lastModified = 1720000000123) => ({ path, size, lastModified });
const u16 = (b, n) => b.readUInt16LE(n);
const u32 = (b, n) => b.readUInt32LE(n);
const u64 = (b, n) => Number(b.readBigUInt64LE(n));

async function smallArchive(files, contents) {
  const parts = [];
  let closed = false;
  const writer = new ZipWriter({ async write(bytes) { parts.push(Buffer.from(bytes)); }, async close() { closed = true; } });
  for (let i = 0; i < files.length; i++) {
    await writer.startFile(files[i]);
    const bytes = contents[i];
    for (let offset = 0; offset < bytes.length; offset += 3) await writer.write(bytes.subarray(offset, offset + 3));
    await writer.endFile();
  }
  await writer.close();
  assert.equal(closed, true);
  const bytes = Buffer.concat(parts);
  assert.equal(bytes.length, archiveSize(files));
  return bytes;
}

function parseSmall(bytes, files, contents, crcs) {
  let offset = 0;
  const offsets = [];
  for (let i = 0; i < files.length; i++) {
    offsets.push(offset);
    assert.equal(u32(bytes, offset), 0x04034b50);
    assert.equal(u16(bytes, offset + 4), 20);
    assert.equal(u16(bytes, offset + 6), 0x0808);
    assert.equal(u16(bytes, offset + 8), 0);
    assert.equal(u32(bytes, offset + 14), 0);
    assert.equal(u32(bytes, offset + 18), 0);
    assert.equal(u32(bytes, offset + 22), 0);
    const nameLength = u16(bytes, offset + 26);
    assert.equal(u16(bytes, offset + 28), 0);
    assert.equal(bytes.subarray(offset + 30, offset + 30 + nameLength).toString(), files[i].path);
    offset += 30 + nameLength;
    assert.deepEqual(bytes.subarray(offset, offset + files[i].size), contents[i]);
    offset += files[i].size;
    assert.equal(u32(bytes, offset), 0x08074b50);
    assert.equal(u32(bytes, offset + 4), crcs[i]);
    assert.equal(u32(bytes, offset + 8), files[i].size);
    assert.equal(u32(bytes, offset + 12), files[i].size);
    offset += 16;
  }
  const centralOffset = offset;
  for (let i = 0; i < files.length; i++) {
    assert.equal(u32(bytes, offset), 0x02014b50);
    assert.equal(u16(bytes, offset + 6), 20);
    assert.equal(u16(bytes, offset + 8), 0x0808);
    assert.equal(u16(bytes, offset + 10), 0);
    assert.equal(u32(bytes, offset + 16), crcs[i]);
    assert.equal(u32(bytes, offset + 20), files[i].size);
    assert.equal(u32(bytes, offset + 24), files[i].size);
    assert.equal(u32(bytes, offset + 42), offsets[i]);
    const nameLength = u16(bytes, offset + 28);
    assert.equal(u16(bytes, offset + 30), 0);
    assert.equal(bytes.subarray(offset + 46, offset + 46 + nameLength).toString(), files[i].path);
    offset += 46 + nameLength;
  }
  const centralSize = offset - centralOffset;
  assert.equal(u32(bytes, offset), 0x06054b50);
  assert.equal(u16(bytes, offset + 8), files.length);
  assert.equal(u16(bytes, offset + 10), files.length);
  assert.equal(u32(bytes, offset + 12), centralSize);
  assert.equal(u32(bytes, offset + 16), centralOffset);
  assert.equal(u16(bytes, offset + 20), 0);
  assert.equal(offset + 22, bytes.length);
}

const files = [file('empty.txt', 0), file('nested/123456789.txt', 9), file('日本語/été.txt', 3), file('other/vector', 3)];
const contents = [Buffer.alloc(0), Buffer.from('123456789'), Buffer.from('abc'), Buffer.from('abc')];

test('regular ZIP structures, UTF-8 names, empty files, split CRC32 known vectors', async () => {
  const bytes = await smallArchive(files, contents);
  parseSmall(bytes, files, contents, [0, 0xcbf43926, 0x352441c2, 0x352441c2]);
  const empty = await smallArchive([], []);
  assert.equal(empty.length, 22);
  parseSmall(empty, [], [], []);
});

test('Python zipfile independently reads names, stored data, CRC and sizes', async () => {
  const bytes = await smallArchive(files, contents);
  const result = spawnSync('python3', ['-c', `
import io, json, sys, zipfile
with zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read())) as archive:
    assert archive.testzip() is None
    assert all(info.compress_type == zipfile.ZIP_STORED for info in archive.infolist())
    print(json.dumps([[info.filename, archive.read(info).hex(), info.file_size] for info in archive.infolist()]))
`], { input: bytes, encoding: 'utf8' });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), files.map((entry, i) => [entry.path, contents[i].toString('hex'), entry.size]));
});

test('DOS dates clamp to 1980..2107 and truncate odd seconds', async () => {
  const dates = [-8640000000000000, 8640000000000000, new Date(2024, 5, 7, 8, 9, 11, 999).getTime()];
  const expected = [[0, 33], [0xbf7d, 0xff9f], [(8 << 11) | (9 << 5) | 5, (44 << 9) | (6 << 5) | 7]];
  for (let i = 0; i < dates.length; i++) {
    const bytes = await smallArchive([file('date', 0, dates[i])], [Buffer.alloc(0)]);
    assert.equal(u16(bytes, 10), expected[i][0]);
    assert.equal(u16(bytes, 12), expected[i][1]);
    const central = 30 + 4 + 16;
    assert.equal(u16(bytes, central + 12), expected[i][0]);
    assert.equal(u16(bytes, central + 14), expected[i][1]);
  }
});

test('archiveSize exactly accounts for ZIP64 size/offset sentinel boundaries', () => {
  const name = 'x';
  const regularOverhead = 30 + 1 + 16 + 46 + 1 + 22;
  assert.equal(archiveSize([file(name, 0)]), regularOverhead);
  // Central offset reaches the sentinel even though the only file is regular.
  const atCentralBoundary = U32_MAX - (30 + 1 + 16);
  assert.equal(archiveSize([file(name, atCentralBoundary - 1)]), atCentralBoundary - 1 + regularOverhead);
  assert.equal(archiveSize([file(name, atCentralBoundary)]), atCentralBoundary + regularOverhead + 76);
  for (const size of [U32_MAX, U32_MAX + 1, 20 * GiB]) {
    assert.equal(archiveSize([file(name, size)]), size + 51 + 24 + 67 + 98);
  }
  // Second file needs an offset-only extra; local header and descriptor stay regular.
  assert.equal(archiveSize([file('x', U32_MAX + 1), file('y', 0)]), U32_MAX + 1 + 51 + 24 + 31 + 16 + 67 + 59 + 98);
});

test('ZIP64 streams a >4 GiB file and a >4 GiB offset with bounded allocations', async () => {
  const chunk = new Uint8Array(8 * 1024 ** 2);
  const metadata = [];
  let written = 0;
  const writer = new ZipWriter({
    async write(bytes) {
      // The reusable payload is counted, never copied or retained.
      if (bytes !== chunk && bytes.length !== 1) metadata.push({ offset: written, bytes: Buffer.from(bytes) });
      written += bytes.length;
    },
    async close() {},
  });
  const entries = [file('large', 4 * GiB + 1), file('empty', 0)];
  await writer.startFile(entries[0]);
  for (let i = 0; i < 512; i++) await writer.write(chunk);
  await writer.write(new Uint8Array(1));
  await writer.endFile();
  await writer.startFile(entries[1]);
  await writer.endFile();
  await writer.close();
  assert.equal(written, archiveSize(entries));
  assert.equal(metadata.length, 7);
  const [local, descriptor, nextLocal, nextDescriptor, central, nextCentral, ending] = metadata.map(part => part.bytes);
  assert.equal(u16(local, 4), 45);
  assert.equal(u32(local, 18), U32_MAX);
  assert.equal(u32(local, 22), U32_MAX);
  assert.equal(u16(local, 28), 20);
  assert.equal(u16(local, 35), 1);
  assert.equal(u16(local, 37), 16);
  assert.equal(u64(local, 39), entries[0].size);
  assert.equal(u64(local, 47), entries[0].size);
  assert.equal(descriptor.length, 24);
  assert.equal(u32(descriptor, 0), 0x08074b50);
  assert.equal(u64(descriptor, 8), entries[0].size);
  assert.equal(u64(descriptor, 16), entries[0].size);
  // Independent zlib computes the same rolling CRC without allocating the file.
  const crc = spawnSync('python3', ['-c', 'import zlib; b=bytes(8*1024**2); c=0\nfor i in range(512): c=zlib.crc32(b,c)\nprint(zlib.crc32(bytes(1),c))'], { encoding: 'utf8' });
  assert.ifError(crc.error);
  assert.equal(crc.status, 0, crc.stderr);
  assert.equal(u32(descriptor, 4), Number(crc.stdout));
  assert.equal(u16(nextLocal, 4), 20);
  assert.equal(u16(nextLocal, 28), 0);
  assert.equal(nextDescriptor.length, 16);
  assert.equal(u32(central, 16), u32(descriptor, 4));
  assert.equal(u32(central, 20), U32_MAX);
  assert.equal(u32(central, 24), U32_MAX);
  assert.equal(u16(central, 30), 20);
  assert.equal(u64(central, 55), entries[0].size);
  assert.equal(u64(central, 63), entries[0].size);
  assert.equal(u16(nextCentral, 6), 45);
  assert.equal(u16(nextCentral, 30), 12);
  assert.equal(u32(nextCentral, 42), U32_MAX);
  assert.equal(u16(nextCentral, 51), 1);
  assert.equal(u16(nextCentral, 53), 8);
  assert.equal(u64(nextCentral, 55), metadata[2].offset);
  assert.equal(ending.length, 98);
  assert.equal(u32(ending, 0), 0x06064b50);
  assert.equal(u64(ending, 4), 44);
  assert.equal(u64(ending, 24), 2);
  assert.equal(u64(ending, 32), 2);
  assert.equal(u64(ending, 40), central.length + nextCentral.length);
  assert.equal(u64(ending, 48), metadata[4].offset);
  assert.equal(u32(ending, 56), 0x07064b50);
  assert.equal(u64(ending, 64), metadata[6].offset);
  assert.equal(u32(ending, 72), 1);
  assert.equal(u32(ending, 76), 0x06054b50);
  assert.equal(u32(ending, 88), central.length + nextCentral.length);
  assert.equal(u32(ending, 92), U32_MAX);
});

test('validates paths, sizes, timestamps, count, package limits and duplicates', async () => {
  const sink = { async write() {}, async close() {} };
  const invalid = [file('../x', 0), file('/x', 0), file('a//b', 0), file('a\\b', 0), file('\ud800', 0), file('x'.repeat(4097), 0), ...[-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER, 20 * GiB + 1].map(size => file('x', size)), file('x', 0, NaN), file('x', 0, Infinity)];
  for (const entry of invalid) {
    assert.throws(() => archiveSize([entry]));
    await assert.rejects(new ZipWriter(sink).startFile(entry));
  }
  assert.throws(() => archiveSize([file('x', 0), file('x', 0)]));
  assert.throws(() => archiveSize([file('x', 20 * GiB), file('y', 1)]));
  const many = Array.from({ length: 20000 }, (_, i) => file(String(i), 0));
  assert.ok(Number.isSafeInteger(archiveSize(many)));
  assert.throws(() => archiveSize([...many, file('extra', 0)]));
  const writer = new ZipWriter(sink);
  for (const entry of many) {
    await writer.startFile(entry);
    await writer.endFile();
  }
  await assert.rejects(writer.startFile(file('extra', 0)));
  await writer.close();
  const duplicate = new ZipWriter(sink);
  await duplicate.startFile(file('x', 0));
  await duplicate.endFile();
  await assert.rejects(duplicate.startFile(file('x', 0)));
  assert.throws(() => new ZipWriter({}));
});

test('enforces ordering, complete files, Uint8Array writes, backpressure and concurrency', async () => {
  let release;
  let writes = 0;
  let closes = 0;
  const writer = new ZipWriter({
    async write() { writes++; await new Promise(resolve => { release = resolve; }); },
    async close() { closes++; await new Promise(resolve => { release = resolve; }); },
  });
  await assert.rejects(writer.write(new Uint8Array(1)));
  await assert.rejects(writer.endFile());
  const start = writer.startFile(file('x', 2));
  assert.equal(writes, 1);
  await assert.rejects(writer.startFile(file('y', 0)));
  await assert.rejects(writer.close());
  release(); await start;
  await assert.rejects(writer.startFile(file('y', 0)));
  await assert.rejects(writer.endFile());
  await assert.rejects(writer.close());
  await assert.rejects(writer.write(new Uint8Array(3)));
  await assert.rejects(writer.write([1, 2]));
  const write = writer.write(new Uint8Array(2));
  assert.equal(writes, 2);
  await assert.rejects(writer.endFile());
  release(); await write;
  const end = writer.endFile();
  assert.equal(writes, 3);
  release(); await end;
  const close = writer.close();
  assert.equal(writes, 4);
  assert.equal(closes, 0);
  release();
  while (writes !== 5) await new Promise(resolve => setImmediate(resolve));
  assert.equal(closes, 0);
  release();
  while (closes !== 1) await new Promise(resolve => setImmediate(resolve));
  await assert.rejects(writer.close());
  release(); await close;
  await assert.rejects(writer.close());
  await assert.rejects(writer.startFile(file('y', 0)));
  await assert.rejects(writer.write(new Uint8Array(0)));
  await assert.rejects(writer.endFile());
});

test('sink write and close errors propagate and permanently fail writer', async () => {
  const failure = new Error('sink failed');
  for (const failAt of [1, 2, 3, 4, 5, 6]) {
    let calls = 0;
    const operation = async () => { if (++calls === failAt) throw failure; };
    const writer = new ZipWriter({ write: operation, close: operation });
    await assert.rejects(async () => {
      await writer.startFile(file('x', 1));
      await writer.write(new Uint8Array(1));
      await writer.endFile();
      await writer.close();
    }, error => error === failure);
    const before = calls;
    await assert.rejects(writer.close());
    await assert.rejects(writer.write(new Uint8Array(1)));
    assert.equal(calls, before);
  }
});
