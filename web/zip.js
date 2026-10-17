import { validatePath } from './crypto.js';

const encoder = new TextEncoder();
const U32_MAX = 0xffffffff;
const MAX_BYTES = 20 * 1024 ** 3;
const MAX_FILES = 20000;
const FLAGS = 0x0808; // UTF-8 names and trailing data descriptors.
const crcTable = Uint32Array.from({ length: 256 }, (_, value) => {
  for (let bit = 0; bit < 8; bit++) value = (value >>> 1) ^ ((value & 1) ? 0xedb88320 : 0);
  return value >>> 0;
});

function add(a, b) {
  const result = a + b;
  if (!Number.isSafeInteger(a) || !Number.isSafeInteger(b) || a < 0 || b < 0 || !Number.isSafeInteger(result)) {
    throw new Error('ZIP size exceeds safe integer limits.');
  }
  return result;
}

function record(size, signature) {
  const bytes = new Uint8Array(size);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, signature, true);
  return { bytes, view };
}

function u64(view, offset, value) {
  view.setBigUint64(offset, BigInt(value), true);
}

function metadata(file) {
  validatePath(file.path);
  if (!Number.isSafeInteger(file.size) || file.size < 0 || file.size > MAX_BYTES) throw new Error('Invalid ZIP file size.');
  if (!Number.isFinite(file.lastModified)) throw new Error('Invalid ZIP file timestamp.');
  const date = new Date(Math.max(-8640000000000000, Math.min(8640000000000000, file.lastModified)));
  const year = date.getFullYear();
  const dosDate = year < 1980 ? 33 : year > 2107 ? 0xff9f : ((year - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
  const dosTime = year < 1980 ? 0 : year > 2107 ? 0xbf7d : (date.getHours() << 11) | (date.getMinutes() << 5) | (date.getSeconds() >>> 1);
  return { path: file.path, name: encoder.encode(file.path), size: file.size, dosDate, dosTime, large: file.size >= U32_MAX };
}

function centralExtraLength(entry) {
  return (entry.large || entry.offset >= U32_MAX) ? 4 + (entry.large ? 16 : 0) + (entry.offset >= U32_MAX ? 8 : 0) : 0;
}

function localLength(entry) { return 30 + entry.name.length + (entry.large ? 20 : 0); }
function descriptorLength(entry) { return entry.large ? 24 : 16; }
function centralLength(entry) { return 46 + entry.name.length + centralExtraLength(entry); }

function endings(count, size, offset, zip64) {
  const { bytes, view } = record(zip64 ? 98 : 22, zip64 ? 0x06064b50 : 0x06054b50);
  const end = zip64 ? 76 : 0;
  if (zip64) {
    u64(view, 4, 44);
    view.setUint16(12, 45, true);
    view.setUint16(14, 45, true);
    u64(view, 24, count);
    u64(view, 32, count);
    u64(view, 40, size);
    u64(view, 48, offset);
    view.setUint32(56, 0x07064b50, true);
    u64(view, 64, add(offset, size));
    view.setUint32(72, 1, true);
    view.setUint32(end, 0x06054b50, true);
  }
  view.setUint16(end + 8, count, true);
  view.setUint16(end + 10, count, true);
  view.setUint32(end + 12, Math.min(size, U32_MAX), true);
  view.setUint32(end + 16, Math.min(offset, U32_MAX), true);
  return bytes;
}

export function archiveSize(files) {
  let offset = 0;
  let dataSize = 0;
  let centralSize = 0;
  let count = 0;
  let zip64 = false;
  const paths = new Set();
  for (const file of files) {
    const entry = metadata(file);
    if (++count > MAX_FILES || paths.has(entry.path)) throw new Error('Too many ZIP files or duplicate path.');
    paths.add(entry.path);
    dataSize = add(dataSize, entry.size);
    if (dataSize > MAX_BYTES) throw new Error('ZIP package exceeds 20 GiB.');
    entry.offset = offset;
    centralSize = add(centralSize, centralLength(entry));
    offset = add(offset, add(localLength(entry), add(entry.size, descriptorLength(entry))));
    zip64 ||= entry.large || entry.offset >= U32_MAX;
  }
  zip64 ||= offset >= U32_MAX || centralSize >= U32_MAX;
  return add(add(offset, centralSize), zip64 ? 98 : 22);
}

// Calls must be awaited sequentially. A rejected sink operation permanently fails the writer.
export class ZipWriter {
  constructor(sink) {
    if (typeof sink?.write !== 'function' || typeof sink?.close !== 'function') throw new Error('Invalid ZIP sink.');
    this.sink = sink;
    this.offset = 0;
    this.dataSize = 0;
    this.entries = [];
    this.paths = new Set();
    this.current = null;
    this.busy = false;
    this.closed = false;
    this.failed = false;
  }

  async _run(action) {
    if (this.busy || this.closed || this.failed) throw new Error('ZIP writer is busy, closed or failed.');
    this.busy = true;
    try { return await action(); } finally { this.busy = false; }
  }

  async _emit(bytes) {
    const next = add(this.offset, bytes.length);
    try { await this.sink.write(bytes); } catch (error) { this.failed = true; throw error; }
    this.offset = next;
  }

  async startFile(file) {
    return this._run(async () => {
      if (this.current) throw new Error('ZIP file order is invalid.');
      const entry = metadata(file);
      if (this.entries.length >= MAX_FILES || this.paths.has(entry.path)) throw new Error('Too many ZIP files or duplicate path.');
      const total = add(this.dataSize, entry.size);
      if (total > MAX_BYTES) throw new Error('ZIP package exceeds 20 GiB.');
      entry.offset = this.offset;
      entry.remaining = entry.size;
      entry.crc = U32_MAX;
      const { bytes, view } = record(localLength(entry), 0x04034b50);
      view.setUint16(4, entry.large ? 45 : 20, true);
      view.setUint16(6, FLAGS, true);
      view.setUint16(10, entry.dosTime, true);
      view.setUint16(12, entry.dosDate, true);
      view.setUint16(26, entry.name.length, true);
      view.setUint16(28, entry.large ? 20 : 0, true);
      bytes.set(entry.name, 30);
      if (entry.large) {
        view.setUint32(18, U32_MAX, true);
        view.setUint32(22, U32_MAX, true);
        const extra = 30 + entry.name.length;
        view.setUint16(extra, 1, true);
        view.setUint16(extra + 2, 16, true);
        u64(view, extra + 4, entry.size);
        u64(view, extra + 12, entry.size);
      }
      await this._emit(bytes);
      this.current = entry;
      this.paths.add(entry.path);
      this.dataSize = total;
    });
  }

  async write(bytes) {
    return this._run(async () => {
      const entry = this.current;
      if (!entry || !(bytes instanceof Uint8Array) || bytes.length > entry.remaining) throw new Error('ZIP file size or write order is invalid.');
      let crc = entry.crc;
      for (let i = 0; i < bytes.length; i++) crc = (crc >>> 8) ^ crcTable[(crc ^ bytes[i]) & 255];
      await this._emit(bytes);
      entry.crc = crc;
      entry.remaining -= bytes.length;
    });
  }

  async endFile() {
    return this._run(async () => {
      const entry = this.current;
      if (!entry || entry.remaining !== 0) throw new Error('A ZIP file is incomplete.');
      entry.crc = (entry.crc ^ U32_MAX) >>> 0;
      const { bytes, view } = record(descriptorLength(entry), 0x08074b50);
      view.setUint32(4, entry.crc, true);
      if (entry.large) {
        u64(view, 8, entry.size);
        u64(view, 16, entry.size);
      } else {
        view.setUint32(8, entry.size, true);
        view.setUint32(12, entry.size, true);
      }
      await this._emit(bytes);
      this.entries.push(entry);
      this.current = null;
    });
  }

  async close() {
    return this._run(async () => {
      if (this.current) throw new Error('Cannot finish an incomplete ZIP archive.');
      const centralOffset = this.offset;
      let zip64 = false;
      for (const entry of this.entries) {
        const extraLength = centralExtraLength(entry);
        const { bytes, view } = record(centralLength(entry), 0x02014b50);
        const largeOffset = entry.offset >= U32_MAX;
        const version = extraLength ? 45 : 20;
        zip64 ||= !!extraLength;
        view.setUint16(4, version, true);
        view.setUint16(6, version, true);
        view.setUint16(8, FLAGS, true);
        view.setUint16(12, entry.dosTime, true);
        view.setUint16(14, entry.dosDate, true);
        view.setUint32(16, entry.crc, true);
        view.setUint32(20, entry.large ? U32_MAX : entry.size, true);
        view.setUint32(24, entry.large ? U32_MAX : entry.size, true);
        view.setUint16(28, entry.name.length, true);
        view.setUint16(30, extraLength, true);
        view.setUint32(42, largeOffset ? U32_MAX : entry.offset, true);
        bytes.set(entry.name, 46);
        if (extraLength) {
          let extra = 46 + entry.name.length;
          view.setUint16(extra, 1, true);
          view.setUint16(extra + 2, extraLength - 4, true);
          extra += 4;
          if (entry.large) {
            u64(view, extra, entry.size);
            u64(view, extra + 8, entry.size);
            extra += 16;
          }
          if (largeOffset) u64(view, extra, entry.offset);
        }
        await this._emit(bytes);
      }
      const centralSize = this.offset - centralOffset;
      zip64 ||= centralOffset >= U32_MAX || centralSize >= U32_MAX;
      await this._emit(endings(this.entries.length, centralSize, centralOffset, zip64));
      try { await this.sink.close(); } catch (error) { this.failed = true; throw error; }
      this.closed = true;
    });
  }
}
