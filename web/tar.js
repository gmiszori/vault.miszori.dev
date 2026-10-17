import { validatePath } from './crypto.js';

const encoder = new TextEncoder();
const BLOCK = 512;
const ZERO = new Uint8Array(BLOCK);
const MAX_OCTAL = 0o77777777777;
export const padding = size => (BLOCK - size % BLOCK) % BLOCK;

function putString(header, offset, length, value) {
  const bytes = encoder.encode(value);
  if (bytes.length > length) throw new Error('TAR header field is too long.');
  header.set(bytes, offset);
}

function putOctal(header, offset, length, value) {
  const octal = Math.floor(value).toString(8);
  if (octal.length >= length) throw new Error('TAR numeric field overflow.');
  putString(header, offset, length, octal.padStart(length - 1, '0') + '\0');
}

export function paxRecord(key, value) {
  const body = `${key}=${value}\n`;
  const bodyLength = encoder.encode(body).length;
  let length = bodyLength + 3;
  while (String(length).length + 1 + bodyLength !== length) length = String(length).length + 1 + bodyLength;
  return encoder.encode(`${length} ${body}`);
}

function header(name, size, mtime, type = '0') {
  const block = new Uint8Array(BLOCK);
  putString(block, 0, 100, name);
  putOctal(block, 100, 8, 0o644);
  putOctal(block, 108, 8, 0);
  putOctal(block, 116, 8, 0);
  putOctal(block, 124, 12, size);
  putOctal(block, 136, 12, mtime);
  block.fill(32, 148, 156);
  putString(block, 156, 1, type);
  putString(block, 257, 6, 'ustar\0');
  putString(block, 263, 2, '00');
  const checksum = block.reduce((sum, byte) => sum + byte, 0);
  putString(block, 148, 8, checksum.toString(8).padStart(6, '0') + '\0 ');
  return block;
}

export function fileHeaders(file, index = 0) {
  validatePath(file.path);
  const records = [];
  const needsPath = encoder.encode(file.path).length > 100 || /[^\x20-\x7e]/.test(file.path);
  const mtime = file.lastModified / 1000;
  if (needsPath) records.push(paxRecord('path', file.path));
  if (file.size > MAX_OCTAL) records.push(paxRecord('size', String(file.size)));
  if (mtime > MAX_OCTAL || !Number.isInteger(mtime)) records.push(paxRecord('mtime', String(mtime)));
  const parts = [];
  if (records.length) {
    const size = records.reduce((sum, record) => sum + record.length, 0);
    parts.push(header(`PaxHeaders/${index}`, size, 0, 'x'), ...records);
    if (padding(size)) parts.push(ZERO.subarray(0, padding(size)));
  }
  parts.push(header(needsPath ? `file-${index}` : file.path, file.size > MAX_OCTAL ? 0 : file.size, mtime > MAX_OCTAL ? 0 : mtime));
  return parts;
}

export function archiveSize(files) {
  return 1024 + files.reduce((sum, file, index) => sum + fileHeaders(file, index).reduce((n, part) => n + part.length, 0) + file.size + padding(file.size), 0);
}

export class TarWriter {
  constructor(sink) {
    this.sink = sink;
    this.remaining = null;
    this.fileSize = 0;
    this.index = 0;
    this.closed = false;
  }

  async startFile(file) {
    if (this.closed || this.remaining !== null) throw new Error('TAR file order is invalid.');
    for (const part of fileHeaders(file, this.index++)) await this.sink.write(part);
    this.remaining = file.size;
    this.fileSize = file.size;
  }

  async write(bytes) {
    if (this.remaining === null || bytes.length > this.remaining) throw new Error('Decrypted file size does not match its manifest.');
    await this.sink.write(bytes);
    this.remaining -= bytes.length;
  }

  async endFile() {
    if (this.remaining !== 0) throw new Error('A file is incomplete.');
    if (padding(this.fileSize)) await this.sink.write(ZERO.subarray(0, padding(this.fileSize)));
    this.remaining = null;
  }

  async close() {
    if (this.closed || this.remaining !== null) throw new Error('Cannot finish an incomplete archive.');
    await this.sink.write(ZERO);
    await this.sink.write(ZERO);
    await this.sink.close();
    this.closed = true;
  }
}
