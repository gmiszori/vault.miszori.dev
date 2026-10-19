export const CHUNK_SIZE = 8 * 1024 * 1024;
export const MAX_CIPHERTEXT = CHUNK_SIZE + 16;
export const MAX_BYTES = 20 * 1024 ** 3;
export const MAX_FILES = 20000;
export const MEMORY_LIMIT = 128 * 1024 ** 2;
export const MAX_TEXT_BYTES = CHUNK_SIZE;
const encoder = new TextEncoder();

export function encodeKey(bytes) {
  return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function decodeKey(value) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) throw new Error('This link is missing a valid decryption key.');
  const bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='), c => c.charCodeAt(0));
  if (bytes.length !== 32 || encodeKey(bytes) !== value) throw new Error('The link’s decryption key is invalid.');
  return bytes;
}

export async function deriveClaimToken(rawKey, id) {
  if (!(rawKey instanceof Uint8Array) || rawKey.byteLength !== 32) throw new Error('Invalid file key.');
  if (typeof id !== 'string' || id.length < 1 || id.length > 128 || /[^A-Za-z0-9_-]/.test(id)) throw new Error('Invalid package identifier.');
  const key = await crypto.subtle.importKey('raw', rawKey, 'HKDF', false, ['deriveBits']);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({
    name: 'HKDF', hash: 'SHA-256', salt: encoder.encode(id),
    info: encoder.encode('vault.miszori.dev:package-claim:v1')
  }, key, 256));
  try { return encodeKey(secret); } finally { secret.fill(0); }
}

export async function claimHash(token) {
  if (typeof token !== 'string') throw new Error('Invalid claim token.');
  const secret = decodeKey(token);
  try {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', secret));
    return Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
  } finally { secret.fill(0); }
}

export function importKey(bytes) {
  return crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export function chunkParameters(id, index) {
  if (!Number.isSafeInteger(index) || index < 0) throw new Error('Invalid chunk index.');
  const iv = new Uint8Array(12);
  new DataView(iv.buffer).setBigUint64(4, BigInt(index), false);
  return { name: 'AES-GCM', iv, additionalData: encoder.encode(`${id}:${index}`), tagLength: 128 };
}

export async function encryptChunk(key, id, index, plaintext) {
  if (plaintext.byteLength > CHUNK_SIZE) throw new Error('Plaintext chunk exceeds the 8 MiB limit.');
  return new Uint8Array(await crypto.subtle.encrypt(chunkParameters(id, index), key, plaintext));
}

export async function decryptChunk(key, id, index, ciphertext) {
  if (ciphertext.byteLength < 16 || ciphertext.byteLength > MAX_CIPHERTEXT) throw new Error('Invalid encrypted record size.');
  try {
    return new Uint8Array(await crypto.subtle.decrypt(chunkParameters(id, index), key, ciphertext));
  } catch {
    throw new Error('Decryption failed. The key is incorrect, or the transfer is damaged.');
  }
}

export function validatePath(path) {
  if (typeof path !== 'string' || !path || encoder.encode(path).length > 4096 || /[\\\x00-\x1f\x7f:]/u.test(path)) {
    throw new Error('A file has an unsafe or unsupported path.');
  }
  if (path.split('/').some(part => !part || part === '.' || part === '..')) throw new Error('A file has an unsafe path.');
  // Unpaired UTF-16 surrogates cannot round-trip through the UTF-8 manifest.
  if (new TextDecoder().decode(encoder.encode(path)) !== path) throw new Error('A file path contains invalid Unicode.');
  return path;
}

export function validateManifest(manifest) {
  if (!manifest || manifest.version !== 1 || manifest.chunkSize !== CHUNK_SIZE || !Array.isArray(manifest.files) || !manifest.files.length || manifest.files.length > MAX_FILES) {
    throw new Error('Invalid or unsupported package manifest.');
  }
  let bytes = 0;
  let chunks = 1;
  const paths = new Set();
  const parents = new Set();
  const files = manifest.files.map(file => {
    if (!file || typeof file !== 'object') throw new Error('Invalid file entry.');
    const path = validatePath(file.path);
    const normalized = path.normalize('NFC');
    if (paths.has(normalized) || parents.has(normalized)) throw new Error('Duplicate or conflicting file paths.');
    const parts = normalized.split('/');
    for (let i = 1; i < parts.length; i++) {
      const parent = parts.slice(0, i).join('/');
      if (paths.has(parent)) throw new Error('Conflicting file and folder paths.');
      parents.add(parent);
    }
    paths.add(normalized);
    if (!Number.isSafeInteger(file.size) || file.size < 0 || !Number.isSafeInteger(file.lastModified) || file.lastModified < 0 || file.lastModified > 8640000000000000) {
      throw new Error('Invalid file size or modification date.');
    }
    bytes += file.size;
    chunks += Math.ceil(file.size / CHUNK_SIZE);
    if (bytes > MAX_BYTES) throw new Error('The package exceeds the 20 GiB limit.');
    if (chunks > 30000) throw new Error('The package exceeds the 30,000-record limit.');
    return { path, size: file.size, lastModified: file.lastModified };
  });
  return { manifest: { version: 1, files, chunkSize: CHUNK_SIZE }, bytes, chunks };
}

export function serializeManifest(files) {
  const validated = validateManifest({ version: 1, files, chunkSize: CHUNK_SIZE });
  const plaintext = encoder.encode(JSON.stringify(validated.manifest));
  if (plaintext.byteLength > CHUNK_SIZE) throw new Error('File names make the manifest too large (maximum 8 MiB).');
  return { ...validated, plaintext };
}

export function parseManifest(bytes) {
  if (bytes.byteLength > CHUNK_SIZE) throw new Error('The manifest is too large.');
  let manifest;
  try {
    manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new Error('The encrypted manifest is not valid UTF-8 JSON.');
  }
  return validateManifest(manifest);
}

export function serializeText(value) {
  if (typeof value !== 'string' || /\p{Cs}/u.test(value)) throw new Error('Secret contains invalid Unicode.');
  const text = encoder.encode(value);
  if (!text.byteLength || text.byteLength > MAX_TEXT_BYTES) throw new Error('Enter a secret up to 8 MiB in UTF-8.');
  const manifest = { version: 1, format: 'text', size: text.byteLength, chunkSize: CHUNK_SIZE };
  return { plaintext: encoder.encode(JSON.stringify(manifest)), text, bytes: text.byteLength, chunks: 2 };
}

export function parseTextManifest(bytes) {
  if (bytes.byteLength > 1024) throw new Error('Invalid secret manifest.');
  let manifest;
  try { manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { throw new Error('Invalid secret manifest.'); }
  if (!manifest || manifest.version !== 1 || manifest.format !== 'text' || manifest.chunkSize !== CHUNK_SIZE || !Number.isSafeInteger(manifest.size) || manifest.size < 1 || manifest.size > MAX_TEXT_BYTES) throw new Error('Invalid secret manifest.');
  return manifest;
}

export class FramedReader {
  constructor(stream, onProgress) {
    if (!stream) throw new Error('This browser did not provide a download stream.');
    this.reader = stream.getReader();
    this.onProgress = onProgress;
    this.buffer = new Uint8Array(0);
    this.offset = 0;
  }

  async exact(length, allowEnd = false) {
    const result = new Uint8Array(length);
    let written = 0;
    while (written < length) {
      if (this.offset === this.buffer.length) {
        const { value, done } = await this.reader.read();
        if (done) {
          if (allowEnd && written === 0) return null;
          throw new Error('The transfer ended early. It cannot be resumed.');
        }
        this.buffer = value;
        this.offset = 0;
        if (!value.length) continue;
      }
      const take = Math.min(length - written, this.buffer.length - this.offset);
      result.set(this.buffer.subarray(this.offset, this.offset + take), written);
      this.offset += take;
      written += take;
      this.onProgress?.(take);
    }
    return result;
  }

  async record() {
    const header = await this.exact(4);
    const length = new DataView(header.buffer).getUint32(0, false);
    if (length < 16 || length > MAX_CIPHERTEXT) throw new Error('The transfer contains an invalid record length.');
    return this.exact(length);
  }

  async end() {
    if (await this.exact(1, true) !== null) throw new Error('The transfer contains unexpected extra data.');
  }

  async cancel() {
    try { await this.reader.cancel(); } catch { /* The request may already be aborted. */ }
  }
}

export function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  const unit = Math.min(3, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / 1024 ** unit).toLocaleString(undefined, { maximumFractionDigits: unit ? 1 : 0 })} ${units[unit]}`;
}
