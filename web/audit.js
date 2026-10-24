const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const P256 = { name: 'ECDH', namedCurve: 'P-256' };
const RECORD_INFO = 'vault.miszori.dev:audit-record:v1';
const BLOCK = 1024;

function encode(bytes) {
  return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function decode(value, min, max) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > Math.ceil(max * 4 / 3)) throw new Error('Invalid activity encryption data.');
  const bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), char => char.charCodeAt(0));
  if (bytes.length < min || bytes.length > max || encode(bytes) !== value) throw new Error('Invalid activity encryption data.');
  return bytes;
}

// The wrapped private key is bound to its public key, so a swapped public key fails to unwrap.
function keyAad(publicKey) {
  return encoder.encode(`vault.miszori.dev:audit-key:v1:${publicKey}`);
}

function recordAad(id) {
  if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(id)) throw new Error('Invalid package identifier.');
  return encoder.encode(`${RECORD_INFO}:${id}`);
}

export function validateAuditKey(config) {
  if (!config || config.version !== 1) throw new Error('Invalid activity key configuration.');
  decode(config.publicKey, 65, 65);
  decode(config.iv, 12, 12);
  decode(config.wrappedKey, 64, 512);
  return { version: 1, publicKey: config.publicKey, iv: config.iv, wrappedKey: config.wrappedKey };
}

// The server receives the public key and a password-wrapped private key, so it can seal
// retrieval records that only this password can open.
export async function createAuditKey(wrapKey) {
  const pair = await crypto.subtle.generateKey(P256, true, ['deriveBits']);
  const publicKey = encode(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  try {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: keyAad(publicKey), tagLength: 128 }, wrapKey, pkcs8);
    const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, P256, false, ['deriveBits']);
    return { config: { version: 1, publicKey, iv: encode(iv), wrappedKey: encode(new Uint8Array(wrapped)) }, privateKey };
  } finally { pkcs8.fill(0); }
}

export async function unwrapAuditKey(wrapKey, config) {
  const { publicKey, iv, wrappedKey } = validateAuditKey(config);
  const pkcs8 = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decode(iv, 12, 12), additionalData: keyAad(publicKey), tagLength: 128 }, wrapKey, decode(wrappedKey, 64, 512)));
  try { return await crypto.subtle.importKey('pkcs8', pkcs8, P256, false, ['deriveBits']); }
  finally { pkcs8.fill(0); }
}

function validBrowser(profile) {
  if (profile === null || profile === undefined) return null;
  if (typeof profile !== 'object' || !['browser', 'os', 'deviceType', 'userAgent'].every(field => typeof profile[field] === 'string')) throw new Error('Invalid activity record.');
  return { browser: profile.browser, os: profile.os, deviceType: profile.deviceType, userAgent: profile.userAgent };
}

// Opens a record sealed by the server: ECDH(audit key, ephemeral) -> HKDF-SHA256 -> AES-256-GCM.
export async function openRecord(privateKey, id, record) {
  if (!record || record.version !== 1) throw new Error('Invalid activity record.');
  const ephemeralKey = decode(record.ephemeralKey, 65, 65);
  const ciphertext = decode(record.ciphertext, BLOCK + 16, 4 * BLOCK + 16);
  if ((ciphertext.length - 16) % BLOCK) throw new Error('Invalid activity record.');
  const ephemeral = await crypto.subtle.importKey('raw', ephemeralKey, P256, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: ephemeral }, privateKey, 256));
  let key;
  try {
    const material = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: ephemeralKey, info: encoder.encode(RECORD_INFO) }, material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  } finally { shared.fill(0); }
  const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decode(record.iv, 12, 12), additionalData: recordAad(id), tagLength: 128 }, key, ciphertext));
  try {
    const value = JSON.parse(decoder.decode(plaintext));
    if (!value || typeof value.openedAt !== 'string' || !Number.isFinite(Date.parse(value.openedAt)) || typeof value.openedIp !== 'string') throw new Error('Invalid activity record.');
    return { openedAt: value.openedAt, openedIp: value.openedIp, openedBrowser: validBrowser(value.openedBrowser) };
  } finally { plaintext.fill(0); }
}
