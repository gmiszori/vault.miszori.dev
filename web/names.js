const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

function encode(bytes) {
  return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function decode(value, min, max) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > Math.ceil(max * 4 / 3)) throw new Error('Invalid name encryption data.');
  const bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), char => char.charCodeAt(0));
  if (bytes.length < min || bytes.length > max || encode(bytes) !== value) throw new Error('Invalid name encryption data.');
  return bytes;
}

export function validateLabelKey(config) {
  if (!config || config.version !== 1 || config.iterations !== 600000) throw new Error('Invalid name key configuration.');
  decode(config.salt, 16, 16);
  return { version: 1, salt: config.salt, iterations: 600000 };
}

export function validateName(value) {
  if (typeof value !== 'string' || /[\p{Cc}\p{Cf}\p{Cs}]/u.test(value)) throw new Error('Names cannot contain control characters.');
  const name = value.trim();
  if ([...name].length > 120 || encoder.encode(name).length > 480) throw new Error('Names must be at most 120 Unicode characters and 480 UTF-8 bytes.');
  return name;
}

export async function deriveNameKey(passphrase, config) {
  validateLabelKey(config);
  if (typeof passphrase !== 'string' || [...passphrase].length < 16 || passphrase.length > 1024) throw new Error('Use a separate passphrase of 16–1,024 characters.');
  const bytes = encoder.encode(passphrase);
  try {
    const material = await crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveKey']);
    return await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: decode(config.salt, 16, 16), iterations: config.iterations }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally { bytes.fill(0); }
}

function aad(id) {
  if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(id)) throw new Error('Invalid package identifier.');
  return encoder.encode(`drive.miszori.dev:admin-name:v1:${id}`);
}

export async function encryptName(key, id, value) {
  const name = validateName(value);
  if (!name) throw new Error('Enter a package name.');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(name);
  try {
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(id), tagLength: 128 }, key, plaintext);
    return { version: 1, iv: encode(iv), ciphertext: encode(new Uint8Array(ciphertext)) };
  } finally { plaintext.fill(0); }
}

export async function decryptName(key, id, envelope) {
  if (!envelope || envelope.version !== 1) throw new Error('Invalid encrypted name.');
  const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decode(envelope.iv, 12, 12), additionalData: aad(id), tagLength: 128 }, key, decode(envelope.ciphertext, 17, 512)));
  try {
    const name = validateName(decoder.decode(plaintext));
    if (!name) throw new Error('Invalid encrypted name.');
    return name;
  } finally { plaintext.fill(0); }
}
