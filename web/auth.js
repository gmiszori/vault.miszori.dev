import { validateLabelKey } from './names.js';

const encoder = new TextEncoder();

function encode(bytes) {
  return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function validateAuthConfig(config) {
  if (!config || typeof config.initialized !== 'boolean' || typeof config.username !== 'string' || !config.username || config.username.includes(':') || /[\p{Cc}\p{Cs}]/u.test(config.username)) throw new Error('Invalid admin authentication configuration.');
  return { initialized: config.initialized, username: config.username, labelKey: validateLabelKey(config.labelKey), publicOrigin: config.publicOrigin };
}

export async function deriveAdminKeys(password, config) {
  validateLabelKey(config);
  if (typeof password !== 'string' || [...password].length < 16 || [...password].length > 1024 || /\p{Cs}/u.test(password)) throw new Error('Use a password of 16–1,024 Unicode characters. A strong random password is recommended.');
  const bytes = encoder.encode(password);
  password = '';
  let root;
  let authentication;
  try {
    const salt = Uint8Array.from(atob(config.salt.replaceAll('-', '+').replaceAll('_', '/')), char => char.charCodeAt(0));
    const material = await crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveBits']);
    bytes.fill(0);
    root = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: config.iterations }, material, 256));
    const hkdf = await crypto.subtle.importKey('raw', root, 'HKDF', false, ['deriveBits', 'deriveKey']);
    root.fill(0);
    authentication = new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode('drive.miszori.dev:admin-auth:v1') }, hkdf, 256));
    const nameKey = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode('drive.miszori.dev:admin-names:v1') }, hkdf, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    return { authentication: encode(authentication), nameKey };
  } finally {
    bytes.fill(0);
    root?.fill(0);
    authentication?.fill(0);
  }
}

export function adminAuthorization(username, authentication) {
  if (typeof username !== 'string' || !username || username.includes(':') || /[\p{Cc}\p{Cs}]/u.test(username) || typeof authentication !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(authentication)) throw new Error('Invalid admin credentials.');
  const bytes = encoder.encode(`${username}:${authentication}`);
  try { return `Basic ${btoa(String.fromCharCode(...bytes))}`; }
  finally { bytes.fill(0); }
}
