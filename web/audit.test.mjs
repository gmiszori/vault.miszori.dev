import test from 'node:test';
import assert from 'node:assert/strict';
import { createAuditKey, unwrapAuditKey, openRecord, validateAuditKey } from './audit.js';

const P256 = { name: 'ECDH', namedCurve: 'P-256' };

// Sealed by the Go server's seal() (cmd/vault/audit.go) with the private key below.
const vector = {
  pkcs8: 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2vJzIWprDG4mHvMoL7rrd8giw1uErT1a65mPOPCVGEKhRANCAAS6QEx7Rvg9rlsiOLv04GmR2gam6gqjGIYj1YJG0lYP76uoLS8uimi6SrCnQQhn_SnLj_d33CuyReRvSaMDlmA6',
  id: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  record: {
    version: 1,
    ephemeralKey: 'BIZwLHWCOM3C_YuSWnaeYpzfGcO1475BCwBHBOL1iX63l8N8Y6H29HXQKtz3b-RkhBa4LY8_VRCxbljOki5YKqI',
    iv: 'j90lVQya0AoGPaVq',
    ciphertext: 'ywkShtV_OEDltltnq1O43QOsQH0m5HINas9HUcYaZ2UpPR3QRBvDHdRE2gCLWxlfxlvbv8jjOuhqImSeAyjLt3C-7UA3MeI6Fhi6nCHReg6l7e544-SLo7EQkmFSH3kQNvh-FwRhNn-gRd9-JoXGqxse5KqcTJNKXOUcMJo7mA14cGw0WsJNHrDM3acvdx8lcQF5PQp48OpS-UbEZvpFdKVW9uuTTerXgbrTCKtDTxxdV5AmqUlNizOU6jfwy6eY6jhLdEiAD0jYHN0MehHq4ubkLAs_EJUczE85T4WfzWDytKm6r1REw6DFQVGZ28GUuRD0_KVix0hM3neK-cSjONFjyBuTol61a8Ty9ypLcGIXUoXz71S4MmhhFL6fvyo94LCPA6-adO5tpiupbv-idtAYu9viR_eej_T9B1jF3vVbXXR48Rv3ilu7cO7qrDrqb9lCBlCCUx-kMM7DPKxFqx_n5hx72JKOR5MWhIzFxGb72lrcSC0VbMppvh86H8F3sT3006QzZPdXOwKMu-5Ly3v17zywQRQdEzFbgHBQnlcZPnOvNAcL0rVk9cfncuaDXx05MVL2PLiKH2gMhb8koSNYDB3UvI-DOJTRQ7-1jAmv9MgGIIMRcBTJnu7vFEGjl9vwrfXZeZ5EFKTg8-vcU0G3x4vfp68ucVVExopjTftTpvj_tANCb4zAGKUrjArRgzAd8UNCL45dR5mxgbwWIDw5B4_xhwCXMUmWDpcHGuaG9L6RqH_QvqPCkkbEowV8ymdonoTFIK2KlB4jtrCRMWlnL_I7IQX9jsTu6pxdaSneTeQ089SkytAZ1zDWbQ2VjFQY-tvhuf0GX0QVblt_SGkO-FH-kOpQKww2v2Bb9R9je0YfvQDOesou1RilD_PpzFJ2vYutdeaKj62_krMbYJP9z7UwYLwmSrPfSavlVbgIJsplIjbEyN0Q41ZgM9AQ1JGK4p7sgrdH5nrJoFCOFhJVKGkvk-PkHYlSes7LCRxShb0PF3Pwaxl-zZnfTTNIDavZzP0aVESTrJVFzMAs8abCv6jIzKbaR0_m2p1tGiYwpZXKusmJQnoXOO8Crba-eMkk-O6IlvGKzbBQJalN_U12n5IrfYUYFJ0ONJQYW5gsnjpBbYqzaYXGUTc-s1Eil1fbBxIoWn5wu3AhJxtgfZrQuNKM1zo-1v5RwBa8qVt_OSeEEwq2YbH0jIeBlQHm7hoSkUI5yCOildAK8CA8N5NsetP3bh8EaVg6ALl4JQevC1nW0qYNY4sCOgY04vQtO3co4MW4UYzIuFs_DMdSRANtJmeRJSntoOdOfeRdA-JYtk_GIuCw8EUE6xzTpOJXeI_pu_L_2KNNPjyvzv5dMNB2YDwRxxHQu-uqolMt7MQ'
  }
};

async function vectorKey() {
  return crypto.subtle.importKey('pkcs8', Buffer.from(vector.pkcs8, 'base64url'), P256, false, ['deriveBits']);
}

async function wrapKey() {
  return crypto.subtle.importKey('raw', crypto.getRandomValues(new Uint8Array(32)), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

test('opens a record sealed by the Go server, including padding and escaped text', async () => {
  const opened = await openRecord(await vectorKey(), vector.id, vector.record);
  assert.deepEqual(opened, {
    openedAt: '2026-01-02T03:04:05Z',
    openedIp: '198.51.100.7',
    openedBrowser: { browser: 'Firefox', os: 'Linux', deviceType: 'desktop', userAgent: 'Mozilla/5.0 <"東京">' }
  });
  assert.equal(Buffer.from(vector.record.ciphertext, 'base64url').length, 1024 + 16);
});

test('sealed records reject another package, tampering, malformed lengths and other keys', async () => {
  const key = await vectorKey();
  await assert.rejects(openRecord(key, vector.id.replace('0', '1'), vector.record));
  const flipped = Buffer.from(vector.record.ciphertext, 'base64url');
  flipped[5] ^= 1;
  await assert.rejects(openRecord(key, vector.id, { ...vector.record, ciphertext: flipped.toString('base64url') }));
  const unpadded = Buffer.concat([Buffer.from(vector.record.ciphertext, 'base64url'), Buffer.alloc(1)]);
  await assert.rejects(openRecord(key, vector.id, { ...vector.record, ciphertext: unpadded.toString('base64url') }), /Invalid activity record/);
  for (const bad of [null, { ...vector.record, version: 2 }, { ...vector.record, iv: 'AAAA' }, { ...vector.record, ephemeralKey: 'AAAA' }]) await assert.rejects(openRecord(key, vector.id, bad));
  await assert.rejects(openRecord(key, '../x', vector.record), /Invalid package identifier/);
  const other = await crypto.subtle.generateKey(P256, false, ['deriveBits']);
  await assert.rejects(openRecord(other.privateKey, vector.id, vector.record));
});

test('the activity private key leaves the browser only wrapped and bound to its public key', async () => {
  const wrap = await wrapKey();
  const { config, privateKey } = await createAuditKey(wrap);
  assert.deepEqual(validateAuditKey(config), config);
  assert.equal(Buffer.from(config.publicKey, 'base64url').length, 65);
  assert.equal(privateKey.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('pkcs8', privateKey));
  const unwrapped = await unwrapAuditKey(wrap, config);
  assert.equal(unwrapped.extractable, false);
  // Both keys derive the same secret against a third party, so they are the same key pair.
  const peer = await crypto.subtle.generateKey(P256, false, ['deriveBits']);
  const derive = key => crypto.subtle.deriveBits({ name: 'ECDH', public: peer.publicKey }, key, 256);
  assert.deepEqual(Buffer.from(await derive(privateKey)), Buffer.from(await derive(unwrapped)));
  await assert.rejects(unwrapAuditKey(await wrapKey(), config));
  const swapped = (await createAuditKey(wrap)).config.publicKey;
  await assert.rejects(unwrapAuditKey(wrap, { ...config, publicKey: swapped }));
  for (const bad of [null, { ...config, version: 2 }, { ...config, publicKey: 'AAAA' }, { ...config, iv: 'AAAA' }, { ...config, wrappedKey: 'AAAA' }]) assert.throws(() => validateAuditKey(bad));
});
