import { randomBytes, webcrypto, createHash } from 'node:crypto';

export async function protectPackage(packageInfo, rawKey = randomBytes(32)) {
  const material = await webcrypto.subtle.importKey('raw', rawKey, 'HKDF', false, ['deriveBits']);
  const bytes = Buffer.from(await webcrypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: Buffer.from(packageInfo.id), info: Buffer.from('vault.miszori.dev:package-claim:v1') }, material, 256));
  return {
    ...packageInfo,
    rawKey,
    claimToken: bytes.toString('base64url'),
    claimHash: createHash('sha256').update(bytes).digest('hex'),
    claimHeaders: { 'X-Claim-Token': bytes.toString('base64url') }
  };
}
