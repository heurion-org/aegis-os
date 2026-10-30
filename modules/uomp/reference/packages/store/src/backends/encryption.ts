/**
 * AES-256-GCM Encryption Layer
 * Node.js: uses crypto module
 * Browser: uses Web Crypto API
 */
import { createCipheriv, createDecipheriv, randomBytes, createHash, createHmac } from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

export interface EncryptedBlob {
  ciphertext: Buffer;
  iv: Buffer;
  tag: Buffer;
  keyId: string;
}

export function encrypt(plaintext: Buffer | string, key: Buffer): EncryptedBlob {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH });
  const data = typeof plaintext === 'string' ? Buffer.from(plaintext) : plaintext;
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  const keyId = createHash('sha256').update(key).digest('hex').slice(0, 16);

  return { ciphertext, iv, tag, keyId };
}

export function decrypt(blob: EncryptedBlob, key: Buffer): Buffer {
  const decipher = createDecipheriv(ALGORITHM, key, blob.iv, { authTagLength: TAG_LENGTH });
  decipher.setAuthTag(blob.tag);
  return Buffer.concat([decipher.update(blob.ciphertext), decipher.final()]);
}

export function serializeBlob(blob: EncryptedBlob): Buffer {
  // Binary format: [iv(12)][tag(16)][keyId(16)][ciphertext]
  return Buffer.concat([blob.iv, blob.tag, Buffer.from(blob.keyId), blob.ciphertext]);
}

export function deserializeBlob(buffer: Buffer): EncryptedBlob {
  const iv = buffer.subarray(0, IV_LENGTH);
  const tag = buffer.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const keyId = buffer.subarray(IV_LENGTH + TAG_LENGTH, IV_LENGTH + TAG_LENGTH + 16).toString();
  const ciphertext = buffer.subarray(IV_LENGTH + TAG_LENGTH + 16);
  return { ciphertext, iv, tag, keyId };
}

export function deriveItemKey(masterKey: Buffer, itemKey: string): Buffer {
  // HKDF-expand: key = HMAC-SHA256(masterKey, itemKey)
  return createHmac('sha256', masterKey).update(`uomp-item:${itemKey}`).digest();
}
