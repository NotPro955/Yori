// AES-256-GCM with Associated Data and 256-byte Padding
import { bytesToB64, b64ToBytes } from './identity.js';

export function pad256(data) {
  let target = 256;
  while (target <= data.length) target += 256;
  const padded = new Uint8Array(target);
  padded.set(data);
  padded[data.length] = 0x80;
  return padded;
}

export function unpad256(data) {
  const arr = new Uint8Array(data);
  for (let i = arr.length - 1; i >= 0; i--) {
    if (arr[i] === 0x80) return arr.slice(0, i);
    if (arr[i] !== 0x00) break;
  }
  throw new Error('invalid padding');
}

export async function encryptBytesAAD(aesKey, plaintextBytes, aadString) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const padded = pad256(plaintextBytes);
  const aadBytes = new TextEncoder().encode(aadString);

  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aadBytes },
    aesKey,
    padded
  );

  const combined = new Uint8Array(nonce.length + ciphertextBuf.byteLength);
  combined.set(nonce);
  combined.set(new Uint8Array(ciphertextBuf), nonce.length);
  return bytesToB64(combined);
}

export async function decryptBytesAAD(aesKey, combinedB64, aadString) {
  const combined = b64ToBytes(combinedB64);
  if (combined.length < 28) { // 12 nonce + 16 tag minimum
    throw new Error('short ciphertext');
  }

  const nonce = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const aadBytes = new TextEncoder().encode(aadString);

  const decryptedBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aadBytes },
    aesKey,
    ciphertext
  );

  return unpad256(new Uint8Array(decryptedBuf));
}
