// X25519 ECDH Key Agreement
import { bytesToB64, b64ToBytes } from './identity.js';

export async function generateX25519KeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'X25519' },
    true,
    ['deriveKey', 'deriveBits']
  );
  const rawPub = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  return {
    keyPair,
    pubB64: bytesToB64(rawPub)
  };
}

export async function deriveSharedSecret(privateKey, peerPubKeyB64) {
  const peerPubBytes = b64ToBytes(peerPubKeyB64);
  const peerKey = await crypto.subtle.importKey(
    'raw',
    peerPubBytes,
    { name: 'X25519' },
    true,
    []
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'X25519', public: peerKey },
    privateKey,
    256
  );
  return new Uint8Array(sharedBits);
}
