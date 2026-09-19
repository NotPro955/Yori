// Ed25519 Identity Key Management and IndexedDB Persistence.
// Noble is used only for Ed25519; Web Crypto handles X25519, HKDF and AEAD.
import * as ed from 'https://cdn.jsdelivr.net/npm/@noble/ed25519@2.1.0/index.js';

const DB_NAME = 'yori_crypto_db';
const DB_VERSION = 1;
const STORE_NAME = 'identities';

function openDB() {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      return resolve(null); // Node / fallback environment
    }
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'username' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export function bytesToB64(bytes) {
  const bin = String.fromCharCode(...new Uint8Array(bytes));
  return btoa(bin).replace(/=/g, '');
}

export function b64ToBytes(b64) {
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

export function bytesToHex(bytes) {
  return Array.from(new Uint8Array(bytes))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function getFingerprintHex(pubKeyB64) {
  const pubBytes = b64ToBytes(pubKeyB64);
  const hash = await crypto.subtle.digest('SHA-256', pubBytes);
  return bytesToHex(hash);
}

export async function initIdentityKey(username, logger = console.log) {
  const db = await openDB();
  if (db) {
    const existing = await new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const req = tx.objectStore(STORE_NAME).get(username);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    });

    if (existing && existing.privateKeyB64 && existing.pubB64) {
      logger(`[identity] loaded existing key`);
      return {
        keyPair: { privateKey: b64ToBytes(existing.privateKeyB64), publicKey: b64ToBytes(existing.pubB64) },
        pubB64: existing.pubB64,
        fingerprint: await getFingerprintHex(existing.pubB64)
      };
    }

    // Migration for identities written by an earlier Web Crypto implementation:
    // an Ed25519 PKCS#8 private key ends with its 32-byte seed.
    if (existing && existing.pkcs8 && existing.pubB64) {
      const seed = new Uint8Array(existing.pkcs8).slice(-32);
      logger(`[identity] loaded existing key`);
      return {
        keyPair: { privateKey: seed, publicKey: b64ToBytes(existing.pubB64) },
        pubB64: existing.pubB64,
        fingerprint: await getFingerprintHex(existing.pubB64)
      };
    }
  }

  // Generate new key pair
  const privateKey = crypto.getRandomValues(new Uint8Array(32));
  const rawPub = await ed.getPublicKeyAsync(privateKey);
  const pubB64 = bytesToB64(rawPub);

  if (db) {
    await new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      tx.objectStore(STORE_NAME).put({
        username,
        pubB64,
        privateKeyB64: bytesToB64(privateKey)
      });
      tx.oncomplete = () => resolve();
    });
  }

  logger(`[identity] generated new key`);
  return {
    keyPair: { privateKey, publicKey: rawPub },
    pubB64,
    fingerprint: await getFingerprintHex(pubB64)
  };
}

export async function signSessionMetadata(identityPrivKey, sender, sessionID, ephemeralPubB64) {
  const msg = new TextEncoder().encode(`yori/session/v1|${sender}|${sessionID}|${ephemeralPubB64}`);
  const sig = await ed.signAsync(msg, identityPrivKey);
  return bytesToB64(sig);
}

export async function verifySessionMetadata(identityPubB64, sender, sessionID, ephemeralPubB64, signatureB64) {
  try {
    const msg = new TextEncoder().encode(`yori/session/v1|${sender}|${sessionID}|${ephemeralPubB64}`);
    const sig = b64ToBytes(signatureB64);
    return await ed.verifyAsync(sig, msg, b64ToBytes(identityPubB64));
  } catch (err) {
    return false;
  }
}
