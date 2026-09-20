// Onion routing: packet construction and layer peeling
import { generateX25519KeyPair, deriveSharedSecret } from './keyagreement.js';
import { derivePreSessionKey } from './kdf.js';
import { encryptBytesAAD, decryptBytesAAD } from './encryption.js';
import { bytesToB64, b64ToBytes } from './identity.js';

export function randomHex(bytesLen = 8) {
  const bytes = crypto.getRandomValues(new Uint8Array(bytesLen));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Encrypt an onion layer for a target relay's server-advertised relay key.
export async function encryptLayer(targetPubB64, envelopeObj) {
  const eph = await generateX25519KeyPair();
  const shared = await deriveSharedSecret(eph.keyPair.privateKey, targetPubB64);
  const aesKey = await derivePreSessionKey(shared);
  
  const envelopeJson = JSON.stringify(envelopeObj);
  const ciphertextB64 = await encryptBytesAAD(aesKey, new TextEncoder().encode(envelopeJson), 'yori/onion/v1');

  return {
    ephemeral: eph.pubB64,
    ciphertext: ciphertextB64
  };
}

// Decrypt an onion layer using this browser's relay private key.
export async function peelLayer(relayPrivKey, layerPacket) {
  const shared = await deriveSharedSecret(relayPrivKey, layerPacket.ephemeral);
  const aesKey = await derivePreSessionKey(shared);
  
  const decryptedBytes = await decryptBytesAAD(aesKey, layerPacket.ciphertext, 'yori/onion/v1');
  const envelope = JSON.parse(new TextDecoder().decode(decryptedBytes));
  
  envelope.ttl = (envelope.ttl || 1) - 1;
  if (envelope.ttl <= 0) {
    throw new Error('TTL expired on relay hop');
  }
  return envelope;
}

// Build multi-hop onion packet
// route: [relay1, relay2] (peer objects with username, relay_pub)
// recipient: username of target
// innerPayloadB64: already encrypted with session key for recipient
export async function buildOnionPacket(route, recipient, innerPayloadB64, circuitID = randomHex(8)) {
  
  // Innermost envelope (carried through relay2 to recipient)
  let currentEnvelope = {
    next: recipient,
    payload: innerPayloadB64,
    circuit_id: circuitID,
    ttl: 2
  };
  
  // Wrap in relay 2 layer
  const relay2Packet = await encryptLayer(route[1].relay_pub, currentEnvelope);
  
  // Wrap in relay 1 layer
  const relay1Envelope = {
    next: route[1].username,
    payload: JSON.stringify(relay2Packet),
    circuit_id: circuitID,
    ttl: 3
  };
  const relay1Packet = await encryptLayer(route[0].relay_pub, relay1Envelope);
  
  return {
    circuitID,
    targetRelay: route[0].username,
    onionPayload: JSON.stringify(relay1Packet)
  };
}
