// Packet construction and validation
import { bytesToB64 } from './crypto/identity.js';

export const PROTOCOL_VERSION = 1;
export const MAX_PACKET_BYTES = 64 * 1024;
export const MAX_PAYLOAD_BYTES = 48 * 1024;

export function randomID() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_');
}

export function createPacket(type, fields = {}) {
  return {
    version: PROTOCOL_VERSION,
    id: fields.id || randomID(),
    type,
    circuit_id: fields.circuitID || fields.circuit_id || undefined,
    ttl: fields.ttl || 5,
    to: fields.to || undefined,
    payload: fields.payload || undefined,
    public_key: fields.publicKey || fields.public_key || undefined,
    original_type: fields.originalType || fields.original_type || undefined
  };
}
