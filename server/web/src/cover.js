// Global cover traffic generator
import { generateX25519KeyPair, deriveSharedSecret } from './crypto/keyagreement.js';
import { derivePreSessionKey } from './crypto/kdf.js';
import { encryptBytesAAD } from './crypto/encryption.js';
import { bytesToB64 } from './crypto/identity.js';
import { createPacket } from './protocol.js';

export const COVER_INTERVAL_MS = 2000;
export const ENABLE_COVER_TRAFFIC = true;

export class CoverTrafficManager {
  constructor(getPeers, selfUsername, sendPacket, logger = () => {}) {
    this.getPeers = getPeers;
    this.selfUsername = selfUsername;
    this.sendPacket = sendPacket;
    this.logger = logger;
    this.timer = null;
  }

  start() {
    if (this.timer || !ENABLE_COVER_TRAFFIC) return;
    this.logger('[info] cover traffic active');
    this.timer = setInterval(() => this.tick(), COVER_INTERVAL_MS);
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  async tick() {
    const peers = this.getPeers().filter(p => 
      p.username !== this.selfUsername && (p.presession_pub || p.pre_session_key)
    );
    if (peers.length === 0) return;

    // Pick one peer at random using crypto.getRandomValues
    const randBuf = new Uint32Array(1);
    crypto.getRandomValues(randBuf);
    const targetPeer = peers[randBuf[0] % peers.length];
    const targetPub = targetPeer.presession_pub || targetPeer.pre_session_key;

    try {
      const eph = await generateX25519KeyPair();
      const shared = await deriveSharedSecret(eph.keyPair.privateKey, targetPub);
      const aesKey = await derivePreSessionKey(shared);

      const dummyBytes = crypto.getRandomValues(new Uint8Array(32));
      const dummyObj = {
        type: 'message',
        is_cover: true,
        body: bytesToB64(dummyBytes)
      };

      const dummyJson = JSON.stringify(dummyObj);
      const ciphertextB64 = await encryptBytesAAD(aesKey, new TextEncoder().encode(dummyJson), 'yori-presession-v1');

      const packet = createPacket('deliver', {
        to: targetPeer.username,
        payload: ciphertextB64,
        publicKey: eph.pubB64
      });

      this.sendPacket(packet);
    } catch (err) {
      // Cover traffic fails silently
    }
  }
}
