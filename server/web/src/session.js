// Session management, key agreement, anti-replay, and messaging
import { generateX25519KeyPair, deriveSharedSecret } from './crypto/keyagreement.js';
import { deriveDirectionalKeys, derivePreSessionKey } from './crypto/kdf.js';
import { encryptBytesAAD, decryptBytesAAD } from './crypto/encryption.js';
import { signSessionMetadata, verifySessionMetadata, getFingerprintHex } from './crypto/identity.js';
import { buildOnionPacket } from './crypto/onion.js';
import { createPacket, randomID } from './protocol.js';

export class SessionManager {
  constructor(selfUsername, identityKeyInfo, preSessionKeyInfo, sendPacket, circuitManager, logger = console.log) {
    this.selfUsername = selfUsername;
    this.identityKeyInfo = identityKeyInfo;       // { keyPair, pubB64, fingerprint }
    this.preSessionKeyInfo = preSessionKeyInfo;   // { keyPair, pubB64 }
    this.sendPacket = sendPacket;
    this.circuitManager = circuitManager;
    this.logger = logger;

    // Per-peer active session state
    // peerUsername -> { sessionID, sendKey, recvKey, sendCounter, highestRecvCounter, ephemeralKeyPair, state }
    this.sessions = new Map();

    // Fingerprint store for TOFU (peerUsername -> { fingerprint, verified: bool })
    this.fingerprints = new Map();
    this.keyChanged = new Set();
    this.loadCachedFingerprints();
  }

  loadCachedFingerprints() {
    try {
      const raw = localStorage.getItem('yori_fingerprints');
      if (raw) {
        const parsed = JSON.parse(raw);
        for (const [k, v] of Object.entries(parsed)) {
          this.fingerprints.set(k, v);
        }
      }
    } catch (e) {}
  }

  saveCachedFingerprints() {
    try {
      const obj = {};
      for (const [k, v] of this.fingerprints.entries()) {
        obj[k] = v;
      }
      localStorage.setItem('yori_fingerprints', JSON.stringify(obj));
    } catch (e) {}
  }

  trustKey(peerUsername) {
    this.fingerprints.delete(peerUsername);
    this.keyChanged.delete(peerUsername);
    this.saveCachedFingerprints();
    this.logger(`[identity] cleared cached key for ${peerUsername} — next session offer will be accepted`);
  }

  verifyFingerprint(peerUsername) {
    const entry = this.fingerprints.get(peerUsername);
    if (entry) {
      entry.verified = true;
      this.saveCachedFingerprints();
      this.logger(`[identity] verified fingerprint for ${peerUsername}`);
    }
  }

  hasSession(peerUsername) {
    const s = this.sessions.get(peerUsername);
    return s && s.state === 'ESTABLISHED';
  }

  // Alice initiates session offer to Bob
  async startSession(targetPeer) {
    const peerUsername = targetPeer.username;
    const targetPub = targetPeer.presession_pub || targetPeer.pre_session_key;
    if (!targetPub) {
      this.logger(`[error] cannot start session with ${peerUsername}: missing pre-session public key`);
      return;
    }

    const ephemeral = await generateX25519KeyPair();
    const sessionID = randomID();
    const signature = await signSessionMetadata(
      this.identityKeyInfo.keyPair.privateKey,
      this.selfUsername,
      sessionID,
      ephemeral.pubB64
    );

    // Save pending session state for Alice
    this.sessions.set(peerUsername, {
      sessionID,
      ephemeralKeyPair: ephemeral.keyPair,
      ephemeralPubB64: ephemeral.pubB64,
      sendCounter: 0,
      highestRecvCounter: 0,
      state: 'PENDING_OFFER'
    });

    const offerPayload = {
      type: 'session_offer',
      sender: this.selfUsername,
      session_id: sessionID,
      ephemeral_pub: ephemeral.pubB64,
      identity_pub: this.identityKeyInfo.pubB64,
      signature
    };

    // Encrypt offer using recipient's presession_pub
    const ephOuter = await generateX25519KeyPair();
    const shared = await deriveSharedSecret(ephOuter.keyPair.privateKey, targetPub);
    const aesKey = await derivePreSessionKey(shared);
    const ciphertextB64 = await encryptBytesAAD(
      aesKey,
      new TextEncoder().encode(JSON.stringify(offerPayload)),
      'yori-presession-v1'
    );

    // Send deliver packet to server
    const deliverPacket = createPacket('deliver', {
      to: peerUsername,
      payload: ciphertextB64,
      publicKey: ephOuter.pubB64
    });

    this.sendPacket(deliverPacket);
    this.logger(`[session] sent session offer to ${peerUsername}`);
  }

  // Bob receives and processes a session offer
  async handleSessionOffer(offer) {
    const sender = offer.sender;
    const fingerprint = await getFingerprintHex(offer.identity_pub);

    // TOFU check
    const cached = this.fingerprints.get(sender);
    if (cached && cached.fingerprint !== fingerprint) {
      this.keyChanged.add(sender);
      this.logger(`[warn] session offer from ${sender} blocked: identity key changed`);
      // Send rejection
      const rejectPayload = {
        type: 'session_reject',
        sender: this.selfUsername,
        reason: 'identity_key_changed'
      };
      await this.sendPreSessionDeliver(sender, offer.ephemeral_pub, rejectPayload);
      return;
    }

    // Verify signature
    const valid = await verifySessionMetadata(
      offer.identity_pub,
      sender,
      offer.session_id,
      offer.ephemeral_pub,
      offer.signature
    );
    if (!valid) {
      this.logger(`[warn] session offer from ${sender} blocked: invalid signature`);
      return;
    }

    // Record fingerprint if new
    if (!cached) {
      this.fingerprints.set(sender, { fingerprint, verified: false });
      this.saveCachedFingerprints();
    }

    // Bob generates own ephemeral X25519 key pair
    const ephemeral = await generateX25519KeyPair();
    const sharedSecret = await deriveSharedSecret(ephemeral.keyPair.privateKey, offer.ephemeral_pub);

    // Bob is responder: send = yori-recv-v1, recv = yori-send-v1
    const keys = await deriveDirectionalKeys(sharedSecret);
    const bobSendKey = keys.recvKey;
    const bobRecvKey = keys.sendKey;

    this.sessions.set(sender, {
      sessionID: offer.session_id,
      sendKey: bobSendKey,
      recvKey: bobRecvKey,
      sendCounter: 0,
      highestRecvCounter: 0,
      state: 'ESTABLISHED'
    });

    // Bob signs his reply
    const signature = await signSessionMetadata(
      this.identityKeyInfo.keyPair.privateKey,
      this.selfUsername,
      offer.session_id,
      ephemeral.pubB64
    );

    const replyPayload = {
      type: 'session_reply',
      sender: this.selfUsername,
      session_id: offer.session_id,
      ephemeral_pub: ephemeral.pubB64,
      identity_pub: this.identityKeyInfo.pubB64,
      signature
    };

    await this.sendPreSessionDeliver(sender, offer.ephemeral_pub, replyPayload);
    this.logger(`[session] session established with ${sender}`);
  }

  // Alice receives Bob's session reply
  async handleSessionReply(reply) {
    const sender = reply.sender;
    const pending = this.sessions.get(sender);
    if (!pending || pending.sessionID !== reply.session_id) {
      return;
    }

    const valid = await verifySessionMetadata(
      reply.identity_pub,
      sender,
      reply.session_id,
      reply.ephemeral_pub,
      reply.signature
    );
    if (!valid) {
      this.logger(`[warn] session reply from ${sender} signature verification failed`);
      return;
    }

    // Alice performs X25519 with Bob's ephemeral pub
    const sharedSecret = await deriveSharedSecret(pending.ephemeralKeyPair.privateKey, reply.ephemeral_pub);

    // Alice is initiator: send = yori-send-v1, recv = yori-recv-v1
    const keys = await deriveDirectionalKeys(sharedSecret);
    pending.sendKey = keys.sendKey;
    pending.recvKey = keys.recvKey;
    pending.state = 'ESTABLISHED';

    const fingerprint = await getFingerprintHex(reply.identity_pub);
    const cached = this.fingerprints.get(sender);
    if (cached && cached.fingerprint !== fingerprint) {
      this.sessions.delete(sender);
      this.keyChanged.add(sender);
      this.logger(`[warn] session reply from ${sender} blocked: identity key changed`);
      return;
    }
    if (!cached) {
      this.fingerprints.set(sender, { fingerprint, verified: false });
      this.saveCachedFingerprints();
    }

    this.logger(`[session] session established with ${sender}`);
  }

  handleSessionReject(reject) {
    const sender = reject.sender;
    if (reject.reason === 'identity_key_changed') {
      this.logger(`[warn] session rejected by ${sender}: identity key changed — ask them to run /trustkey ${this.selfUsername}`);
    } else {
      this.logger(`[warn] session rejected by ${sender}`);
    }
    this.sessions.delete(sender);
  }

  // Replies and rejections are sealed to the initiator's pending ephemeral
  // key, not to its long-lived pre-session key. This also lets the transport
  // remain type-blind: the outer packet is always just "deliver".
  async decryptPendingResponse(senderEphemeralPubB64, ciphertextB64) {
    for (const pending of this.sessions.values()) {
      if (pending.state !== 'PENDING_OFFER' || !pending.ephemeralKeyPair) continue;
      try {
        const shared = await deriveSharedSecret(pending.ephemeralKeyPair.privateKey, senderEphemeralPubB64);
        const key = await derivePreSessionKey(shared);
        const plaintext = await decryptBytesAAD(key, ciphertextB64, 'yori-presession-v1');
        const payload = JSON.parse(new TextDecoder().decode(plaintext));
        if (payload.type === 'session_reply' || payload.type === 'session_reject') return payload;
      } catch (_) {
        // The packet may instead be an offer/cover sealed to our pre-session key.
      }
    }
    return null;
  }

  // Send an encrypted chat message to Bob
  async sendMessage(peerUsername, bodyText) {
    const session = this.sessions.get(peerUsername);
    if (!session || session.state !== 'ESTABLISHED') {
      throw new Error(`No established session with ${peerUsername}`);
    }

    session.sendCounter += 1;
    const counter = session.sendCounter;

    const messageEnvelope = {
      type: 'message',
      session_id: session.sessionID,
      counter,
      body: bodyText,
      is_cover: false
    };

    const aad = `yori/message/v1|${session.sessionID}`;
    const ciphertextB64 = await encryptBytesAAD(
      session.sendKey,
      new TextEncoder().encode(JSON.stringify(messageEnvelope)),
      aad
    );

    // Onion route delivery
    const circuit = this.circuitManager.getCircuit(peerUsername);
    if (!circuit || !circuit.route || circuit.route.length < 2) {
      // Never silently degrade a chat message to direct delivery.
      session.sendCounter -= 1;
      throw new Error('not enough peers for onion route');
    }

    const { circuitID, targetRelay, onionPayload } = await buildOnionPacket(
      circuit.route,
      peerUsername,
      ciphertextB64,
      circuit.circuitID
    );

    const deliverPkt = createPacket('deliver', {
      to: targetRelay,
      payload: onionPayload,
      circuit_id: circuitID
    });

    this.sendPacket(deliverPkt);
    return {
      counter,
      circuit: {
        circuitID,
        path: [this.selfUsername, circuit.route[0].username, circuit.route[1].username, peerUsername]
      }
    };
  }

  // Decrypt incoming message
  async decryptMessage(sender, ciphertextB64) {
    const session = this.sessions.get(sender);
    if (!session || !session.recvKey) {
      throw new Error(`No session key to decrypt message from ${sender}`);
    }

    const aad = `yori/message/v1|${session.sessionID}`;
    let decryptedBytes;
    try {
      decryptedBytes = await decryptBytesAAD(session.recvKey, ciphertextB64, aad);
    } catch (err) {
      this.logger(`[tamper] AES-GCM authentication failure from ${sender}: message was modified or corrupted!`);
      throw err;
    }

    const envelope = JSON.parse(new TextDecoder().decode(decryptedBytes));
    if (envelope.is_cover) {
      return null; // Cover traffic silently discarded
    }

    // Replay protection: counter must be strictly greater than highest seen
    if (envelope.counter <= session.highestRecvCounter) {
      this.logger(`[warn] replay rejected from ${sender}: counter ${envelope.counter} already seen`);
      return null;
    }

    session.highestRecvCounter = envelope.counter;
    return envelope;
  }

  async sendPreSessionDeliver(toUsername, recipientPubB64, payloadObj) {
    const eph = await generateX25519KeyPair();
    const shared = await deriveSharedSecret(eph.keyPair.privateKey, recipientPubB64);
    const key = await derivePreSessionKey(shared);
    const ciphertextB64 = await encryptBytesAAD(
      key,
      new TextEncoder().encode(JSON.stringify(payloadObj)),
      'yori-presession-v1'
    );
    const packet = createPacket('deliver', {
      to: toUsername,
      payload: ciphertextB64,
      publicKey: eph.pubB64
    });
    this.sendPacket(packet);
  }
}
