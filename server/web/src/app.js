// Main application controller
import { initIdentityKey, getFingerprintHex, bytesToHex, b64ToBytes } from './crypto/identity.js';
import { generateX25519KeyPair, deriveSharedSecret } from './crypto/keyagreement.js';
import { derivePreSessionKey } from './crypto/kdf.js';
import { decryptBytesAAD } from './crypto/encryption.js';
import { peelLayer } from './crypto/onion.js';
import { createPacket } from './protocol.js';
import { WebSocketManager } from './websocket.js';
import { CircuitManager } from './routing.js';
import { CoverTrafficManager } from './cover.js';
import { SessionManager } from './session.js';

// The browser always connects back to the host that served this application.
// This yields wss:// on Render and ws:// for local HTTP development without a
// configured hostname or address.
const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const SERVER_URL = `${protocol}//${window.location.host}/ws`;

class YoriApp {
  constructor() {
    this.username = null;
    this.identity = null;
    this.preSession = null;
    this.peers = [];
    this.selectedPeer = null;

    this.ws = null;
    this.circuitManager = null;
    this.coverManager = null;
    this.sessionManager = null;

    this.messages = new Map(); // username -> Array<{ sender, body, time, counter }>

    this.initDOM();
  }

  initDOM() {
    this.dom = {
      loginModal: document.getElementById('login-modal'),
      loginForm: document.getElementById('login-form'),
      usernameInput: document.getElementById('username-input'),
      selfUsername: document.getElementById('self-username'),
      selfFingerprint: document.getElementById('self-fingerprint'),
      connStatus: document.getElementById('conn-status'),
      peerList: document.getElementById('peer-list'),
      chatHeaderName: document.getElementById('chat-header-name'),
      circuitDisplay: document.getElementById('circuit-display'),
      circuitPath: document.getElementById('circuit-path'),
      circuitId: document.getElementById('circuit-id'),
      messagesPane: document.getElementById('messages-pane'),
      messageForm: document.getElementById('message-form'),
      messageInput: document.getElementById('message-input'),
      securityDrawer: document.getElementById('security-drawer'),
      drawerToggle: document.getElementById('drawer-toggle'),
      drawerContent: document.getElementById('drawer-content')
    };

    this.dom.loginForm.onsubmit = (e) => {
      e.preventDefault();
      const val = this.dom.usernameInput.value.trim();
      if (val.length >= 3) {
        this.login(val);
      }
    };

    this.dom.messageForm.onsubmit = (e) => {
      e.preventDefault();
      this.handleSendMessage();
    };

    this.dom.drawerToggle.onclick = () => {
      this.dom.securityDrawer.classList.toggle('collapsed');
    };
  }

  log(msg, type = 'info') {
    console.log(msg);
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    const time = new Date().toLocaleTimeString();
    entry.textContent = `[${time}] ${msg}`;
    this.dom.drawerContent.prepend(entry);
  }

  async login(username) {
    this.username = username;
    this.dom.loginModal.style.display = 'none';
    this.dom.selfUsername.textContent = username;

    // 1. Ed25519 Identity Key (IndexedDB)
    this.identity = await initIdentityKey(username, (m) => this.log(m, 'info'));
    const shortFp = this.identity.fingerprint.slice(0, 8) + '...' + this.identity.fingerprint.slice(-8);
    this.dom.selfFingerprint.textContent = `🔑 ${shortFp}`;

    // 2. Pre-Session Key (X25519)
    this.preSession = await generateX25519KeyPair();

    // 3. Circuit Manager
    this.circuitManager = new CircuitManager(
      () => this.peers,
      this.username,
      (recipient, circuitID, route) => {
        this.log(`[info] circuit rotated for ${recipient} (ID: ${circuitID})`, 'info');
        if (this.selectedPeer === recipient) {
          this.updateCircuitUI(recipient);
        }
      }
    );

    // 4. WebSocket Manager
    this.ws = new WebSocketManager(
      SERVER_URL,
      (pkt) => this.handlePacket(pkt),
      (status, text) => this.handleConnStatus(status, text),
      (m) => this.log(m, 'error')
    );

    // 5. Session Manager
    this.sessionManager = new SessionManager(
      this.username,
      this.identity,
      this.preSession,
      (pkt) => this.ws.send(pkt),
      this.circuitManager,
      (msg) => {
        let type = 'info';
        if (msg.includes('[warn]')) type = 'warn';
        if (msg.includes('[tamper]') || msg.includes('[error]')) type = 'tamper';
        this.log(msg, type);
        this.renderPeerList();
      }
    );

    // 6. Cover Traffic Manager
    this.coverManager = new CoverTrafficManager(
      () => this.peers,
      this.username,
      (pkt) => this.ws.send(pkt),
      (m) => this.log(m, 'warn')
    );

    // Connect
    this.ws.connect();
  }

  handleConnStatus(status, text) {
    let icon = '🔴';
    if (status === 'connected') icon = '🟢';
    else if (status === 'reconnecting') icon = '🟡';

    this.dom.connStatus.textContent = `${icon} ${text}`;

    if (status === 'connected') {
      // Register with server
      this.ws.send({
        type: 'register',
        username: this.username,
        presession_pub: this.preSession.pubB64,
        identity: this.identity.pubB64
      });

      // Start cover traffic immediately
      this.coverManager.start();
    } else {
      this.coverManager.stop();
      this.circuitManager.stopAll();
    }
  }

  handlePacket(pkt) {
    switch (pkt.type) {
      case 'users':
        this.peers = (pkt.users || []).filter(p => p.username !== this.username);
        this.renderPeerList();
        if (this.selectedPeer) {
          this.updateCircuitUI(this.selectedPeer);
        }
        break;

      case 'deliver':
      case 'message':
      case 'onion':
        this.handleInboundDelivery(pkt);
        break;

      case 'waiting':
        this.log(`[info] server waiting for recipient ${pkt.to}`, 'info');
        break;

      case 'error':
        this.log(`[server] ${pkt.payload}`, 'error');
        break;
    }
  }

  async handleInboundDelivery(pkt) {
    // Check if this is an onion packet for relaying. A malformed onion packet
    // is an authenticated-decryption failure, not a chat packet.
    if (pkt.payload && pkt.payload.startsWith('{') && pkt.payload.includes('ephemeral')) {
      try {
        const layer = JSON.parse(pkt.payload);
        if (layer.ephemeral && layer.ciphertext) {
          const envelope = await peelLayer(this.preSession.keyPair.privateKey, layer);
          if (envelope.next === this.username) {
            // Reached final recipient!
            await this.processDecryptedPayload(envelope.payload, envelope.circuit_id);
            return;
          } else {
            // Forward along route
            this.log(`[relay] forwarding onion layer for circuit ${envelope.circuit_id} to ${envelope.next}`, 'info');
            const fwdPkt = createPacket('deliver', {
              to: envelope.next,
              payload: envelope.payload,
              circuit_id: envelope.circuit_id,
              ttl: envelope.ttl
            });
            this.ws.send(fwdPkt);
            return;
          }
        }
      } catch (e) {
        this.log('[tamper] onion layer authentication failed or TTL expired', 'tamper');
        return;
      }
    }

    // Direct pre-session sealed sender payload (session offer/reply/cover)
    if (pkt.public_key && pkt.payload) {
      try {
        // A reply/reject is encrypted to a pending initiator ephemeral key.
        const pendingResponse = await this.sessionManager.decryptPendingResponse(pkt.public_key, pkt.payload);
        if (pendingResponse) {
          if (pendingResponse.type === 'session_reply') await this.sessionManager.handleSessionReply(pendingResponse);
          else this.sessionManager.handleSessionReject(pendingResponse);
          this.renderPeerList();
          return;
        }

        const shared = await deriveSharedSecret(this.preSession.keyPair.privateKey, pkt.public_key);
        const aesKey = await derivePreSessionKey(shared);
        const dec = await decryptBytesAAD(aesKey, pkt.payload, 'yori-presession-v1');
        const inner = JSON.parse(new TextDecoder().decode(dec));

        if (inner.is_cover) {
          // Cover traffic silently discarded without reply or UI change
          return;
        }

        if (inner.type === 'session_offer') {
          await this.sessionManager.handleSessionOffer(inner);
          this.renderPeerList();
          return;
        } else if (inner.type === 'session_reply') {
          await this.sessionManager.handleSessionReply(inner);
          this.renderPeerList();
          return;
        } else if (inner.type === 'session_reject') {
          this.sessionManager.handleSessionReject(inner);
          this.renderPeerList();
          return;
        }
      } catch (e) {
        // An unrelated packet cannot have a public key in this protocol. Do
        // not attempt session-message decryption with it.
        this.log('[tamper] pre-session packet authentication failed', 'tamper');
        return;
      }
    }

    // Direct encrypted chat message
    if (pkt.payload) {
      for (const [peer, session] of this.sessionManager.sessions.entries()) {
        try {
          const msg = await this.sessionManager.decryptMessage(peer, pkt.payload);
          if (msg) {
            this.addMessage(peer, msg.body, 'peer', msg.counter);
          }
          return;
        } catch (e) {
          // Continue to next session or surface tamper
        }
      }
    }
  }

  async processDecryptedPayload(payloadB64, circuitID) {
    for (const [peer, session] of this.sessionManager.sessions.entries()) {
      try {
        const msg = await this.sessionManager.decryptMessage(peer, payloadB64);
        if (msg) {
          this.addMessage(peer, msg.body, 'peer', msg.counter, circuitID);
        }
        return;
      } catch (e) {}
    }
  }

  addMessage(peer, body, senderType, counter, circuitID = null) {
    if (!this.messages.has(peer)) {
      this.messages.set(peer, []);
    }
    const list = this.messages.get(peer);
    list.push({
      sender: senderType === 'self' ? this.username : peer,
      body,
      senderType,
      counter,
      circuitID,
      time: new Date().toLocaleTimeString()
    });

    if (this.selectedPeer === peer) {
      this.renderMessages();
    }
  }

  renderPeerList() {
    this.dom.peerList.innerHTML = '';
    for (const p of this.peers) {
      const li = document.createElement('li');
      li.className = `peer-item ${this.selectedPeer === p.username ? 'selected' : ''}`;

      const fpEntry = this.sessionManager.fingerprints.get(p.username);
      let statusIcon = '🔵 unverified';
      let statusClass = 'unverified';
      if (this.sessionManager.keyChanged.has(p.username)) {
        statusIcon = '🔴 key changed';
        statusClass = 'key-changed';
      } else if (fpEntry) {
        if (fpEntry.verified) {
          statusIcon = '🟢 verified';
          statusClass = 'verified';
        }
      }

      const hasSess = this.sessionManager.hasSession(p.username);

      li.innerHTML = `
        <div class="peer-header-row">
          <span class="peer-name">${p.username}</span>
          <span class="peer-tag ${statusClass}">${statusIcon}</span>
        </div>
        ${fpEntry ? `<div class="peer-details">FP: ${fpEntry.fingerprint.slice(0, 16)}...</div>` : ''}
        <div class="peer-actions">
          ${!hasSess ? `<button class="primary btn-session">Session</button>` : `<button class="btn-chat">Chat</button>`}
          ${fpEntry && !fpEntry.verified ? `<button class="btn-verify">Verify</button>` : ''}
          <button class="danger btn-trust">Trust Key</button>
        </div>
      `;

      li.querySelector('.btn-session')?.addEventListener('click', (e) => {
        e.stopPropagation();
        this.sessionManager.startSession(p);
      });

      li.querySelector('.btn-chat')?.addEventListener('click', (e) => {
        e.stopPropagation();
        this.selectPeer(p.username);
      });

      li.querySelector('.btn-verify')?.addEventListener('click', (e) => {
        e.stopPropagation();
        this.sessionManager.verifyFingerprint(p.username);
        this.renderPeerList();
      });

      li.querySelector('.btn-trust')?.addEventListener('click', (e) => {
        e.stopPropagation();
        this.sessionManager.trustKey(p.username);
        this.renderPeerList();
      });

      li.onclick = () => this.selectPeer(p.username);
      this.dom.peerList.appendChild(li);
    }
  }

  selectPeer(peerUsername) {
    this.selectedPeer = peerUsername;
    this.dom.chatHeaderName.textContent = `Chat with ${peerUsername}`;
    this.updateCircuitUI(peerUsername);
    this.renderPeerList();
    this.renderMessages();
  }

  updateCircuitUI(peerUsername) {
    const circuit = this.circuitManager.getCircuit(peerUsername);
    if (circuit && circuit.route && circuit.route.length >= 2) {
      this.dom.circuitDisplay.style.display = 'flex';
      this.dom.circuitPath.textContent = `${this.username} → ${circuit.route[0].username} → ${circuit.route[1].username} → ${peerUsername}`;
      this.dom.circuitId.textContent = `ID: ${circuit.circuitID} | TTL: 3`;
    } else {
      this.dom.circuitDisplay.style.display = 'flex';
      this.dom.circuitPath.textContent = `Direct fallback via server`;
      this.dom.circuitId.textContent = `peers < 2`;
    }
  }

  renderMessages() {
    this.dom.messagesPane.innerHTML = '';
    const list = this.messages.get(this.selectedPeer) || [];
    for (const m of list) {
      const row = document.createElement('div');
      row.className = `message-row ${m.senderType}`;
      row.innerHTML = `
        <div class="message-meta">${m.sender} • ${m.time} ${m.counter ? `[#${m.counter}]` : ''}</div>
        <div class="message-bubble">${this.escapeHTML(m.body)}</div>
      `;
      this.dom.messagesPane.appendChild(row);
    }
    this.dom.messagesPane.scrollTop = this.dom.messagesPane.scrollHeight;
  }

  async handleSendMessage() {
    const text = this.dom.messageInput.value.trim();
    if (!text) return;
    this.dom.messageInput.value = '';

    // Handle slash commands
    if (text.startsWith('/trustkey ')) {
      const target = text.slice(10).trim();
      this.sessionManager.trustKey(target);
      this.renderPeerList();
      return;
    }
    if (text === '/users') {
      this.ws.send(createPacket('users'));
      return;
    }

    if (!this.selectedPeer) {
      this.log('[warn] select a peer to send a message', 'warn');
      return;
    }

    if (!this.sessionManager.hasSession(this.selectedPeer)) {
      this.log(`[warn] no active session with ${this.selectedPeer} — starting session...`, 'warn');
      const p = this.peers.find(x => x.username === this.selectedPeer);
      if (p) this.sessionManager.startSession(p);
      return;
    }

    try {
      const res = await this.sessionManager.sendMessage(this.selectedPeer, text);
      this.addMessage(this.selectedPeer, text, 'self', res.counter, res.circuit?.circuitID);
    } catch (err) {
      this.log(`[error] failed to send message: ${err.message}`, 'error');
    }
  }

  escapeHTML(str) {
    return str.replace(/[&<>'"]/g, 
      tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
    );
  }
}

window.addEventListener('DOMContentLoaded', () => {
  const app = new YoriApp();
  window.addEventListener('beforeunload', () => {
    app.coverManager?.stop();
    app.circuitManager?.stopAll();
    app.ws?.disconnect();
  });
});
