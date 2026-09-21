// Yori browser client UI. Cryptography, envelopes, circuits and transport remain
// in their dedicated modules; this controller only presents their real state.
import { initIdentityKey } from './crypto/identity.js';
import { generateX25519KeyPair, deriveSharedSecret } from './crypto/keyagreement.js';
import { derivePreSessionKey } from './crypto/kdf.js';
import { decryptBytesAAD } from './crypto/encryption.js';
import { peelLayer } from './crypto/onion.js';
import { createPacket } from './protocol.js';
import { WebSocketManager } from './websocket.js';
import { CircuitManager } from './routing.js';
import { CoverTrafficManager } from './cover.js';
import { SessionManager } from './session.js';

// Deriving this from the page is intentional: HTTPS pages use WSS automatically.
const socketProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const SERVER_URL = `${socketProtocol}//${window.location.host}/ws`;

const initials = (name = '') => name.split(/[_-]/).map(x => x[0]).join('').slice(0, 2).toUpperCase() || 'YO';
const formatFingerprint = (value = '') => value.match(/.{1,4}/g)?.slice(0, 8).join(' ') || 'PENDING';

class YoriApp {
  constructor() {
    this.username = null;
    this.identity = null;
    this.preSession = null;
    this.relayKey = null;
    this.peers = [];
    this.selectedPeer = null;
    this.messages = new Map();
    this.connectionState = 'disconnected';
    this.handshakePeer = null;
    this.handshakeMode = 'setup';
    this.keyMode = null;
    this.ws = null;
    this.circuitManager = null;
    this.coverManager = null;
    this.sessionManager = null;
    this.initDOM();
  }

  initDOM() {
    const $ = id => document.getElementById(id);
    this.dom = {
      landing: $('landing'), appShell: $('app-shell'), loginForm: $('login-form'), usernameInput: $('username-input'),
      landingConnection: $('landing-connection'), connStatus: $('conn-status'), loginError: $('login-error'), leave: $('leave-button'),
      selfUsername: $('self-username'), selfAvatar: $('self-avatar'), peerCount: $('peer-count'), peerList: $('peer-list'), noPeers: $('no-peers'), peerFilter: $('peer-filter'), peerSidebar: $('peer-sidebar'),
      mobileSidebarToggle: $('mobile-sidebar-toggle'), sidebarClose: $('sidebar-close'), shareSessionKey: $('share-session-key'),
      emptyChat: $('empty-chat'), chatView: $('chat-view'), chatAvatar: $('chat-avatar'), chatHeaderName: $('chat-header-name'), chatSessionState: $('chat-session-state'), routeLabel: $('route-label'),
      messagesPane: $('messages-pane'), messageForm: $('message-form'), messageInput: $('message-input'), securityButton: $('security-button'), clearChat: $('clear-chat-button'), endSession: $('end-session-button'),
      securityDrawer: $('security-drawer'), drawerToggle: $('drawer-toggle'), drawerContent: $('drawer-content'),
      modal: $('handshake-modal'), handshakeLabel: $('handshake-label'), handshakeTitle: $('handshake-title'), handshakeDescription: $('handshake-description'), handshakeStatus: $('handshake-status'), keySetup: $('key-setup'), keyOptions: $('key-options'), ownKeyPanel: $('own-key-panel'), ownKeyOutput: $('own-key-output'), peerKeyPanel: $('peer-key-panel'), peerKeyInput: $('peer-key-input'), generateKey: $('generate-key-button'), inputKey: $('input-key-button'), copyKey: $('copy-key-button'), fingerprintPanel: $('fingerprint-panel'), peerFingerprint: $('peer-fingerprint'), handshakeAction: $('handshake-action'), handshakeCancel: $('handshake-cancel')
    };
    this.dom.loginForm.addEventListener('submit', e => { e.preventDefault(); const handle = this.dom.usernameInput.value.trim(); this.dom.loginError.hidden = true; if (handle.length >= 3) this.login(handle); });
    this.dom.messageForm.addEventListener('submit', e => { e.preventDefault(); this.handleSendMessage(); });
    this.dom.messageInput.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); this.handleSendMessage(); } });
    this.dom.messageInput.addEventListener('input', () => { this.dom.messageInput.style.height = 'auto'; this.dom.messageInput.style.height = `${Math.min(this.dom.messageInput.scrollHeight, 130)}px`; });
    this.dom.peerFilter.addEventListener('input', () => this.renderPeerList());
    this.dom.drawerToggle.addEventListener('click', () => this.dom.securityDrawer.classList.toggle('collapsed'));
    this.dom.shareSessionKey.addEventListener('click', () => this.shareSessionKey());
    this.dom.leave.addEventListener('click', () => this.leave());
    this.dom.mobileSidebarToggle.addEventListener('click', () => { this.dom.peerSidebar.classList.add('open'); document.body.classList.add('drawer-open'); });
    this.dom.sidebarClose.addEventListener('click', () => { this.dom.peerSidebar.classList.remove('open'); document.body.classList.remove('drawer-open'); });
    this.dom.securityButton.addEventListener('click', () => this.openSecurity());
    this.dom.clearChat.addEventListener('click', () => this.clearChat());
    this.dom.endSession.addEventListener('click', () => this.endSession());
    this.dom.handshakeCancel.addEventListener('click', () => this.closeModal());
    this.dom.modal.querySelector('[data-close-modal]').addEventListener('click', () => this.closeModal());
    this.dom.modal.addEventListener('click', e => { if (e.target === this.dom.modal) this.closeModal(); });
    this.dom.handshakeAction.addEventListener('click', () => this.handleModalAction());
    this.dom.generateKey.addEventListener('click', () => this.showKeyMode('generate'));
    this.dom.inputKey.addEventListener('click', () => this.showKeyMode('input'));
    this.dom.copyKey.addEventListener('click', () => this.copySessionKey());
  }

  log(message, type = 'info') {
    console.log(message);
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    this.dom.drawerContent.prepend(entry);
  }

  async login(username) {
    this.username = username;
    this.dom.landing.hidden = true;
    this.dom.appShell.hidden = false;
    this.dom.selfUsername.textContent = username;
    this.dom.selfAvatar.textContent = initials(username);
    this.setConnectionStatus('connecting', 'CONNECTING');
    try {
      this.identity = await initIdentityKey(username, m => this.log(m));
      this.preSession = await generateX25519KeyPair();
      // This is deliberately separate from the externally exchanged
      // pre-session key. The server advertises only its public half to peers.
      this.relayKey = await generateX25519KeyPair();
      this.circuitManager = new CircuitManager(() => this.peers, username, (recipient, id, route) => {
        this.log(`[routing] circuit rotated for ${recipient}`, 'info');
        if (recipient === this.selectedPeer) this.updateRouteUI();
      });
      this.ws = new WebSocketManager(SERVER_URL, packet => this.handlePacket(packet), (status, text) => this.handleConnStatus(status, text), m => this.log(m, 'error'));
      this.sessionManager = new SessionManager(username, this.identity, this.preSession, packet => this.ws.send(packet), this.circuitManager, msg => {
        const type = msg.includes('[error]') ? 'error' : msg.includes('[warn]') ? 'warn' : msg.includes('[tamper]') ? 'tamper' : 'info';
        this.log(msg, type);
        this.renderPeerList();
      });
      this.coverManager = new CoverTrafficManager(() => this.peers, peer => this.sessionManager?.getPeerPreSessionKey(peer) || '', username, packet => this.ws.send(packet), m => this.log(m, 'warn'));
      this.ws.connect();
    } catch (error) {
      this.log(`[error] identity setup failed: ${error.message}`, 'error');
      this.setConnectionStatus('disconnected', 'SETUP FAILED');
    }
  }

  setConnectionStatus(status, label) {
    this.connectionState = status;
    const cls = status === 'connected' ? 'is-connected' : status === 'reconnecting' || status === 'connecting' ? 'is-reconnecting' : 'is-disconnected';
    for (const el of [this.dom.connStatus, this.dom.landingConnection]) { if (!el) continue; el.className = `connection-status ${cls}`; el.innerHTML = '<i></i>'; const text = document.createElement('span'); text.textContent = el === this.dom.landingConnection ? `NETWORK ${label}` : label; el.append(text); }
  }

  handleConnStatus(status, text) {
    const label = status === 'connected' ? 'MESH CONNECTED' : status === 'reconnecting' ? (text.includes('Connecting') ? 'CONNECTING' : 'RECONNECTING') : 'DISCONNECTED';
    this.setConnectionStatus(status, label);
    if (status === 'connected') {
      this.ws.send({ type: 'register', username: this.username, relay_public_key: this.relayKey.pubB64 });
      this.coverManager.start();
    } else { this.coverManager?.stop(); this.circuitManager?.stopAll(); }
  }

  handlePacket(packet) {
    switch (packet.type) {
      case 'users':
        this.peers = (packet.users || []).filter(peer => peer.username !== this.username);
        this.renderPeerList(); this.updateRouteUI(); break;
      case 'deliver': case 'message': case 'onion': this.handleInboundDelivery(packet); break;
      case 'waiting': this.log(`[transport] recipient ${packet.to} is not currently available`, 'warn'); break;
      case 'error':
        this.log(`[server] ${packet.payload}`, 'error');
        if (/username already taken|invalid registration|invalid username/i.test(packet.payload || '')) {
          this.showRegistrationError(packet.payload);
        }
        break;
    }
  }

  async handleInboundDelivery(packet) {
    if (packet.payload?.startsWith('{') && packet.payload.includes('ephemeral')) {
      try {
        const layer = JSON.parse(packet.payload);
        if (layer.ephemeral && layer.ciphertext) {
          const envelope = await peelLayer(this.relayKey.keyPair.privateKey, layer);
          if (envelope.next === this.username) return this.processDecryptedPayload(envelope.payload, envelope.circuit_id);
          this.ws.send(createPacket('deliver', { to: envelope.next, payload: envelope.payload, circuit_id: envelope.circuit_id, ttl: envelope.ttl }));
          return;
        }
      } catch (_) { this.log('[tamper] onion layer authentication failed or TTL expired', 'tamper'); return; }
    }
    if (packet.public_key && packet.payload) {
      try {
        const pending = await this.sessionManager.decryptPendingResponse(packet.public_key, packet.payload);
        if (pending) {
          if (pending.type === 'session_reply') await this.sessionManager.handleSessionReply(pending); else this.sessionManager.handleSessionReject(pending);
          this.afterSessionUpdate(pending.sender); return;
        }
        const shared = await deriveSharedSecret(this.preSession.keyPair.privateKey, packet.public_key);
        const key = await derivePreSessionKey(shared);
        const inner = JSON.parse(new TextDecoder().decode(await decryptBytesAAD(key, packet.payload, 'yori-presession-v1')));
        if (inner.is_cover) return;
        if (inner.type === 'session_offer') { await this.sessionManager.handleSessionOffer(inner); this.afterSessionUpdate(inner.sender, true); }
        else if (inner.type === 'session_reply') { await this.sessionManager.handleSessionReply(inner); this.afterSessionUpdate(inner.sender); }
        else if (inner.type === 'session_reject') { this.sessionManager.handleSessionReject(inner); this.afterSessionUpdate(inner.sender); }
        return;
      } catch (_) { this.log('[tamper] pre-session packet authentication failed', 'tamper'); return; }
    }
    if (packet.payload) {
      for (const [peer] of this.sessionManager.sessions.entries()) {
        try { const message = await this.sessionManager.decryptMessage(peer, packet.payload); if (message) this.addMessage(peer, message.body, 'peer', message.counter); return; } catch (_) { /* Try the next active peer session. */ }
      }
    }
  }

  async processDecryptedPayload(payload, circuitID) {
    for (const [peer] of this.sessionManager.sessions.entries()) {
      try { const message = await this.sessionManager.decryptMessage(peer, payload); if (message) this.addMessage(peer, message.body, 'peer', message.counter, circuitID); return; } catch (_) {}
    }
  }

  afterSessionUpdate(peer, incoming = false) {
    this.renderPeerList();
    if (this.sessionManager.keyChanged.has(peer)) { this.openHandshake(peer, 'key-change'); return; }
    if (this.sessionManager.hasSession(peer)) {
      this.selectPeer(peer);
      this.openHandshake(peer, 'established');
    } else if (this.handshakePeer === peer) this.openHandshake(peer, 'failed');
    if (incoming) this.log(`[session] authenticated session accepted from ${peer}`);
  }

  renderPeerList() {
    const filter = this.dom.peerFilter.value.trim().toLowerCase();
    const peers = this.peers.filter(peer => peer.username.toLowerCase().includes(filter));
    this.dom.peerCount.textContent = `${this.peers.length} ${this.peers.length === 1 ? 'peer' : 'peers'}`;
    this.dom.peerList.replaceChildren(); this.dom.noPeers.hidden = this.peers.length !== 0;
    for (const peer of peers) {
      const fp = this.sessionManager?.fingerprints.get(peer.username);
      const changed = this.sessionManager?.keyChanged.has(peer.username);
      const established = this.sessionManager?.hasSession(peer.username);
      const card = document.createElement('button'); card.type = 'button'; card.className = `peer-card ${this.selectedPeer === peer.username ? 'selected' : ''}`;
      const avatar = document.createElement('span'); avatar.className = 'avatar'; avatar.textContent = initials(peer.username);
      const info = document.createElement('span'); info.className = 'peer-card-info'; const name = document.createElement('strong'); name.textContent = peer.username; const state = document.createElement('small');
      state.textContent = changed ? 'IDENTITY CHANGE DETECTED' : established ? 'ONLINE · SESSION ACTIVE' : fp?.verified ? 'ONLINE · VERIFIED' : 'ONLINE · READY'; state.className = established || fp?.verified ? 'ready' : changed ? '' : '';
      info.append(name, state); const arrow = document.createElement('span'); arrow.className = 'peer-chevron'; arrow.textContent = '›'; card.append(avatar, info, arrow);
      card.addEventListener('click', () => established ? this.selectPeer(peer.username) : this.openHandshake(peer.username, changed ? 'key-change' : 'setup'));
      this.dom.peerList.append(card);
    }
  }

  selectPeer(peer) {
    this.selectedPeer = peer; this.dom.peerSidebar.classList.remove('open'); document.body.classList.remove('drawer-open'); this.dom.emptyChat.hidden = true; this.dom.chatView.hidden = false;
    this.dom.chatHeaderName.textContent = peer; this.dom.chatAvatar.textContent = initials(peer); this.dom.messageInput.placeholder = `Message ${peer}…`;
    const verified = this.sessionManager.fingerprints.get(peer)?.verified;
    this.dom.chatSessionState.textContent = verified ? 'IDENTITY VERIFIED' : 'IDENTITY UNVERIFIED';
    this.renderPeerList(); this.renderMessages(); this.updateRouteUI();
  }

  updateRouteUI() {
    if (!this.selectedPeer || !this.circuitManager) return;
    const circuit = this.circuitManager.getCircuit(this.selectedPeer);
    this.dom.routeLabel.textContent = circuit?.route?.length >= 2 ? 'MULTI-HOP ROUTING ACTIVE' : 'ENCRYPTED SERVER RELAY';
  }

  renderMessages() {
    this.dom.messagesPane.replaceChildren();
    for (const message of this.messages.get(this.selectedPeer) || []) {
      const row = document.createElement('div'); row.className = `message-row ${message.senderType}`;
      const meta = document.createElement('div'); meta.className = 'message-meta'; meta.textContent = `${message.senderType === 'self' ? 'YOU' : message.sender.toUpperCase()} · ${message.time}${message.counter ? ` · #${message.counter}` : ''}`;
      const bubble = document.createElement('div'); bubble.className = 'message-bubble'; bubble.textContent = message.body; row.append(meta, bubble); this.dom.messagesPane.append(row);
    }
    this.dom.messagesPane.scrollTop = this.dom.messagesPane.scrollHeight;
  }

  addMessage(peer, body, senderType, counter, circuitID = null) {
    if (!this.messages.has(peer)) this.messages.set(peer, []);
    this.messages.get(peer).push({ sender: senderType === 'self' ? this.username : peer, body, senderType, counter, circuitID, time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) });
    if (this.selectedPeer === peer) this.renderMessages();
  }

  openHandshake(peer, mode = 'setup') {
    this.handshakePeer = peer; this.handshakeMode = mode; const hasKey = this.sessionManager.getPeerPreSessionKey(peer);
    const fp = this.sessionManager.fingerprints.get(peer); const changed = this.sessionManager.keyChanged.has(peer);
    this.dom.modal.hidden = false; document.body.classList.add('modal-open'); this.dom.handshakeLabel.textContent = `HANDSHAKE / ${peer.toUpperCase()}`; this.dom.keySetup.hidden = true; this.dom.fingerprintPanel.hidden = true; this.dom.handshakeStatus.replaceChildren();
    const statuses = (values) => values.forEach(([left, right, cls = '']) => { const row = document.createElement('div'); const a = document.createElement('span'); a.textContent = left; const b = document.createElement('span'); b.textContent = right; b.className = cls; row.append(a,b); this.dom.handshakeStatus.append(row); });
    if (mode === 'key-change' || changed) {
      this.dom.handshakeTitle.textContent = 'Identity change detected'; this.dom.handshakeDescription.textContent = `The identity associated with ${peer} has changed. Verify the new fingerprint before continuing.`; this.dom.fingerprintPanel.hidden = false; this.dom.peerFingerprint.textContent = formatFingerprint(fp?.fingerprint); statuses([['IDENTITY', 'CHANGED', 'pending'], ['SESSION', 'BLOCKED', 'pending']]); this.dom.handshakeAction.textContent = 'ACCEPT NEW IDENTITY';
    } else if (mode === 'waiting') {
      this.dom.handshakeTitle.textContent = 'Waiting for peer to connect'; this.dom.handshakeDescription.textContent = `Secure session negotiation is in progress with ${peer}.`; statuses([['SESSION', 'NEGOTIATING', 'pending'], ['IDENTITY', 'PENDING VERIFICATION', 'pending'], ['ENCRYPTION', 'INITIALIZING', 'pending'], ['ROUTING', 'MULTI-HOP']]); this.dom.handshakeAction.hidden = true;
    } else if (mode === 'awaiting-peer') {
      this.dom.handshakeTitle.textContent = `Waiting for ${peer} to connect`; this.dom.handshakeDescription.textContent = `Your public session key is ready. Share it with ${peer} through a trusted channel, then wait for their session offer.`; statuses([['PUBLIC KEY', 'READY', 'ready'], ['SESSION', 'WAITING FOR PEER', 'pending'], ['ENCRYPTION', 'NOT STARTED']]); this.dom.handshakeAction.hidden = true;
    } else if (mode === 'established') {
      this.dom.handshakeTitle.textContent = 'Private session established'; this.dom.handshakeDescription.textContent = `An authenticated encrypted session with ${peer} is ready.`; statuses([['SESSION', 'ESTABLISHED', 'ready'], ['ENCRYPTION', 'ACTIVE', 'ready'], ['IDENTITY', fp?.verified ? 'VERIFIED' : 'UNVERIFIED', fp?.verified ? 'ready' : 'pending'], ['ROUTING', 'MULTI-HOP']]); this.dom.fingerprintPanel.hidden = !fp; this.dom.peerFingerprint.textContent = formatFingerprint(fp?.fingerprint); this.dom.handshakeAction.textContent = fp?.verified ? 'CONTINUE TO CHAT' : 'VERIFY PEER';
    } else if (mode === 'failed') {
      this.dom.handshakeTitle.textContent = 'Session could not be established'; this.dom.handshakeDescription.textContent = 'The peer declined the offer or its identity could not be confirmed.'; statuses([['SESSION', 'NOT ESTABLISHED', 'pending']]); this.dom.handshakeAction.textContent = 'TRY AGAIN';
    } else {
      this.keyMode = null;
      this.dom.handshakeTitle.textContent = 'Set up a private session'; this.dom.handshakeDescription.textContent = `Choose how you want to exchange public session keys with ${peer}.`; statuses([['SESSION', 'SETUP REQUIRED', 'pending'], ['IDENTITY', 'AWAITING VERIFICATION', 'pending'], ['ENCRYPTION', 'EPHEMERAL SESSION']]); this.dom.keySetup.hidden = false; this.dom.keyOptions.hidden = false; this.dom.ownKeyPanel.hidden = true; this.dom.peerKeyPanel.hidden = true; this.dom.handshakeAction.hidden = true;
    }
    if (mode !== 'setup') this.dom.handshakeAction.hidden = mode === 'waiting' || mode === 'awaiting-peer';
    this.dom.handshakeCancel.textContent = mode === 'established' ? 'CLOSE' : 'CANCEL';
  }

  showKeyMode(mode) {
    this.keyMode = mode;
    this.dom.ownKeyPanel.hidden = mode !== 'generate';
    this.dom.peerKeyPanel.hidden = mode !== 'input';
    if (mode === 'generate') {
      this.dom.ownKeyOutput.value = this.preSession.pubB64;
      this.dom.handshakeAction.textContent = 'WAIT FOR USER';
    } else {
      this.dom.handshakeAction.textContent = `CONNECT TO ${this.handshakePeer.toUpperCase()} →`;
      this.dom.peerKeyInput.focus();
    }
    this.dom.handshakeAction.hidden = false;
  }

  async copySessionKey() {
    const value = this.preSession?.pubB64;
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      this.dom.copyKey.textContent = 'COPIED';
      setTimeout(() => { this.dom.copyKey.textContent = 'COPY PUBLIC KEY'; }, 1600);
    } catch (_) {
      this.dom.ownKeyOutput.focus(); this.dom.ownKeyOutput.select();
      this.log('[warn] select and copy the public key manually', 'warn');
    }
  }

  async handleModalAction() {
    const peer = this.handshakePeer; if (!peer) return;
    if (this.handshakeMode === 'key-change') { this.sessionManager.trustKey(peer); this.openHandshake(peer, 'setup'); return; }
    if (this.handshakeMode === 'established') { const entry = this.sessionManager.fingerprints.get(peer); if (entry && !entry.verified) this.sessionManager.verifyFingerprint(peer); this.closeModal(); this.selectPeer(peer); return; }
    if (this.handshakeMode === 'failed') { this.openHandshake(peer, 'setup'); return; }
    if (this.handshakeMode === 'setup' && this.keyMode === 'generate') { this.openHandshake(peer, 'awaiting-peer'); return; }
    if (this.handshakeMode === 'setup' && this.keyMode !== 'input') return;
    // Always accept a newly pasted key: a peer may have reloaded and created
    // a fresh ephemeral pre-session key since the last exchange.
    if (!this.sessionManager.setPeerPreSessionKey(peer, this.dom.peerKeyInput.value)) { this.log(`[error] invalid public setup key for ${peer}`, 'error'); this.dom.peerKeyInput.focus(); return; }
    this.log(`[identity] saved externally exchanged public setup key for ${peer}`);
    await this.sessionManager.startSession({ username: peer }); this.renderPeerList(); this.openHandshake(peer, 'waiting');
  }

  openSecurity() { if (!this.selectedPeer) return; this.openHandshake(this.selectedPeer, 'established'); }
  clearChat() {
    if (!this.selectedPeer) return;
    if (!window.confirm(`Clear the local chat history with ${this.selectedPeer}? This cannot be undone.`)) return;
    this.messages.delete(this.selectedPeer);
    this.renderMessages();
    this.log(`[chat] cleared local chat history with ${this.selectedPeer}`);
  }
  closeModal() { this.dom.modal.hidden = true; document.body.classList.remove('modal-open'); this.handshakePeer = null; this.dom.peerKeyInput.value = ''; }
  endSession() { if (!this.selectedPeer) return; this.sessionManager.sessions.delete(this.selectedPeer); this.log(`[session] closed local session with ${this.selectedPeer}`); this.selectedPeer = null; this.dom.chatView.hidden = true; this.dom.emptyChat.hidden = false; this.renderPeerList(); }
  shareSessionKey() { if (!this.preSession) return; window.prompt('Share this public setup key with a trusted contact outside Yori. Never share private keys or session secrets.', this.preSession.pubB64); }

  async handleSendMessage() {
    const text = this.dom.messageInput.value.trim(); if (!text || !this.selectedPeer) return;
    if (!this.sessionManager.hasSession(this.selectedPeer)) { this.openHandshake(this.selectedPeer); return; }
    try {
      const result = await this.sessionManager.sendMessage(this.selectedPeer, text);
      this.dom.messageInput.value = ''; this.dom.messageInput.style.height = 'auto';
      this.dom.routeLabel.textContent = result.circuit ? 'MULTI-HOP ROUTING ACTIVE' : 'ENCRYPTED SERVER RELAY';
      this.addMessage(this.selectedPeer, text, 'self', result.counter, result.circuit?.circuitID);
    } catch (error) {
      this.log(`[error] failed to send message: ${error.message}`, 'error');
    }
  }

  leave() { this.coverManager?.stop(); this.circuitManager?.stopAll(); this.ws?.disconnect(); this.dom.appShell.hidden = true; this.dom.landing.hidden = false; this.setConnectionStatus('disconnected', 'DISCONNECTED'); this.selectedPeer = null; }

  showRegistrationError(message) {
    this.ws?.disconnect();
    this.dom.appShell.hidden = true;
    this.dom.landing.hidden = false;
    this.setConnectionStatus('disconnected', 'DISCONNECTED');
    this.dom.loginError.textContent = message || 'Unable to register this username.';
    this.dom.loginError.hidden = false;
    this.dom.usernameInput.focus();
  }
}

window.addEventListener('DOMContentLoaded', () => {
  const app = new YoriApp();
  window.addEventListener('beforeunload', () => { app.coverManager?.stop(); app.circuitManager?.stopAll(); app.ws?.disconnect(); });
});
