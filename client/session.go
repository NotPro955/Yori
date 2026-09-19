package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

func read_server(server net.Conn, state *clientState) {
	scanner := bufio.NewScanner(server)
	configureScanner(scanner)
	for scanner.Scan() {
		var packet Packet
		if err := json.Unmarshal(scanner.Bytes(), &packet); err != nil {
			continue
		}
		if err := validatePacket(packet); err != nil {
			fmt.Println("invalid server packet")
			continue
		}
		processServerPacket(packet, state, server)
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("server connection closed:", err)
	}
}

func processServerPacket(packet Packet, state *clientState, server net.Conn) {
	switch packet.Type {
	case "users":
		state.mu.Lock()
		active := make(map[string]bool, len(packet.Users))
		for _, peer := range packet.Users {
			active[peer.Username] = true
			if peer.Identity != "" {
				if old, exists := state.identities[peer.Username]; exists && old != "" && old != peer.Identity {
					state.keyChanged[peer.Username] = true
				}
				state.identities[peer.Username] = peer.Identity
			}
			state.peers[peer.Username] = peer
		}
		for name := range state.peers {
			if !active[name] {
				delete(state.peers, name)
			}
		}
		select {
		case state.peerUpdates <- struct{}{}:
		default:
		}
		state.mu.Unlock()
		usernames := make([]string, 0, len(packet.Users))
		for _, peer := range packet.Users {
			usernames = append(usernames, peer.Username)
		}
		fmt.Println("Users:", strings.Join(usernames, ", "))
	case "waiting":
		fmt.Printf("Waiting for %s...\n", packet.To)
	case "message":
		envelope, err := decryptChatEnvelope(state, packet.Payload)
		if err != nil {
			fmt.Println("decrypt error:", err)
			return
		}
		if envelope.Cover {
			return
		}
		fmt.Printf("\n[%s] %s\n> ", envelope.Sender, envelope.Body)
	case "session_offer":
		privateKey, err := ensurePrivateKey(state)
		if err != nil {
			fmt.Println("session offer keygen error:", err)
			return
		}
		shared, err := deriveSessionKey(privateKey, packet.PublicKey)
		if err != nil {
			fmt.Println("session offer key error:", err)
			return
		}
		offerBytes, err := decryptBytesAAD(shared, packet.Payload, []byte("yori/session/v1/offer"))
		if err != nil {
			fmt.Println("session offer decrypt error:", err)
			return
		}
		var offer sessionEnvelope
		if err := json.Unmarshal(offerBytes, &offer); err != nil || offer.Sender == "" || offer.PublicKey == "" || offer.SessionID == "" {
			fmt.Println("invalid session offer")
			return
		}
		state.mu.RLock()
		peerIdentity, known := state.identities[offer.Sender]
		changed := state.keyChanged[offer.Sender]
		state.mu.RUnlock()
		if changed {
			fmt.Printf("\n[warn] session offer from %s blocked: identity key changed\n> ", offer.Sender)
			
			state.mu.RLock()
			username := state.username
			state.mu.RUnlock()
			
			rejectMsg := Packet{Type: "session_reject", From: username, To: offer.Sender, Payload: "identity_key_changed"}
			rejectBytes, _ := json.Marshal(rejectMsg)
			paddedBytes := pad256(rejectBytes)
			ciphertext, ephPub, err := encryptPreSession(packet.PublicKey, paddedBytes)
			if err == nil {
				_ = directSendToUser(state, offer.Sender, Packet{Type: "deliver", To: offer.Sender, Payload: ciphertext, PublicKey: ephPub})
			}
			return
		}
		if known && peerIdentity != "" && !verifySessionSignature(peerIdentity, offer.Sender, offer.SessionID, offer.PublicKey, offer.Signature) {
			fmt.Printf("\n[warn] session offer from %s blocked: signature invalid\n> ", offer.Sender)
			return
		}
		sendKey, receiveKey, err := deriveDirectionalKeys(shared, offer.SessionID, false)
		if err != nil {
			fmt.Println("session key derivation error:", err)
			return
		}
		state.mu.Lock()
		state.keys[offer.Sender] = receiveKey
		state.outgoing[offer.Sender] = sendKey
		state.shared[offer.Sender] = shared
		state.sessionIDs[offer.Sender] = offer.SessionID
		state.mu.Unlock()
		state.mu.RLock()
		username := state.username
		state.mu.RUnlock()
		replyPublicKey := base64.RawStdEncoding.EncodeToString(privateKey.PublicKey().Bytes())
		identity, err := ensureIdentityKey(state)
		if err != nil {
			fmt.Println("identity key error:", err)
			return
		}
		reply, err := json.Marshal(sessionEnvelope{Sender: username, PublicKey: replyPublicKey, SessionID: offer.SessionID, Signature: sessionSignature(identity, username, offer.SessionID, replyPublicKey)})
		if err != nil {
			fmt.Println("session reply encoding error:", err)
			return
		}
		encryptedBobKey, err := encryptBytesAAD(shared, reply, []byte("yori/session/v1/reply"))
		if err != nil {
			fmt.Println("session reply encryption error:", err)
			return
		}
		innerReply := Packet{Type: "session_reply", To: offer.Sender, Payload: encryptedBobKey}
		innerBytes, err := json.Marshal(innerReply)
		if err != nil {
			fmt.Println("inner reply marshal error:", err)
			return
		}
		paddedBytes := pad256(innerBytes)
		ciphertext, ephPub, err := encryptPreSession(packet.PublicKey, paddedBytes)
		if err != nil {
			fmt.Println("pre-session encryption error:", err)
			return
		}
		if err := directSendToUser(state, offer.Sender, Packet{Type: "deliver", To: offer.Sender, Payload: ciphertext, PublicKey: ephPub}); err != nil {
			fmt.Println("session reply send error:", err)
			return
		}
		fmt.Printf("\nsession established with %s — type /chat %s\n> ", offer.Sender, offer.Sender)
	case "session_reply":
		sender, sessionID, publicKey, signature, err := decryptSessionReply(state, packet.Payload)
		if err != nil {
			fmt.Println("session reply decrypt error:", err)
			return
		}
		state.mu.RLock()
		identity, known := state.identities[sender]
		changed := state.keyChanged[sender]
		state.mu.RUnlock()
		if changed {
			fmt.Printf("\n[warn] session reply from %s blocked: identity key changed\n> ", sender)
			return
		}
		if known && identity != "" && !verifySessionSignature(identity, sender, sessionID, publicKey, signature) {
			fmt.Printf("\n[warn] session reply from %s blocked: signature invalid\n> ", sender)
			return
		}
		state.mu.Lock()
		if shared, ok := state.shared[sender]; ok {
			if sendKey, receiveKey, keyErr := deriveDirectionalKeys(shared, sessionID, true); keyErr == nil {
				state.outgoing[sender] = sendKey
				state.keys[sender] = receiveKey
			}
		}
		state.mu.Unlock()
		fmt.Printf("\nsession established with %s — type /chat %s\n> ", sender, sender)
	case "session_reject":
		if packet.Payload == "identity_key_changed" {
			state.mu.RLock()
			username := state.username
			state.mu.RUnlock()
			fmt.Printf("\n[warn] session rejected by %s: identity key changed on their end — ask them to run /trustkey %s\n> ", packet.From, username)
		}
	case "relay":
		if err := send_packet(server, packet); err != nil {
			fmt.Println("relay send error:", err)
			return
		}
	case "error":
		fmt.Println("Server:", packet.Payload)
	case "deliver":
		state.mu.RLock()
		preSessionKey := state.preSessionKey
		sessionPrivKey := state.privateKey
		state.mu.RUnlock()

		var plaintext []byte
		var err error
		if preSessionKey != nil {
			plaintext, err = decryptPreSessionWithKey(preSessionKey, packet.PublicKey, packet.Payload)
		}
		if (err != nil || preSessionKey == nil) && sessionPrivKey != nil {
			plaintext, err = decryptPreSessionWithKey(sessionPrivKey, packet.PublicKey, packet.Payload)
		}
		if err != nil {
			fmt.Println("pre-session decrypt error:", err)
			return
		}
		
		unpadded, err := unpad256(plaintext)
		if err != nil {
			return
		}

		var inner Packet
		if err := json.Unmarshal(unpadded, &inner); err != nil {
			fmt.Println("pre-session unmarshal error:", err)
			return
		}
		if inner.Type == "cover" || inner.IsCover {
			return
		}
		processServerPacket(inner, state, server)
	}
}

func decryptChatEnvelope(state *clientState, ciphertext string) (chatEnvelope, error) {
	state.mu.RLock()
	keys := make(map[string][]byte, len(state.keys))
	for sender, key := range state.keys {
		keys[sender] = append([]byte(nil), key...)
	}
	sessionIDs := make(map[string]string, len(state.sessionIDs))
	for sender, sessionID := range state.sessionIDs {
		sessionIDs[sender] = sessionID
	}
	state.mu.RUnlock()

	var lastErr error
	for sender, key := range keys {
		sessionID := sessionIDs[sender]
		plaintext, err := decryptBytesAAD(key, ciphertext, []byte("yori/message/v1|"+sessionID))
		if err != nil {
			lastErr = err
			continue
		}
		unpadded, err := unpad256(plaintext)
		if err != nil {
			lastErr = err
			continue
		}
		var envelope chatEnvelope
		if err := json.Unmarshal(unpadded, &envelope); err != nil {
			lastErr = err
			continue
		}
		if envelope.Version != protocolVersion || envelope.Sender == "" || envelope.SessionID != sessionID || envelope.MessageID == "" || envelope.Counter == 0 {
			lastErr = fmt.Errorf("message sender missing")
			continue
		}
		state.mu.Lock()
		seen := state.received[sessionID]
		if seen == nil {
			seen = make(map[uint64]bool)
			state.received[sessionID] = seen
		}
		if seen[envelope.Counter] {
			state.mu.Unlock()
			return chatEnvelope{}, fmt.Errorf("replayed message")
		}
		seen[envelope.Counter] = true
		state.mu.Unlock()
		return envelope, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no session keys available")
	}
	return chatEnvelope{}, lastErr
}

func decryptSessionReply(state *clientState, ciphertext string) (string, string, string, string, error) {
	state.mu.RLock()
	keys := make(map[string][]byte, len(state.shared))
	for sender, key := range state.shared {
		keys[sender] = append([]byte(nil), key...)
	}
	state.mu.RUnlock()

	var lastErr error
	for _, key := range keys {
		plaintext, err := decryptBytesAAD(key, ciphertext, []byte("yori/session/v1/reply"))
		if err != nil {
			lastErr = err
			continue
		}
		var reply sessionEnvelope
		if err := json.Unmarshal(plaintext, &reply); err != nil || reply.Sender == "" {
			lastErr = fmt.Errorf("invalid session reply")
			continue
		}
		if reply.SessionID == "" {
			lastErr = fmt.Errorf("session id missing")
			continue
		}
		return reply.Sender, reply.SessionID, reply.PublicKey, reply.Signature, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no pending session keys")
	}
	return "", "", "", "", lastErr
}

func clearSession(state *clientState, recipient string) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if k, ok := state.keys[recipient]; ok {
		for i := range k {
			k[i] = 0
		}
		delete(state.keys, recipient)
	}
	if k, ok := state.outgoing[recipient]; ok {
		for i := range k {
			k[i] = 0
		}
		delete(state.outgoing, recipient)
	}
	if k, ok := state.shared[recipient]; ok {
		for i := range k {
			k[i] = 0
		}
		delete(state.shared, recipient)
	}
	if sid, ok := state.sessionIDs[recipient]; ok {
		delete(state.received, sid)
		delete(state.sessionIDs, recipient)
	}
	delete(state.sendCounts, recipient)
}

func clearAllSessions(state *clientState) {
	state.mu.Lock()
	defer state.mu.Unlock()
	for u, k := range state.keys {
		for i := range k {
			k[i] = 0
		}
		delete(state.keys, u)
	}
	for u, k := range state.outgoing {
		for i := range k {
			k[i] = 0
		}
		delete(state.outgoing, u)
	}
	for u, k := range state.shared {
		for i := range k {
			k[i] = 0
		}
		delete(state.shared, u)
	}
	state.sessionIDs = make(map[string]string)
	state.sendCounts = make(map[string]uint64)
	state.received = make(map[string]map[uint64]bool)
}

