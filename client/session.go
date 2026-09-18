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
		switch packet.Type {
		case "users":
			state.mu.Lock()
			for _, peer := range packet.Users {
				if old, exists := state.identities[peer.Username]; exists && old != peer.Identity {
					state.keyChanged[peer.Username] = true
				}
				if _, exists := state.identities[peer.Username]; !exists {
					state.identities[peer.Username] = peer.Identity
				}
				state.peers[peer.Username] = peer
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
				continue
			}
			fmt.Printf("\n[%s] %s\n> ", envelope.Sender, envelope.Body)
		case "session_offer":
			privateKey, err := ensurePrivateKey(state)
			if err != nil {
				fmt.Println("session offer keygen error:", err)
				continue
			}
			shared, err := deriveSessionKey(privateKey, packet.PublicKey)
			if err != nil {
				fmt.Println("session offer key error:", err)
				continue
			}
			offerBytes, err := decryptBytesAAD(shared, packet.Payload, []byte("yori/session/v1/offer"))
			if err != nil {
				fmt.Println("session offer decrypt error:", err)
				continue
			}
			var offer sessionEnvelope
			if err := json.Unmarshal(offerBytes, &offer); err != nil || offer.Sender == "" || offer.PublicKey == "" || offer.SessionID == "" {
				fmt.Println("invalid session offer")
				continue
			}
			state.mu.RLock()
			peer, known := state.peers[offer.Sender]
			changed := state.keyChanged[offer.Sender]
			state.mu.RUnlock()
			if changed || !known || !verifySessionSignature(peer.Identity, offer.Sender, offer.SessionID, offer.PublicKey, offer.Signature) {
				fmt.Println("session identity verification failed")
				continue
			}
			sendKey, receiveKey, err := deriveDirectionalKeys(shared, offer.SessionID, false)
			if err != nil {
				fmt.Println("session key derivation error:", err)
				continue
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
				continue
			}
			reply, err := json.Marshal(sessionEnvelope{Sender: username, PublicKey: replyPublicKey, SessionID: offer.SessionID, Signature: sessionSignature(identity, username, offer.SessionID, replyPublicKey)})
			if err != nil {
				fmt.Println("session reply encoding error:", err)
				continue
			}
			encryptedBobKey, err := encryptBytesAAD(shared, reply, []byte("yori/session/v1/reply"))
			if err != nil {
				fmt.Println("session reply encryption error:", err)
				continue
			}
			if err := directSendToUser(state, offer.Sender, Packet{Type: "session_reply", To: offer.Sender, Payload: encryptedBobKey}); err != nil {
				fmt.Println("session reply send error:", err)
				return
			}
			fmt.Println("session established with", offer.Sender)
		case "session_reply":
			sender, sessionID, publicKey, signature, err := decryptSessionReply(state, packet.Payload)
			if err != nil {
				fmt.Println("session reply decrypt error:", err)
				continue
			}
			state.mu.RLock()
			peer, known := state.peers[sender]
			state.mu.RUnlock()
			if !known || !verifySessionSignature(peer.Identity, sender, sessionID, publicKey, signature) {
				fmt.Println("session identity verification failed")
				continue
			}
			state.mu.Lock()
			if shared, ok := state.shared[sender]; ok {
				if sendKey, receiveKey, keyErr := deriveDirectionalKeys(shared, sessionID, true); keyErr == nil {
					state.outgoing[sender] = sendKey
					state.keys[sender] = receiveKey
				}
			}
			state.mu.Unlock()
			fmt.Println("session established with", sender)
		case "relay":
			if err := send_packet(server, packet); err != nil {
				fmt.Println("relay send error:", err)
				return
			}
		case "error":
			fmt.Println("Server:", packet.Payload)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("server connection closed:", err)
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
		var envelope chatEnvelope
		if err := json.Unmarshal(plaintext, &envelope); err != nil {
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
