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
	for scanner.Scan() {
		var packet Packet
		if err := json.Unmarshal(scanner.Bytes(), &packet); err != nil {
			continue
		}
		switch packet.Type {
		case "users":
			state.mu.Lock()
			for _, peer := range packet.Users {
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
			offerBytes, err := decryptBytes(shared, packet.Payload)
			if err != nil {
				fmt.Println("session offer decrypt error:", err)
				continue
			}
			var offer sessionEnvelope
			if err := json.Unmarshal(offerBytes, &offer); err != nil || offer.Sender == "" || offer.PublicKey == "" {
				fmt.Println("invalid session offer")
				continue
			}
			state.mu.Lock()
			state.keys[offer.Sender] = shared
			state.outgoing[offer.Sender] = shared
			state.mu.Unlock()
			state.mu.RLock()
			username := state.username
			state.mu.RUnlock()
			reply, err := json.Marshal(sessionEnvelope{Sender: username, PublicKey: base64.RawStdEncoding.EncodeToString(privateKey.PublicKey().Bytes())})
			if err != nil {
				fmt.Println("session reply encoding error:", err)
				continue
			}
			encryptedBobKey, err := encryptBytes(shared, reply)
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
			sender, err := decryptSessionReply(state, packet.Payload)
			if err != nil {
				fmt.Println("session reply decrypt error:", err)
				continue
			}
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
	keys := make([][]byte, 0, len(state.keys))
	for _, key := range state.keys {
		keys = append(keys, append([]byte(nil), key...))
	}
	state.mu.RUnlock()

	var lastErr error
	for _, key := range keys {
		plaintext, err := decryptBytes(key, ciphertext)
		if err != nil {
			lastErr = err
			continue
		}
		var envelope chatEnvelope
		if err := json.Unmarshal(plaintext, &envelope); err != nil {
			lastErr = err
			continue
		}
		if envelope.Sender == "" {
			lastErr = fmt.Errorf("message sender missing")
			continue
		}
		return envelope, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no session keys available")
	}
	return chatEnvelope{}, lastErr
}

func decryptSessionReply(state *clientState, ciphertext string) (string, error) {
	state.mu.RLock()
	keys := make(map[string][]byte, len(state.keys))
	for sender, key := range state.keys {
		keys[sender] = append([]byte(nil), key...)
	}
	state.mu.RUnlock()

	var lastErr error
	for _, key := range keys {
		plaintext, err := decryptBytes(key, ciphertext)
		if err != nil {
			lastErr = err
			continue
		}
		var reply sessionEnvelope
		if err := json.Unmarshal(plaintext, &reply); err != nil || reply.Sender == "" {
			lastErr = fmt.Errorf("invalid session reply")
			continue
		}
		return reply.Sender, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no pending session keys")
	}
	return "", lastErr
}
