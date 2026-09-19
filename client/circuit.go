package main

import (
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

const (
	// CircuitRotationInterval controls how often the onion relay path is
	// rebuilt during an active chat session. Adjust to change rotation speed.
	CircuitRotationInterval = 60 * time.Second

	// CoverTrafficEnabled toggles periodic cover message injection.
	// Set to false to disable cover traffic during debugging.
	CoverTrafficEnabled = true

	// coverIntervalMin and coverIntervalMax bound the random window between
	// cover message sends (uniform random in [min, max)).
	coverIntervalMin = 5 * time.Second
	coverIntervalMax = 15 * time.Second

	// coverBodySize is the fixed plaintext byte length of cover message bodies.
	// Real messages use the same envelope structure, so packet sizes are
	// indistinguishable between cover and genuine traffic.
	coverBodySize = 256
)

// sessionCircuit caches the active onion relay path for one chat session.
// It is goroutine-safe; the rotation goroutine and the chat loop share it.
type sessionCircuit struct {
	mu    sync.RWMutex
	route []Peer
}

// rebuild selects a fresh relay route toward recipient using the current peer
// list and stores it. Returns an error if fewer than 2 relay peers are available.
func (sc *sessionCircuit) rebuild(state *clientState, recipient string) error {
	state.mu.RLock()
	peers := make(map[string]Peer, len(state.peers))
	for name, peer := range state.peers {
		peers[name] = peer
	}
	state.mu.RUnlock()

	route := chooseRoute(peers, state.username, recipient)
	if len(route) == 0 {
		return fmt.Errorf("not enough relay peers")
	}
	sc.mu.Lock()
	sc.route = route
	sc.mu.Unlock()
	return nil
}

// routeDisplay returns a human-readable description of the current relay path,
// e.g. "alice → bob → carol → notpro".
func (sc *sessionCircuit) routeDisplay(self, recipient string) string {
	sc.mu.RLock()
	route := sc.route
	sc.mu.RUnlock()
	if len(route) == 0 {
		return self + " → (no circuit)"
	}
	hopNames := make([]string, len(route))
	for i, p := range route {
		hopNames[i] = p.Username
	}
	return self + " → " + strings.Join(hopNames, " → ") + " → " + recipient
}

// sendOnCircuit delivers packet to recipient through the cached relay route.
// If the cached route is empty or the send fails (stale peer), it falls back
// to directSendToUser which picks a fresh route ad-hoc.
func (sc *sessionCircuit) sendOnCircuit(state *clientState, recipient string, packet Packet) error {
	sc.mu.RLock()
	route := sc.route
	sc.mu.RUnlock()

	if len(route) == 0 {
		return directSendToUser(state, recipient, packet)
	}

	state.mu.RLock()
	serverAddr := state.serverAddr
	username := state.username
	state.mu.RUnlock()

	onion, _, err := buildOnion(route, serverAddr, recipient, packet.Type, packet.Payload, packet.PublicKey)
	if err != nil {
		return directSendToUser(state, recipient, packet)
	}
	if err := directSend(route[0].Address, username, Packet{Type: "onion", Payload: onion}); err != nil {
		// Route is stale — clear it so the fallback selects a fresh path.
		sc.mu.Lock()
		sc.route = nil
		sc.mu.Unlock()
		return directSendToUser(state, recipient, packet)
	}
	return nil
}

// startCircuitRotation launches a background goroutine that rebuilds the relay
// route every CircuitRotationInterval. On failure it retries up to 3 times
// with exponential backoff before printing an error. Stops when done is closed.
func startCircuitRotation(state *clientState, recipient string, sc *sessionCircuit, done <-chan struct{}) {
	state.mu.RLock()
	username := state.username
	state.mu.RUnlock()

	go func() {
		ticker := time.NewTicker(CircuitRotationInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				backoff := 5 * time.Second
				rebuilt := false
				for attempt := 0; attempt < 3; attempt++ {
					if err := sc.rebuild(state, recipient); err != nil {
						if attempt < 2 {
							select {
							case <-done:
								return
							case <-time.After(backoff):
								backoff *= 2
							}
						} else {
							fmt.Printf("\n[circuit rotation failed: %v]\n> ", err)
						}
						continue
					}
					rebuilt = true
					break
				}
				if rebuilt {
					id, _ := randomID()
					shortID := id
					if len(shortID) > 8 {
						shortID = shortID[:8]
					}
					fmt.Printf("\n[circuit rotated] %s  ID: %s\n> ",
						sc.routeDisplay(username, recipient), shortID)
				}
			}
		}
	}()
}

// randomCoverInterval returns a uniformly random duration in [coverIntervalMin, coverIntervalMax).
func randomCoverInterval() time.Duration {
	rangeNs := int64(coverIntervalMax - coverIntervalMin)
	n, err := crand.Int(crand.Reader, big.NewInt(rangeNs))
	if err != nil {
		return coverIntervalMin
	}
	return coverIntervalMin + time.Duration(n.Int64())
}

// randomPaddedBody returns a base64-encoded string of coverBodySize bytes drawn
// from crypto/rand, used as the body of cover messages so their encrypted size
// matches that of typical real messages.
func randomPaddedBody() (string, error) {
	raw := make([]byte, coverBodySize)
	if _, err := crand.Read(raw); err != nil {
		return "", err
	}
	encoded := base64.RawStdEncoding.EncodeToString(raw)
	if len(encoded) > coverBodySize {
		encoded = encoded[:coverBodySize]
	}
	return encoded, nil
}

// startCoverTraffic launches a goroutine that injects encrypted cover messages
// at random intervals within [coverIntervalMin, coverIntervalMax]. Cover messages
// use the real session key and are wrapped in the same onion envelope as genuine
// messages; they are structurally indistinguishable to any observer outside the
// E2E session. The recipient identifies them via the Cover field inside the
// decrypted chatEnvelope and silently discards them. Has no effect when
// CoverTrafficEnabled is false. Stops cleanly when done is closed.
func startCoverTraffic(state *clientState, recipient string, sc *sessionCircuit, done <-chan struct{}) {
	if !CoverTrafficEnabled {
		return
	}
	go func() {
		for {
			interval := randomCoverInterval()
			select {
			case <-done:
				return
			case <-time.After(interval):
			}

			// Grab all required session fields under a single write lock so
			// the counter increment is atomic with respect to real sends.
			state.mu.Lock()
			sessionID := state.sessionIDs[recipient]
			state.sendCounts[recipient]++
			counter := state.sendCounts[recipient]
			outKey, ok := state.outgoing[recipient]
			senderName := state.username
			var key []byte
			if ok {
				key = append([]byte(nil), outKey...)
			}
			state.mu.Unlock()

			if !ok {
				continue // session may have been cleared
			}

			msgID, err := randomID()
			if err != nil {
				continue
			}
			body, err := randomPaddedBody()
			if err != nil {
				continue
			}
			envelope, err := json.Marshal(chatEnvelope{
				Version:   protocolVersion,
				MessageID: msgID,
				SessionID: sessionID,
				Counter:   counter,
				Sender:    senderName,
				Body:      body,
				Cover:     true, // recipient silently discards after decryption
			})
			if err != nil {
				continue
			}
			paddedEnv := pad256(envelope)
			ciphertext, err := encryptBytesAAD(key, paddedEnv, []byte("yori/message/v1|"+sessionID))
			if err != nil {
				continue
			}
			// Fire-and-forget; errors are intentionally ignored so cover
			// failures never surface in the chat UI.
			_ = sc.sendOnCircuit(state, recipient, Packet{Type: "send", To: recipient, Payload: ciphertext})
		}
	}()
}
