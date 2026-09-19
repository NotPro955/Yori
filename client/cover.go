package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"time"
)

const GlobalCoverTrafficInterval = 2 * time.Second
const EnableGlobalCoverTraffic = true

func startGlobalCoverTraffic(state *clientState) {
	if !EnableGlobalCoverTraffic {
		return
	}
	ticker := time.NewTicker(GlobalCoverTrafficInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			state.mu.RLock()
			var candidates []Peer
			for name, p := range state.peers {
				if name != state.username && p.Address != "" && p.PreSessionKey != "" {
					candidates = append(candidates, p)
				}
			}
			state.mu.RUnlock()

			if len(candidates) < 1 {
				continue
			}

			idxBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(candidates))))
			if err != nil {
				continue
			}
			peer := candidates[idxBig.Int64()]

			dummyBody := make([]byte, 128)
			rand.Read(dummyBody)
			dummy := Packet{
				Type:    "cover",
				IsCover: true,
				Body:    base64.RawStdEncoding.EncodeToString(dummyBody),
			}
			dummyBytes, _ := json.Marshal(dummy)
			padded := pad256(dummyBytes)
			ciphertext, ephPub, err := encryptPreSession(peer.PreSessionKey, padded)
			if err == nil {
				_ = directSendToUserSilent(state, peer.Username, Packet{Type: "deliver", To: peer.Username, Payload: ciphertext, PublicKey: ephPub})
			}
		case <-state.done:
			return
		}
	}
}
