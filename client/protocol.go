package main

import (
	"crypto/ecdh"
	crand "crypto/rand"
	"encoding/json"
	"net"
	"sync"
)

type Packet struct {
	Type         string `json:"type"`
	To           string `json:"to,omitempty"`
	Next         string `json:"next,omitempty"`
	Payload      string `json:"payload,omitempty"`
	PublicKey    string `json:"public_key,omitempty"`
	Hops         int    `json:"hops,omitempty"`
	OriginalType string `json:"original_type,omitempty"`
	Users        []Peer `json:"users,omitempty"`
}

type Peer struct {
	Username string `json:"username"`
	Address  string `json:"address"`
}

type chatEnvelope struct {
	Sender string `json:"sender"`
	Body   string `json:"body"`
}

type sessionEnvelope struct {
	Sender string `json:"sender"`
	Key    []byte `json:"key"`
}

type clientState struct {
	mu          sync.RWMutex
	username    string
	privateKey  *ecdh.PrivateKey
	keys        map[string][]byte
	outgoing    map[string][]byte
	peers       map[string]Peer
	peerUpdates chan struct{}
}

func send_packet(server net.Conn, packet Packet) error {
	data, err := json.Marshal(packet)
	if err != nil {
		return err
	}
	clientWriteMu.Lock()
	defer clientWriteMu.Unlock()
	_, err = server.Write(append(data, '\n'))
	return err
}

var clientWriteMu sync.Mutex

func ensurePrivateKey(state *clientState) (*ecdh.PrivateKey, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.privateKey == nil {
		privateKey, err := ecdh.X25519().GenerateKey(crand.Reader)
		if err != nil {
			return nil, err
		}
		state.privateKey = privateKey
	}
	return state.privateKey, nil
}
