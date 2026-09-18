package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"sync"
)

const (
	protocolVersion  uint8 = 1
	maxPacketBytes         = 64 * 1024
	maxPayloadBytes        = 48 * 1024
	maxUsernameBytes       = 32
	maxTTL                 = 8
	defaultTTL             = 5
)

type Packet struct {
	Version      uint8  `json:"version"`
	ID           string `json:"id"`
	CircuitID    string `json:"circuit_id,omitempty"`
	TTL          uint8  `json:"ttl,omitempty"`
	Type         string `json:"type"`
	To           string `json:"to,omitempty"`
	Payload      string `json:"payload,omitempty"`
	PublicKey    string `json:"public_key,omitempty"`
	OriginalType string `json:"original_type,omitempty"`
	Users        []Peer `json:"users,omitempty"`
}

type Peer struct {
	Username  string `json:"username"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
	Identity  string `json:"identity"`
}

type onionEnvelope struct {
	Version   uint8  `json:"version"`
	CircuitID string `json:"circuit_id"`
	TTL       uint8  `json:"ttl"`
	Next      string `json:"next"`
	To        string `json:"to,omitempty"`
	Type      string `json:"type"`
	Payload   string `json:"payload"`
	PublicKey string `json:"public_key,omitempty"`
}

type onionPacket struct {
	Ephemeral  string `json:"ephemeral"`
	Ciphertext string `json:"ciphertext"`
}

type chatEnvelope struct {
	Version   uint8  `json:"version"`
	MessageID string `json:"message_id"`
	SessionID string `json:"session_id"`
	Counter   uint64 `json:"counter"`
	Sender    string `json:"sender"`
	Body      string `json:"body"`
}

type sessionEnvelope struct {
	Sender    string `json:"sender"`
	PublicKey string `json:"public_key"`
	SessionID string `json:"session_id"`
	Signature string `json:"signature"`
}

type clientState struct {
	mu          sync.RWMutex
	username    string
	privateKey  *ecdh.PrivateKey
	relayKey    *ecdh.PrivateKey
	identityKey ed25519.PrivateKey
	serverAddr  string
	serverConn  net.Conn
	keys        map[string][]byte
	outgoing    map[string][]byte
	shared      map[string][]byte
	sessionIDs  map[string]string
	sendCounts  map[string]uint64
	received    map[string]map[uint64]bool
	peers       map[string]Peer
	identities  map[string]string
	keyChanged  map[string]bool
	peerUpdates chan struct{}
}

func send_packet(server net.Conn, packet Packet) error {
	if err := preparePacket(&packet); err != nil {
		return err
	}
	data, err := json.Marshal(packet)
	if err != nil {
		return err
	}
	clientWriteMu.Lock()
	defer clientWriteMu.Unlock()
	_, err = server.Write(append(data, '\n'))
	return err
}

func preparePacket(packet *Packet) error {
	if packet.Version == 0 {
		packet.Version = protocolVersion
	}
	if packet.Version != protocolVersion {
		return fmt.Errorf("unsupported protocol version")
	}
	if packet.ID == "" {
		id, err := randomID()
		if err != nil {
			return err
		}
		packet.ID = id
	}
	if packet.TTL == 0 {
		packet.TTL = defaultTTL
	}
	return validatePacket(*packet)
}

func validatePacket(packet Packet) error {
	if packet.Version != protocolVersion || packet.ID == "" || packet.Type == "" {
		return fmt.Errorf("invalid packet metadata")
	}
	if !validPacketType(packet.Type) {
		return fmt.Errorf("unknown packet type")
	}
	if packet.TTL > maxTTL {
		return fmt.Errorf("invalid packet ttl")
	}
	if len(packet.Payload) > maxPayloadBytes {
		return fmt.Errorf("packet payload too large")
	}
	if len(packet.To) > maxUsernameBytes {
		return fmt.Errorf("packet recipient too long")
	}
	return nil
}

func validPacketType(packetType string) bool {
	switch packetType {
	case "users", "waiting", "message", "session_offer", "session_reply", "onion", "deliver", "heartbeat", "error":
		return true
	default:
		return false
	}
}

func randomID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := crand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func configureScanner(scanner *bufio.Scanner) {
	scanner.Buffer(make([]byte, 1024), maxPacketBytes)
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
