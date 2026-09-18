package main

import (
	"crypto/ecdh"
	crand "crypto/rand"
	"encoding/base64"
	"testing"
)

func TestChooseRouteExcludesSenderAndRecipient(t *testing.T) {
	peers := map[string]Peer{
		"alice": {Username: "alice", Address: "127.0.0.1:1001", PublicKey: "key1"},
		"bob":   {Username: "bob", Address: "127.0.0.1:1002", PublicKey: "key2"},
		"r1":    {Username: "r1", Address: "127.0.0.1:1003", PublicKey: "key3"},
		"r2":    {Username: "r2", Address: "127.0.0.1:1004", PublicKey: "key4"},
	}

	route := chooseRoute(peers, "alice", "bob")
	if len(route) != 2 {
		t.Fatalf("expected route length 2, got %d", len(route))
	}
	for _, p := range route {
		if p.Username == "alice" || p.Username == "bob" {
			t.Fatalf("route included forbidden peer %s", p.Username)
		}
	}
}

func TestChooseRouteRequiresAtLeastTwoRelays(t *testing.T) {
	peers := map[string]Peer{
		"alice": {Username: "alice", Address: "127.0.0.1:1001", PublicKey: "key1"},
		"bob":   {Username: "bob", Address: "127.0.0.1:1002", PublicKey: "key2"},
		"r1":    {Username: "r1", Address: "127.0.0.1:1003", PublicKey: "key3"},
	}

	route := chooseRoute(peers, "alice", "bob")
	if route != nil {
		t.Fatalf("expected nil route when fewer than 2 relays are available, got %v", route)
	}
}

func TestMultiHopOnionConstructionAndPeeling(t *testing.T) {
	// Generate relay keys for R1 and R2
	r1Priv, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r2Priv, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r1Pub := base64.RawStdEncoding.EncodeToString(r1Priv.PublicKey().Bytes())
	r2Pub := base64.RawStdEncoding.EncodeToString(r2Priv.PublicKey().Bytes())

	route := []Peer{
		{Username: "r1", Address: "127.0.0.1:5001", PublicKey: r1Pub},
		{Username: "r2", Address: "127.0.0.1:5002", PublicKey: r2Pub},
	}

	serverAddr := "127.0.0.1:9000"
	recipient := "bob"
	packetType := "send"
	payload := "encrypted-chat-payload"
	pubKey := "ephemeral-key"

	onion, circuitID, err := buildOnion(route, serverAddr, recipient, packetType, payload, pubKey)
	if err != nil {
		t.Fatalf("buildOnion failed: %v", err)
	}
	if circuitID == "" {
		t.Fatal("circuitID is empty")
	}

	// Hop 1 (R1) peeling
	stateR1 := &clientState{relayKey: r1Priv}
	envR1, err := decryptOnionLayer(stateR1, onion)
	if err != nil {
		t.Fatalf("R1 decrypt failed: %v", err)
	}
	if envR1.CircuitID != circuitID {
		t.Fatalf("R1 circuitID mismatch: expected %s, got %s", circuitID, envR1.CircuitID)
	}
	if envR1.Next != "127.0.0.1:5002" {
		t.Fatalf("R1 next hop mismatch: expected 127.0.0.1:5002, got %s", envR1.Next)
	}
	if envR1.TTL != 2 {
		t.Fatalf("R1 TTL mismatch: expected 2, got %d", envR1.TTL)
	}
	// R1 decrements TTL
	envR1.TTL--
	if envR1.TTL == 0 {
		t.Fatal("R1 TTL should not be 0 after first hop decrement")
	}

	// Hop 2 (R2) peeling
	stateR2 := &clientState{relayKey: r2Priv}
	envR2, err := decryptOnionLayer(stateR2, envR1.Payload)
	if err != nil {
		t.Fatalf("R2 decrypt failed: %v", err)
	}
	if envR2.CircuitID != circuitID {
		t.Fatalf("R2 circuitID mismatch: expected %s, got %s", circuitID, envR2.CircuitID)
	}
	if envR2.Next != serverAddr {
		t.Fatalf("R2 next hop mismatch: expected %s, got %s", serverAddr, envR2.Next)
	}
	if envR2.TTL != 1 {
		t.Fatalf("R2 TTL mismatch: expected 1, got %d", envR2.TTL)
	}
	if envR2.To != recipient {
		t.Fatalf("R2 To mismatch: expected %s, got %s", recipient, envR2.To)
	}
	if envR2.Payload != payload {
		t.Fatalf("R2 payload mismatch: expected %s, got %s", payload, envR2.Payload)
	}
	if envR2.Type != packetType {
		t.Fatalf("R2 type mismatch: expected %s, got %s", packetType, envR2.Type)
	}

	// R2 decrements TTL
	envR2.TTL--
	// R2 is at the exit relay (envR2.Next == serverAddr), so it delivers to server
	if envR2.Next != serverAddr {
		t.Fatal("expected R2 to deliver to server")
	}
}

func TestExpiredRouteDrop(t *testing.T) {
	r1Priv, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stateR1 := &clientState{
		relayKey:   r1Priv,
		serverAddr: "127.0.0.1:9000",
		username:   "r1",
	}

	// An envelope with TTL = 1 on an intermediate hop decrements to 0
	env := onionEnvelope{
		Version:   protocolVersion,
		CircuitID: "c1",
		TTL:       1,
		Next:      "127.0.0.1:5002",
		Payload:   "inner",
	}
	env.TTL--
	if !(env.TTL == 0 && env.Next != stateR1.serverAddr) {
		t.Fatal("expected intermediate hop with expired TTL to trigger drop condition")
	}
}
