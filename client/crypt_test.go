package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestSessionKeyAgreement(t *testing.T) {
	alice, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aliceShared, err := deriveSessionKey(alice, base64.RawStdEncoding.EncodeToString(bob.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	bobShared, err := deriveSessionKey(bob, base64.RawStdEncoding.EncodeToString(alice.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if string(aliceShared) != string(bobShared) {
		t.Fatal("X25519 peers derived different HKDF keys")
	}
}

func TestDirectionalKeysDiffer(t *testing.T) {
	shared := []byte("test shared secret")
	send, receive, err := deriveDirectionalKeys(shared, "session-1", true)
	if err != nil {
		t.Fatal(err)
	}
	if string(send) == string(receive) {
		t.Fatal("directional keys are identical")
	}
}

func TestAEADAuthenticatesAADAndCiphertext(t *testing.T) {
	key, err := randomAESKey()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := encryptBytesAAD(key, []byte("message"), []byte("metadata"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := decryptBytesAAD(key, ciphertext, []byte("metadata"))
	if err != nil || string(plaintext) != "message" {
		t.Fatalf("decrypt failed: %v", err)
	}
	if _, err := decryptBytesAAD(key, ciphertext, []byte("changed")); err == nil {
		t.Fatal("modified AAD was accepted")
	}
	raw, err := base64.RawStdEncoding.DecodeString(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	mutated := base64.RawStdEncoding.EncodeToString(raw)
	if _, err := decryptBytesAAD(key, mutated, []byte("metadata")); err == nil {
		t.Fatal("modified ciphertext was accepted")
	}
}

func TestInvalidPublicKeyFails(t *testing.T) {
	privateKey, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deriveSessionKey(privateKey, "bad-key"); err == nil {
		t.Fatal("invalid public key was accepted")
	}
}

func TestIdentitySignatureBindsSessionData(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature := sessionSignature(privateKey, "alice", "session-1", "ephemeral-key")
	identity := base64.RawStdEncoding.EncodeToString(publicKey)
	if !verifySessionSignature(identity, "alice", "session-1", "ephemeral-key", signature) {
		t.Fatal("valid identity signature was rejected")
	}
	if verifySessionSignature(identity, "bob", "session-1", "ephemeral-key", signature) {
		t.Fatal("signature accepted for altered sender")
	}
}

func TestReplayCounterRejection(t *testing.T) {
	key, err := randomAESKey()
	if err != nil {
		t.Fatal(err)
	}
	sessionID := "session-replay-1"
	state := &clientState{
		keys:       map[string][]byte{"alice": key},
		sessionIDs: map[string]string{"alice": sessionID},
		received:   make(map[string]map[uint64]bool),
	}

	envelope := chatEnvelope{
		Version:   protocolVersion,
		MessageID: "msg-1",
		SessionID: sessionID,
		Counter:   1,
		Sender:    "alice",
		Body:      "hello",
	}
	bytes, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := encryptBytesAAD(key, bytes, []byte("yori/message/v1|"+sessionID))
	if err != nil {
		t.Fatal(err)
	}

	// First receipt must succeed
	decrypted, err := decryptChatEnvelope(state, ciphertext)
	if err != nil {
		t.Fatalf("first delivery failed: %v", err)
	}
	if decrypted.Body != "hello" {
		t.Fatalf("unexpected body: %s", decrypted.Body)
	}

	// Replay receipt with same counter must fail
	if _, err := decryptChatEnvelope(state, ciphertext); err == nil {
		t.Fatal("replayed message was accepted")
	}
}

func TestWrongSessionRejection(t *testing.T) {
	key, err := randomAESKey()
	if err != nil {
		t.Fatal(err)
	}
	sessionA := "session-A"
	sessionB := "session-B"

	envelope := chatEnvelope{
		Version:   protocolVersion,
		MessageID: "msg-wrong-session",
		SessionID: sessionA,
		Counter:   1,
		Sender:    "alice",
		Body:      "secret for A",
	}
	bytes, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	// Encrypted under sessionA's AAD
	ciphertext, err := encryptBytesAAD(key, bytes, []byte("yori/message/v1|"+sessionA))
	if err != nil {
		t.Fatal(err)
	}

	// State configured with sessionB
	stateB := &clientState{
		keys:       map[string][]byte{"alice": key},
		sessionIDs: map[string]string{"alice": sessionB},
		received:   make(map[string]map[uint64]bool),
	}

	if _, err := decryptChatEnvelope(stateB, ciphertext); err == nil {
		t.Fatal("message for session A was accepted in session B")
	}
}

func TestSessionClearance(t *testing.T) {
	state := &clientState{
		keys:       map[string][]byte{"bob": []byte("key-material")},
		outgoing:   map[string][]byte{"bob": []byte("out-material")},
		shared:     map[string][]byte{"bob": []byte("shared-material")},
		sessionIDs: map[string]string{"bob": "session-123"},
		sendCounts: map[string]uint64{"bob": 5},
		received:   map[string]map[uint64]bool{"session-123": {1: true, 2: true}},
	}

	clearSession(state, "bob")

	if _, ok := state.keys["bob"]; ok {
		t.Fatal("receive key was not deleted")
	}
	if _, ok := state.outgoing["bob"]; ok {
		t.Fatal("outgoing key was not deleted")
	}
	if _, ok := state.shared["bob"]; ok {
		t.Fatal("shared key was not deleted")
	}
	if _, ok := state.sessionIDs["bob"]; ok {
		t.Fatal("sessionID was not deleted")
	}
	if _, ok := state.received["session-123"]; ok {
		t.Fatal("received replay set was not deleted")
	}
}

