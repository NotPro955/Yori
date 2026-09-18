package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/base64"
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
