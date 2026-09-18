package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func encrypt(key []byte, plaintext string) (string, error) {
	return encryptBytes(key, []byte(plaintext))
}

func decrypt(key []byte, ciphertext string) (string, error) {
	plain, err := decryptBytes(key, ciphertext)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func randomAESKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := crand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func encryptBytes(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := crand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

func decryptBytes(key []byte, ciphertext string) ([]byte, error) {
	data, err := base64.RawStdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("short ciphertext")
	}
	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func deriveSessionKey(privateKey *ecdh.PrivateKey, publicKey string) ([]byte, error) {
	keyBytes, err := base64.RawStdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}
	public, err := ecdh.X25519().NewPublicKey(keyBytes)
	if err != nil {
		return nil, err
	}
	shared, err := privateKey.ECDH(public)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(shared)
	return sum[:], nil
}

func encryptOnionLayer(peerPublicKey string, plaintext []byte) (string, error) {
	ephemeral, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		return "", err
	}
	shared, err := deriveSessionKey(ephemeral, peerPublicKey)
	if err != nil {
		return "", err
	}
	ciphertext, err := encryptBytes(shared, plaintext)
	if err != nil {
		return "", err
	}
	packet, err := json.Marshal(onionPacket{
		Ephemeral:  base64.RawStdEncoding.EncodeToString(ephemeral.PublicKey().Bytes()),
		Ciphertext: ciphertext,
	})
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(packet), nil
}

func decryptOnionLayer(state *clientState, encoded string) (onionEnvelope, error) {
	packetBytes, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return onionEnvelope{}, err
	}
	var packet onionPacket
	if err := json.Unmarshal(packetBytes, &packet); err != nil {
		return onionEnvelope{}, err
	}
	state.mu.RLock()
	relayKey := state.relayKey
	state.mu.RUnlock()
	if relayKey == nil {
		return onionEnvelope{}, fmt.Errorf("relay key unavailable")
	}
	shared, err := deriveSessionKey(relayKey, packet.Ephemeral)
	if err != nil {
		return onionEnvelope{}, err
	}
	plaintext, err := decryptBytes(shared, packet.Ciphertext)
	if err != nil {
		return onionEnvelope{}, err
	}
	var envelope onionEnvelope
	if err := json.Unmarshal(plaintext, &envelope); err != nil {
		return onionEnvelope{}, err
	}
	return envelope, nil
}
