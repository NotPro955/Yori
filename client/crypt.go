package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func encrypt(key []byte, plaintext string) (string, error) {
	return encryptBytesAAD(key, []byte(plaintext), nil)
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
	return encryptBytesAAD(key, plaintext, nil)
}

func encryptBytesAAD(key, plaintext, aad []byte) (string, error) {
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
	sealed := gcm.Seal(nonce, nonce, plaintext, aad)
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

func decryptBytes(key []byte, ciphertext string) ([]byte, error) {
	return decryptBytesAAD(key, ciphertext, nil)
}

func decryptBytesAAD(key []byte, ciphertext string, aad []byte) ([]byte, error) {
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
	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], aad)
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
	return hkdf.Key(sha256.New, shared, nil, "yori/session/v1", 32)
}

func deriveDirectionalKeys(shared []byte, sessionID string, initiator bool) ([]byte, []byte, error) {
	send, err := hkdf.Key(sha256.New, shared, nil, "yori/session/v1/"+sessionID+"/a-to-b", 32)
	if err != nil {
		return nil, nil, err
	}
	receive, err := hkdf.Key(sha256.New, shared, nil, "yori/session/v1/"+sessionID+"/b-to-a", 32)
	if err != nil {
		return nil, nil, err
	}
	if initiator {
		return send, receive, nil
	}
	return receive, send, nil
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
	ciphertext, err := encryptBytesAAD(shared, plaintext, []byte("yori/onion/v1"))
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
	plaintext, err := decryptBytesAAD(shared, packet.Ciphertext, []byte("yori/onion/v1"))
	if err != nil {
		return onionEnvelope{}, err
	}
	var envelope onionEnvelope
	if err := json.Unmarshal(plaintext, &envelope); err != nil {
		return onionEnvelope{}, err
	}
	return envelope, nil
}

func ensureIdentityKey(state *clientState) (ed25519.PrivateKey, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.identityKey) == 0 {
		publicKey, privateKey, err := ed25519.GenerateKey(crand.Reader)
		if err != nil {
			return nil, err
		}
		_ = publicKey
		state.identityKey = privateKey
	}
	return append(ed25519.PrivateKey(nil), state.identityKey...), nil
}

func sessionSignature(identity ed25519.PrivateKey, sender, sessionID, publicKey string) string {
	data := []byte("yori/session/v1|" + sender + "|" + sessionID + "|" + publicKey)
	return base64.RawStdEncoding.EncodeToString(ed25519.Sign(identity, data))
}

func verifySessionSignature(identity, sender, sessionID, publicKey, signature string) bool {
	key, err := base64.RawStdEncoding.DecodeString(identity)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.RawStdEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	data := []byte("yori/session/v1|" + sender + "|" + sessionID + "|" + publicKey)
	return ed25519.Verify(ed25519.PublicKey(key), data, sig)
}

func identityFingerprint(identity string) (string, error) {
	key, err := base64.RawStdEncoding.DecodeString(identity)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid identity key")
	}
	sum := sha256.Sum256(key)
	encoded := base64.RawStdEncoding.EncodeToString(sum[:])
	return encoded[:16], nil
}
