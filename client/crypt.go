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
		_, privateKey, err := ed25519.GenerateKey(crand.Reader)
		if err != nil {
			return nil, err
		}
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

func pad256(data []byte) []byte {
	target := 256
	for target <= len(data) {
		target += 256
	}
	padded := make([]byte, target)
	copy(padded, data)
	padded[len(data)] = 0x80
	return padded
}

func unpad256(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%256 != 0 {
		return nil, fmt.Errorf("invalid padded size")
	}
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == 0x80 {
			return data[:i], nil
		}
		if data[i] != 0x00 {
			break
		}
	}
	return nil, fmt.Errorf("invalid padding")
}

// ensurePreSessionKey generates or returns the client's X25519 pre-session key.
// This key is used for sealed-sender session_offer encryption so the server
// never sees the packet type in the outer delivery envelope.
func ensurePreSessionKey(state *clientState) (*ecdh.PrivateKey, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.preSessionKey == nil {
		key, err := ecdh.X25519().GenerateKey(crand.Reader)
		if err != nil {
			return nil, err
		}
		state.preSessionKey = key
	}
	return state.preSessionKey, nil
}

// derivePreSessionKey derives a 32-byte AES key from an ephemeral X25519
// shared secret using HKDF-SHA256 with the domain separator "yori-presession-v1".
func derivePreSessionKey(sharedSecret []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, sharedSecret, nil, "yori-presession-v1", 32)
}

// encryptPreSession encrypts plaintext using the recipient's published pre-session
// X25519 public key (base64-encoded). Returns the base64 ciphertext and the
// base64 ephemeral public key that must be sent alongside so the recipient can
// derive the same shared secret.
func encryptPreSession(recipientPubKeyB64 string, plaintext []byte) (ciphertext string, ephPub string, err error) {
	recipientKeyBytes, err := base64.RawStdEncoding.DecodeString(recipientPubKeyB64)
	if err != nil {
		return "", "", fmt.Errorf("invalid pre-session public key: %w", err)
	}
	recipientPub, err := ecdh.X25519().NewPublicKey(recipientKeyBytes)
	if err != nil {
		return "", "", fmt.Errorf("parse pre-session public key: %w", err)
	}
	ephemeral, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		return "", "", err
	}
	shared, err := ephemeral.ECDH(recipientPub)
	if err != nil {
		return "", "", err
	}
	aesKey, err := derivePreSessionKey(shared)
	if err != nil {
		return "", "", err
	}
	ct, err := encryptBytesAAD(aesKey, plaintext, []byte("yori-presession-v1"))
	if err != nil {
		return "", "", err
	}
	return ct, base64.RawStdEncoding.EncodeToString(ephemeral.PublicKey().Bytes()), nil
}

// decryptPreSessionWithKey decrypts a payload produced by encryptPreSession
// using the provided X25519 private key. The ephPubB64 is the sender's
// ephemeral public key (from the packet's PublicKey field).
func decryptPreSessionWithKey(privKey *ecdh.PrivateKey, ephPubB64 string, ciphertextB64 string) ([]byte, error) {
	ephPubBytes, err := base64.RawStdEncoding.DecodeString(ephPubB64)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}
	ephPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}
	shared, err := privKey.ECDH(ephPub)
	if err != nil {
		return nil, err
	}
	aesKey, err := derivePreSessionKey(shared)
	if err != nil {
		return nil, err
	}
	return decryptBytesAAD(aesKey, ciphertextB64, []byte("yori-presession-v1"))
}
