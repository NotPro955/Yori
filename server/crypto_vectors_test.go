package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type CryptoVectors struct {
	// X25519
	AliceX25519PrivHex string `json:"alice_x25519_priv_hex"`
	AliceX25519PubHex  string `json:"alice_x25519_pub_hex"`
	BobX25519PrivHex   string `json:"bob_x25519_priv_hex"`
	BobX25519PubHex    string `json:"bob_x25519_pub_hex"`
	SharedSecretHex    string `json:"shared_secret_hex"`

	// HKDF directional keys
	SaltHex          string `json:"salt_hex"`
	SendKeyHex       string `json:"send_key_hex"`       // info: "yori-send-v1"
	ReceiveKeyHex    string `json:"receive_key_hex"`    // info: "yori-recv-v1"
	PreSessionKeyHex string `json:"presession_key_hex"` // info: "yori-presession-v1"

	// AES-256-GCM
	AesKeyHex          string `json:"aes_key_hex"`
	AesNonceHex        string `json:"aes_nonce_hex"`
	Plaintext          string `json:"plaintext"`
	PaddedPlaintextHex string `json:"padded_plaintext_hex"`
	AADMessage         string `json:"aad_message"`
	CiphertextHex      string `json:"ciphertext_hex"`

	// Ed25519 Identity
	Ed25519SeedHex       string `json:"ed25519_seed_hex"`
	Ed25519PubHex        string `json:"ed25519_pub_hex"`
	Ed25519SignatureHex  string `json:"ed25519_sig_hex"`
	Ed25519SignedMessage string `json:"ed25519_msg"`
	FingerprintHex       string `json:"fingerprint_hex"`
}

func pad256Bytes(data []byte) []byte {
	target := 256
	for target <= len(data) {
		target += 256
	}
	padded := make([]byte, target)
	copy(padded, data)
	padded[len(data)] = 0x80
	return padded
}

func generateVectors() (CryptoVectors, error) {
	// Deterministic 32-byte private keys
	alicePrivBytes := make([]byte, 32)
	for i := range alicePrivBytes {
		alicePrivBytes[i] = byte(i + 1)
	}
	bobPrivBytes := make([]byte, 32)
	for i := range bobPrivBytes {
		bobPrivBytes[i] = byte(i + 0x20)
	}

	alicePriv, err := ecdh.X25519().NewPrivateKey(alicePrivBytes)
	if err != nil {
		return CryptoVectors{}, err
	}
	bobPriv, err := ecdh.X25519().NewPrivateKey(bobPrivBytes)
	if err != nil {
		return CryptoVectors{}, err
	}

	alicePub := alicePriv.PublicKey().Bytes()
	bobPub := bobPriv.PublicKey().Bytes()

	sharedSecret, err := alicePriv.ECDH(bobPriv.PublicKey())
	if err != nil {
		return CryptoVectors{}, err
	}

	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i + 0x40)
	}

	sendKey, err := hkdf.Key(sha256.New, sharedSecret, salt, "yori-send-v1", 32)
	if err != nil {
		return CryptoVectors{}, err
	}
	recvKey, err := hkdf.Key(sha256.New, sharedSecret, salt, "yori-recv-v1", 32)
	if err != nil {
		return CryptoVectors{}, err
	}
	preSessionKey, err := hkdf.Key(sha256.New, sharedSecret, salt, "yori-presession-v1", 32)
	if err != nil {
		return CryptoVectors{}, err
	}

	// AES-256-GCM test
	aesKey := sendKey
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i + 0x50)
	}
	plaintext := "Hello Yori Web Crypto!"
	padded := pad256Bytes([]byte(plaintext))
	aad := "yori/message/v1|test-session-123"

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return CryptoVectors{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return CryptoVectors{}, err
	}
	sealed := gcm.Seal(nil, nonce, padded, []byte(aad))

	// Ed25519
	edSeed := make([]byte, 32)
	for i := range edSeed {
		edSeed[i] = byte(i + 0x80)
	}
	edPriv := ed25519.NewKeyFromSeed(edSeed)
	edPub := edPriv.Public().(ed25519.PublicKey)
	signedMsg := "yori/session/v1|alice|test-session-123|" + hex.EncodeToString(alicePub)
	sig := ed25519.Sign(edPriv, []byte(signedMsg))

	fpSum := sha256.Sum256(edPub)
	fpHex := hex.EncodeToString(fpSum[:])

	vectors := CryptoVectors{
		AliceX25519PrivHex:   hex.EncodeToString(alicePrivBytes),
		AliceX25519PubHex:    hex.EncodeToString(alicePub),
		BobX25519PrivHex:     hex.EncodeToString(bobPrivBytes),
		BobX25519PubHex:      hex.EncodeToString(bobPub),
		SharedSecretHex:      hex.EncodeToString(sharedSecret),
		SaltHex:              hex.EncodeToString(salt),
		SendKeyHex:           hex.EncodeToString(sendKey),
		ReceiveKeyHex:        hex.EncodeToString(recvKey),
		PreSessionKeyHex:     hex.EncodeToString(preSessionKey),
		AesKeyHex:            hex.EncodeToString(aesKey),
		AesNonceHex:          hex.EncodeToString(nonce),
		Plaintext:            plaintext,
		PaddedPlaintextHex:   hex.EncodeToString(padded),
		AADMessage:           aad,
		CiphertextHex:        hex.EncodeToString(sealed),
		Ed25519SeedHex:       hex.EncodeToString(edSeed),
		Ed25519PubHex:        hex.EncodeToString(edPub),
		Ed25519SignatureHex:  hex.EncodeToString(sig),
		Ed25519SignedMessage: signedMsg,
		FingerprintHex:       fpHex,
	}

	return vectors, nil
}

func TestGenerateAndVerifyCryptoVectors(t *testing.T) {
	v, err := generateVectors()
	if err != nil {
		t.Fatalf("failed to generate vectors: %v", err)
	}

	// Verify self-consistency in Go
	block, err := aes.NewCipher(mustHex(t, v.AesKeyHex))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := gcm.Open(nil, mustHex(t, v.AesNonceHex), mustHex(t, v.CiphertextHex), []byte(v.AADMessage))
	if err != nil {
		t.Fatalf("failed to decrypt ciphertext: %v", err)
	}
	if hex.EncodeToString(decrypted) != v.PaddedPlaintextHex {
		t.Fatalf("decrypted padded mismatch")
	}

	// Verify Ed25519
	if !ed25519.Verify(mustHex(t, v.Ed25519PubHex), []byte(v.Ed25519SignedMessage), mustHex(t, v.Ed25519SignatureHex)) {
		t.Fatalf("ed25519 verification failed in Go")
	}

	// Save to server/web/vectors.json so JS can load and test it
	webDir := filepath.Join(".", "web")
	_ = os.MkdirAll(webDir, 0755)
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(webDir, "vectors.json"), data, 0644); err != nil {
		t.Fatalf("failed to write vectors.json: %v", err)
	}
	t.Logf("Crypto test vectors generated and verified successfully in Go")
}

func mustHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
