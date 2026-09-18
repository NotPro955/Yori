package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

func main() {
	terminal := bufio.NewReader(os.Stdin)

	fmt.Print("Server IP: ")
	serverIP, err := terminal.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	serverIP = strings.TrimSpace(serverIP)
	if serverIP == "" {
		serverIP = "localhost"
	}

	serverAddr := net.JoinHostPort(serverIP, "9000")
	heartbeatAddr := net.JoinHostPort(serverIP, "9500")

	server, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Fatalf("cannot connect to server at %s: %v", serverAddr, err)
	}
	defer server.Close()

	state := &clientState{
		keys:        make(map[string][]byte),
		outgoing:    make(map[string][]byte),
		shared:      make(map[string][]byte),
		sessionIDs:  make(map[string]string),
		sendCounts:  make(map[string]uint64),
		received:    make(map[string]map[uint64]bool),
		peers:       make(map[string]Peer),
		identities:  make(map[string]string),
		keyChanged:  make(map[string]bool),
		peerUpdates: make(chan struct{}, 1),
	}

	fmt.Print("Username: ")
	username, err := terminal.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	username = strings.TrimSpace(username)
	if username == "" {
		log.Fatal("username cannot be empty")
	}
	state.mu.Lock()
	state.username = username
	state.serverAddr = server.RemoteAddr().String()
	state.serverConn = server
	state.mu.Unlock()
	peerAddress, err := startPeerListener(state, server)
	if err != nil {
		log.Fatal("peer listener:", err)
	}
	relayKey, err := relayPublicKey(state)
	if err != nil {
		log.Fatal("relay key:", err)
	}
	identityKey, err := ensureIdentityKey(state)
	if err != nil {
		log.Fatal("identity key:", err)
	}
	identityPublicKey := base64.RawStdEncoding.EncodeToString(identityKey.Public().(ed25519.PublicKey))
	go read_server(server, state)
	go startHeartbeat(heartbeatAddr, username)

	if _, err := fmt.Fprintf(server, "%s\t%s\t%s\t%s\n", username, peerAddress, relayKey, identityPublicKey); err != nil {
		log.Fatal(err)
	}
	if err := send_packet(server, Packet{Type: "users"}); err != nil {
		log.Fatal("peer discovery:", err)
	}

	fmt.Println("Connected as", username)
	fmt.Println("Commands: /users, /key, /session <user> <public-key>, /chat <user>, /quit")
	for {
		fmt.Print("> ")
		message, err := terminal.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(message)
		switch {
		case cmd == "/quit":
			clearAllSessions(state)
			fmt.Fprintln(server, "quit")
			return
		case cmd == "/users":
			if err := send_packet(server, Packet{Type: "users"}); err != nil {
				log.Println("send error:", err)
				return
			}
		case cmd == "/key":
			showPublicKey(state)
		case strings.HasPrefix(cmd, "/fingerprint "):
			showFingerprint(cmd, state)
		case strings.HasPrefix(cmd, "/session "):
			if !startSession(cmd, server, state, username) {
				return
			}
		case strings.HasPrefix(cmd, "/chat "):
			if !startChat(cmd, terminal, server, state, username) {
				return
			}
		default:
			fmt.Println("Unknown command")
		}
	}
}

func showPublicKey(state *clientState) {
	privateKey, err := ensurePrivateKey(state)
	if err != nil {
		log.Println("keygen error:", err)
		return
	}
	fmt.Println("Public key:", base64.RawStdEncoding.EncodeToString(privateKey.PublicKey().Bytes()))
}

func startSession(cmd string, server net.Conn, state *clientState, username string) bool {
	parts := strings.Fields(cmd)
	if len(parts) != 3 {
		fmt.Println("usage: /session <user> <public-key>")
		return true
	}
	state.mu.RLock()
	changed := state.keyChanged[parts[1]]
	state.mu.RUnlock()
	if changed {
		fmt.Println("WARNING: contact identity changed; session blocked")
		return true
	}
	privateKey, err := ensurePrivateKey(state)
	if err != nil {
		fmt.Println("keygen error:", err)
		return true
	}
	shared, err := deriveSessionKey(privateKey, parts[2])
	if err != nil {
		fmt.Println("invalid key:", err)
		return true
	}
	sessionID, err := randomID()
	if err != nil {
		fmt.Println("session id error:", err)
		return true
	}
	identity, err := ensureIdentityKey(state)
	if err != nil {
		fmt.Println("identity key error:", err)
		return true
	}
	ephemeralPublicKey := base64.RawStdEncoding.EncodeToString(privateKey.PublicKey().Bytes())
	offer, err := json.Marshal(sessionEnvelope{Sender: username, PublicKey: ephemeralPublicKey, SessionID: sessionID, Signature: sessionSignature(identity, username, sessionID, ephemeralPublicKey)})
	if err != nil {
		fmt.Println("session offer encoding error:", err)
		return true
	}
	encryptedKey, err := encryptBytesAAD(shared, offer, []byte("yori/session/v1/offer"))
	if err != nil {
		fmt.Println("session key encryption error:", err)
		return true
	}
	state.mu.Lock()
	sendKey, receiveKey, keyErr := deriveDirectionalKeys(shared, sessionID, true)
	if keyErr == nil {
		state.keys[parts[1]] = receiveKey
		state.outgoing[parts[1]] = sendKey
		state.shared[parts[1]] = shared
		state.sessionIDs[parts[1]] = sessionID
	}
	state.mu.Unlock()
	if keyErr != nil {
		fmt.Println("session key derivation error:", keyErr)
		return true
	}
	publicKey := base64.RawStdEncoding.EncodeToString(privateKey.PublicKey().Bytes())
	if err := directSendToUser(state, parts[1], Packet{Type: "session_offer", To: parts[1], Payload: encryptedKey, PublicKey: publicKey}); err != nil {
		log.Println("session direct send error:", err)
		return true
	}
	fmt.Println("session offer sent to", parts[1])
	return true
}

func startChat(cmd string, terminal *bufio.Reader, server net.Conn, state *clientState, username string) bool {
	parts := strings.Fields(cmd)
	if len(parts) != 2 {
		fmt.Println("usage: /chat <user>")
		return true
	}
	state.mu.RLock()
	key, ok := state.outgoing[parts[1]]
	state.mu.RUnlock()
	if !ok {
		fmt.Println("no session key for", parts[1], "- use /session <user> <public-key>")
		return true
	}
	return chat_session(terminal, server, state, username, parts[1], key)
}

func showFingerprint(command string, state *clientState) {
	parts := strings.Fields(command)
	if len(parts) != 2 {
		fmt.Println("usage: /fingerprint <user>")
		return
	}
	state.mu.RLock()
	identity := state.identities[parts[1]]
	changed := state.keyChanged[parts[1]]
	state.mu.RUnlock()
	if identity == "" {
		fmt.Println("identity unavailable")
		return
	}
	status := "UNVERIFIED"
	if changed {
		status = "KEY_CHANGED"
	}
	fingerprint, err := identityFingerprint(identity)
	if err != nil {
		fmt.Println("fingerprint unavailable")
		return
	}
	fmt.Println(parts[1], status, fingerprint)
}
