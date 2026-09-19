package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockCoordinationServer mimics the Yori central server for e2e testing.
type mockCoordinationServer struct {
	ln          net.Listener
	mu          sync.Mutex
	conns       map[string]net.Conn
	peerRecords map[string]Peer
}

func startMockServer(t *testing.T) (*mockCoordinationServer, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &mockCoordinationServer{
		ln:          ln,
		conns:       make(map[string]net.Conn),
		peerRecords: make(map[string]Peer),
	}
	go s.acceptLoop()
	cleanup := func() {
		_ = ln.Close()
		s.mu.Lock()
		for _, c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
	}
	return s, cleanup
}

func (s *mockCoordinationServer) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleClient(conn)
	}
}

func (s *mockCoordinationServer) handleClient(conn net.Conn) {
	reader := bufio.NewReader(conn)
	reg, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return
	}
	parts := strings.SplitN(strings.TrimSpace(reg), "\t", 5)
	if len(parts) < 4 {
		conn.Close()
		return
	}
	username, addr, relayKey, identity := parts[0], parts[1], parts[2], parts[3]
	preSession := ""
	if len(parts) >= 5 {
		preSession = parts[4]
	}

	s.mu.Lock()
	s.conns[username] = conn
	s.peerRecords[username] = Peer{Username: username, Address: addr, PublicKey: relayKey, Identity: identity, PreSessionKey: preSession}
	s.mu.Unlock()

	s.broadcastUsers()

	defer func() {
		s.mu.Lock()
		delete(s.conns, username)
		delete(s.peerRecords, username)
		s.mu.Unlock()
		conn.Close()
		s.broadcastUsers()
	}()

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		var pkt Packet
		if err := json.Unmarshal([]byte(line), &pkt); err != nil {
			continue
		}
		if pkt.Type == "deliver" {
			s.mu.Lock()
			dst, ok := s.conns[pkt.To]
			s.mu.Unlock()
			if ok && dst != nil {
				deliveryType := pkt.OriginalType
				if deliveryType == "send" {
					deliveryType = "message"
				}
				outPkt := Packet{
					Version:   protocolVersion,
					ID:        pkt.ID,
					Type:      deliveryType,
					Payload:   pkt.Payload,
					PublicKey: pkt.PublicKey,
				}
				outBytes, _ := json.Marshal(outPkt)
				_ = dst.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_, _ = dst.Write(append(outBytes, '\n'))
			}
		}
	}
}

func (s *mockCoordinationServer) broadcastUsers() {
	s.mu.Lock()
	peers := make([]Peer, 0, len(s.peerRecords))
	for _, p := range s.peerRecords {
		peers = append(peers, p)
	}
	conns := make(map[string]net.Conn, len(s.conns))
	for u, c := range s.conns {
		conns[u] = c
	}
	s.mu.Unlock()

	for u, conn := range conns {
		filtered := make([]Peer, 0, len(peers))
		for _, p := range peers {
			if p.Username != u {
				filtered = append(filtered, p)
			}
		}
		pkt := Packet{
			Version: protocolVersion,
			ID:      "broadcast",
			Type:    "users",
			Users:   filtered,
		}
		bytes, _ := json.Marshal(pkt)
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write(append(bytes, '\n'))
	}
}

func setupTestClient(t *testing.T, username, serverAddr string) (*clientState, net.Conn, func()) {
	return setupTestClientWithIdentity(t, username, serverAddr, nil)
}

func setupTestClientWithIdentity(t *testing.T, username, serverAddr string, existingIdentity ed25519.PrivateKey) (*clientState, net.Conn, func()) {
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}

	state := &clientState{
		username:    username,
		serverAddr:  serverAddr,
		serverConn:  conn,
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
		done:        make(chan struct{}),
	}
	if len(existingIdentity) > 0 {
		state.identityKey = append(ed25519.PrivateKey(nil), existingIdentity...)
	}

	peerAddress, err := startPeerListener(state, conn)
	if err != nil {
		t.Fatal(err)
	}
	relayKey, err := relayPublicKey(state)
	if err != nil {
		t.Fatal(err)
	}
	identityKey, err := ensureIdentityKey(state)
	if err != nil {
		t.Fatal(err)
	}
	identityPublicKey := base64.RawStdEncoding.EncodeToString(identityKey.Public().(ed25519.PublicKey))

	preSessionKey, err := ensurePreSessionKey(state)
	if err != nil {
		t.Fatal(err)
	}
	preSessionPublicKey := base64.RawStdEncoding.EncodeToString(preSessionKey.PublicKey().Bytes())

	go read_server(conn, state)

	_, err = fmt.Fprintf(conn, "%s\t%s\t%s\t%s\t%s\n", username, peerAddress, relayKey, identityPublicKey, preSessionPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		_ = conn.Close()
		clearAllSessions(state)
	}
	return state, conn, cleanup
}

func TestCriticalDemoPathEndToEnd(t *testing.T) {
	// Step 1: Start central coordination server
	srv, srvCleanup := startMockServer(t)
	defer srvCleanup()

	// Step 2: Start 4 clients (Alice, Bob, Relay1, Relay2)
	stateR1, connR1, cleanupR1 := setupTestClient(t, "relay1", srv.ln.Addr().String())
	defer cleanupR1()
	_ = stateR1
	_ = connR1

	stateR2, connR2, cleanupR2 := setupTestClient(t, "relay2", srv.ln.Addr().String())
	defer cleanupR2()
	_ = stateR2
	_ = connR2

	stateBob, connBob, cleanupBob := setupTestClient(t, "bob", srv.ln.Addr().String())
	defer cleanupBob()
	_ = connBob

	stateAlice, connAlice, cleanupAlice := setupTestClient(t, "alice", srv.ln.Addr().String())
	defer cleanupAlice()
	_ = connAlice

	// Step 3: Wait for peer discovery to populate on Alice and Bob
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		stateAlice.mu.RLock()
		alicePeers := len(stateAlice.peers)
		stateAlice.mu.RUnlock()

		stateBob.mu.RLock()
		bobPeers := len(stateBob.peers)
		stateBob.mu.RUnlock()

		if alicePeers >= 3 && bobPeers >= 3 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	stateAlice.mu.RLock()
	if len(stateAlice.peers) < 3 {
		t.Fatalf("Alice discovered only %d peers, expected 3", len(stateAlice.peers))
	}
	stateAlice.mu.RUnlock()

	// Step 4: Bob generates his ephemeral X25519 key and shares public key with Alice
	bobPriv, err := ensurePrivateKey(stateBob)
	if err != nil {
		t.Fatal(err)
	}
	bobPubStr := base64.RawStdEncoding.EncodeToString(bobPriv.PublicKey().Bytes())

	// Step 5: Alice starts session with Bob using /session command logic
	// Alice initiates session offer routed through Alice -> Relay1 -> Relay2 -> Bob
	cmd := fmt.Sprintf("/session bob %s", bobPubStr)
	success := startSession(cmd, connAlice, stateAlice, "alice")
	if !success {
		t.Fatal("Alice startSession returned false")
	}

	// Step 6: Wait for Bob and Alice to establish session through onion route
	sessionDeadline := time.Now().Add(5 * time.Second)
	established := false
	for time.Now().Before(sessionDeadline) {
		stateAlice.mu.RLock()
		_, aliceHasKey := stateAlice.outgoing["bob"]
		stateAlice.mu.RUnlock()

		stateBob.mu.RLock()
		_, bobHasKey := stateBob.outgoing["alice"]
		stateBob.mu.RUnlock()

		if aliceHasKey && bobHasKey {
			established = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !established {
		t.Fatal("Session was not established between Alice and Bob within deadline")
	}

	// Step 7: Alice sends an encrypted chat message to Bob via multi-hop onion route
	stateAlice.mu.Lock()
	sessionID := stateAlice.sessionIDs["bob"]
	stateAlice.sendCounts["bob"]++
	counter := stateAlice.sendCounts["bob"]
	sendKey := stateAlice.outgoing["bob"]
	stateAlice.mu.Unlock()

	messageID, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	testMessage := "Hello Bob, this is Alice via 2-hop onion!"
	envelope := chatEnvelope{
		Version:   protocolVersion,
		MessageID: messageID,
		SessionID: sessionID,
		Counter:   counter,
		Sender:    "alice",
		Body:      testMessage,
	}
	envelopeBytes, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes = pad256(envelopeBytes)
	ciphertext, err := encryptBytesAAD(sendKey, envelopeBytes, []byte("yori/message/v1|"+sessionID))
	if err != nil {
		t.Fatal(err)
	}

	// Send through Alice's onion routing
	err = directSendToUser(stateAlice, "bob", Packet{Type: "send", To: "bob", Payload: ciphertext})
	if err != nil {
		t.Fatalf("Alice directSendToUser failed: %v", err)
	}

	// Step 8: Verify Bob receives and decrypts the message
	msgDeadline := time.Now().Add(5 * time.Second)
	received := false
	for time.Now().Before(msgDeadline) {
		stateBob.mu.RLock()
		seen := stateBob.received[sessionID]
		if seen != nil && seen[counter] {
			received = true
			stateBob.mu.RUnlock()
			break
		}
		stateBob.mu.RUnlock()
		time.Sleep(50 * time.Millisecond)
	}

	if !received {
		t.Fatal("Bob did not receive Alice's message through the onion circuit")
	}

	// Step 9: Verify Replay attack protection (re-submitting same ciphertext fails)
	if _, err := decryptChatEnvelope(stateBob, ciphertext); err == nil {
		t.Fatal("Bob accepted replayed message ciphertext with duplicate counter")
	}

	// Step 10: Verify Bob can reply back to Alice
	stateBob.mu.Lock()
	bobSessionID := stateBob.sessionIDs["alice"]
	stateBob.sendCounts["alice"]++
	bobCounter := stateBob.sendCounts["alice"]
	bobSendKey := stateBob.outgoing["alice"]
	stateBob.mu.Unlock()

	bobReplyMsg := "Hello Alice, message received loud and clear!"
	bobEnvelope := chatEnvelope{
		Version:   protocolVersion,
		MessageID: "reply-1",
		SessionID: bobSessionID,
		Counter:   bobCounter,
		Sender:    "bob",
		Body:      bobReplyMsg,
	}
	bobEnvBytes, _ := json.Marshal(bobEnvelope)
	bobEnvBytes = pad256(bobEnvBytes)
	bobCiphertext, err := encryptBytesAAD(bobSendKey, bobEnvBytes, []byte("yori/message/v1|"+bobSessionID))
	if err != nil {
		t.Fatal(err)
	}

	err = directSendToUser(stateBob, "alice", Packet{Type: "send", To: "alice", Payload: bobCiphertext})
	if err != nil {
		t.Fatalf("Bob directSendToUser failed: %v", err)
	}

	// Verify Alice receives Bob's reply
	aliceReplyDeadline := time.Now().Add(5 * time.Second)
	replyReceived := false
	for time.Now().Before(aliceReplyDeadline) {
		stateAlice.mu.RLock()
		seen := stateAlice.received[sessionID]
		if seen != nil && seen[bobCounter] {
			replyReceived = true
			stateAlice.mu.RUnlock()
			break
		}
		stateAlice.mu.RUnlock()
		time.Sleep(50 * time.Millisecond)
	}

	if !replyReceived {
		t.Fatal("Alice did not receive Bob's reply through the onion circuit")
	}

	// Step 11: Test Session Cleanup on /back
	clearSession(stateAlice, "bob")
	stateAlice.mu.RLock()
	if _, ok := stateAlice.outgoing["bob"]; ok {
		t.Fatal("Alice outgoing key still exists after session cleanup")
	}
	if _, ok := stateAlice.keys["bob"]; ok {
		t.Fatal("Alice receive key still exists after session cleanup")
	}
	stateAlice.mu.RUnlock()
}

func TestReconnectFlow(t *testing.T) {
	// Step 1: Start central coordination server
	srv, srvCleanup := startMockServer(t)
	defer srvCleanup()

	// Step 2: Start Relays, Alice, and Bob
	_, _, cleanupR1 := setupTestClient(t, "relay1", srv.ln.Addr().String())
	defer cleanupR1()

	_, _, cleanupR2 := setupTestClient(t, "relay2", srv.ln.Addr().String())
	defer cleanupR2()

	stateBob, connBob, cleanupBob := setupTestClient(t, "bob", srv.ln.Addr().String())
	defer cleanupBob()
	_ = connBob

	stateAlice, connAlice, cleanupAlice := setupTestClient(t, "alice", srv.ln.Addr().String())
	_ = connAlice

	aliceIdent, _ := ensureIdentityKey(stateAlice)

	// Wait for discovery
	time.Sleep(200 * time.Millisecond)

	// Alice disconnects
	cleanupAlice()

	// Wait for disconnect broadcast
	time.Sleep(200 * time.Millisecond)

	// Alice reconnects with her existing identity key
	stateAlice2, connAlice2, cleanupAlice2 := setupTestClientWithIdentity(t, "alice", srv.ln.Addr().String(), aliceIdent)
	defer cleanupAlice2()
	_ = connAlice2

	// Wait for discovery
	time.Sleep(300 * time.Millisecond)

	stateAlice2.mu.RLock()
	peersAlice := len(stateAlice2.peers)
	stateAlice2.mu.RUnlock()

	stateBob.mu.RLock()
	peersBob := len(stateBob.peers)
	stateBob.mu.RUnlock()

	if peersAlice < 3 || peersBob < 3 {
		t.Fatalf("Peers not discovered after reconnect: Alice has %d, Bob has %d", peersAlice, peersBob)
	}

	// Re-establish session
	bobPriv, err := ensurePrivateKey(stateBob)
	if err != nil {
		t.Fatal(err)
	}
	bobPubStr := base64.RawStdEncoding.EncodeToString(bobPriv.PublicKey().Bytes())

	cmd := fmt.Sprintf("/session bob %s", bobPubStr)
	if !startSession(cmd, connAlice2, stateAlice2, "alice") {
		t.Fatal("Alice failed to initiate session after reconnect")
	}

	// Wait for session establishment
	deadline := time.Now().Add(5 * time.Second)
	established := false
	for time.Now().Before(deadline) {
		stateAlice2.mu.RLock()
		_, aHas := stateAlice2.outgoing["bob"]
		stateAlice2.mu.RUnlock()

		stateBob.mu.RLock()
		_, bHas := stateBob.outgoing["alice"]
		stateBob.mu.RUnlock()

		if aHas && bHas {
			established = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !established {
		t.Fatal("Session failed to establish after reconnect")
	}

	// Alice sends message after reconnect
	stateAlice2.mu.Lock()
	sessionID := stateAlice2.sessionIDs["bob"]
	stateAlice2.sendCounts["bob"]++
	counter := stateAlice2.sendCounts["bob"]
	sendKey := stateAlice2.outgoing["bob"]
	stateAlice2.mu.Unlock()

	envelope := chatEnvelope{
		Version:   protocolVersion,
		MessageID: "msg-reconnect-1",
		SessionID: sessionID,
		Counter:   counter,
		Sender:    "alice",
		Body:      "Chat works again after reconnect!",
	}
	envBytes, _ := json.Marshal(envelope)
	envBytes = pad256(envBytes)
	ciphertext, _ := encryptBytesAAD(sendKey, envBytes, []byte("yori/message/v1|"+sessionID))

	err = directSendToUser(stateAlice2, "bob", Packet{Type: "send", To: "bob", Payload: ciphertext})
	if err != nil {
		t.Fatalf("directSendToUser failed after reconnect: %v", err)
	}

	// Verify Bob received message
	msgDeadline := time.Now().Add(5 * time.Second)
	received := false
	for time.Now().Before(msgDeadline) {
		stateBob.mu.RLock()
		seen := stateBob.received[sessionID]
		if seen != nil && seen[counter] {
			received = true
			stateBob.mu.RUnlock()
			break
		}
		stateBob.mu.RUnlock()
		time.Sleep(50 * time.Millisecond)
	}

	if !received {
		t.Fatal("Bob did not receive message after reconnect")
	}
}

func TestRelayFailureCleanHandling(t *testing.T) {
	// Relay failure: when an onion relay is unreachable / disappears,
	// directSend fails cleanly within bounded timeout without hanging or crashing.
	stateAlice := &clientState{
		username:   "alice",
		serverAddr: "127.0.0.1:9000",
		peers: map[string]Peer{
			"bob":    {Username: "bob", Address: "127.0.0.1:9001", PublicKey: "bob-key"},
			"relay1": {Username: "relay1", Address: "127.0.0.1:1", PublicKey: "relay1-key"},
			"relay2": {Username: "relay2", Address: "127.0.0.1:2", PublicKey: "relay2-key"},
		},
	}

	start := time.Now()
	err := directSendToUser(stateAlice, "bob", Packet{Type: "send", To: "bob", Payload: "test-payload"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected send to fail when relays are unreachable")
	}
	if elapsed > 15*time.Second {
		t.Fatalf("relay failure took too long to fail: %v", elapsed)
	}

	stateAlice.mu.RLock()
	username := stateAlice.username
	stateAlice.mu.RUnlock()
	if username != "alice" {
		t.Fatal("client state corrupted after relay failure")
	}
}

func TestTwoClientDirectDeliveryFallback(t *testing.T) {
	srv, srvCleanup := startMockServer(t)
	defer srvCleanup()

	// Only 2 clients: Alice and Bob (no relays)
	stateBob, connBob, cleanupBob := setupTestClient(t, "bob", srv.ln.Addr().String())
	defer cleanupBob()
	_ = connBob

	stateAlice, connAlice, cleanupAlice := setupTestClient(t, "alice", srv.ln.Addr().String())
	defer cleanupAlice()
	_ = connAlice

	// Wait for discovery
	time.Sleep(200 * time.Millisecond)

	// Bob shares public key
	bobPriv, err := ensurePrivateKey(stateBob)
	if err != nil {
		t.Fatal(err)
	}
	bobPubStr := base64.RawStdEncoding.EncodeToString(bobPriv.PublicKey().Bytes())

	// Alice initiates session offer with Bob
	cmd := fmt.Sprintf("/session bob %s", bobPubStr)
	if !startSession(cmd, connAlice, stateAlice, "alice") {
		t.Fatal("startSession failed in 2-client mode")
	}

	// Wait for session to establish via server delivery fallback
	deadline := time.Now().Add(5 * time.Second)
	established := false
	for time.Now().Before(deadline) {
		stateAlice.mu.RLock()
		_, aHas := stateAlice.outgoing["bob"]
		stateAlice.mu.RUnlock()

		stateBob.mu.RLock()
		_, bHas := stateBob.outgoing["alice"]
		stateBob.mu.RUnlock()

		if aHas && bHas {
			established = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !established {
		t.Fatal("Session failed to establish between 2 clients via server fallback")
	}

	// Alice sends message to Bob
	stateAlice.mu.Lock()
	sessionID := stateAlice.sessionIDs["bob"]
	stateAlice.sendCounts["bob"]++
	counter := stateAlice.sendCounts["bob"]
	sendKey := stateAlice.outgoing["bob"]
	stateAlice.mu.Unlock()

	envelope := chatEnvelope{
		Version:   protocolVersion,
		MessageID: "msg-2client-1",
		SessionID: sessionID,
		Counter:   counter,
		Sender:    "alice",
		Body:      "Hello directly from Alice!",
	}
	envBytes, _ := json.Marshal(envelope)
	envBytes = pad256(envBytes)
	ciphertext, _ := encryptBytesAAD(sendKey, envBytes, []byte("yori/message/v1|"+sessionID))

	err = directSendToUser(stateAlice, "bob", Packet{Type: "send", To: "bob", Payload: ciphertext})
	if err != nil {
		t.Fatalf("directSendToUser failed in 2-client mode: %v", err)
	}

	// Verify Bob received message
	msgDeadline := time.Now().Add(5 * time.Second)
	received := false
	for time.Now().Before(msgDeadline) {
		stateBob.mu.RLock()
		seen := stateBob.received[sessionID]
		if seen != nil && seen[counter] {
			received = true
			stateBob.mu.RUnlock()
			break
		}
		stateBob.mu.RUnlock()
		time.Sleep(50 * time.Millisecond)
	}

	if !received {
		t.Fatal("Bob did not receive Alice's message in 2-client fallback mode")
	}
}
