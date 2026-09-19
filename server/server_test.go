package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func startTestServer(t *testing.T) (*Server, string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ser := &Server{
		server_addr: ln.Addr().String(),
		listener:    ln,
		clients:     make(map[net.Addr]string),
		connections: make(map[string]net.Conn),
		peerAddrs:   make(map[string]string),
		peerKeys:    make(map[string]string),
		identities:     make(map[string]string),
		preSessionKeys: make(map[string]string),
		heartbeats:     make(map[net.Addr]string),
	}
	go ser.accept()
	cleanup := func() {
		_ = ln.Close()
		ser.state_mu.Lock()
		for _, c := range ser.connections {
			_ = c.Close()
		}
		ser.state_mu.Unlock()
	}
	return ser, ln.Addr().String(), cleanup
}

func TestServerPacketValidation(t *testing.T) {
	valid := Packet{
		Version: protocolVersion,
		ID:      "test-id",
		Type:    "users",
		TTL:     defaultTTL,
	}
	if err := validatePacket(valid); err != nil {
		t.Fatalf("valid packet failed validation: %v", err)
	}

	invalidVersion := valid
	invalidVersion.Version = 99
	if err := validatePacket(invalidVersion); err == nil {
		t.Fatal("invalid version was accepted")
	}

	invalidType := valid
	invalidType.Type = "unknown_type"
	if err := validatePacket(invalidType); err == nil {
		t.Fatal("unknown packet type was accepted")
	}

	oversizedPayload := valid
	oversizedPayload.Payload = string(make([]byte, maxPayloadBytes+1))
	if err := validatePacket(oversizedPayload); err == nil {
		t.Fatal("oversized payload was accepted")
	}

	oversizedTo := valid
	oversizedTo.To = strings.Repeat("a", maxUsernameBytes+1)
	if err := validatePacket(oversizedTo); err == nil {
		t.Fatal("oversized To field was accepted")
	}

	invalidTTL := valid
	invalidTTL.TTL = maxTTL + 1
	if err := validatePacket(invalidTTL); err == nil {
		t.Fatal("TTL > maxTTL was accepted")
	}
}

func TestUsernameValidation(t *testing.T) {
	valid := []string{"alice", "bob_123", "user-name", "ABC_xyz-99"}
	for _, u := range valid {
		if !validUsername(u) {
			t.Fatalf("expected valid username: %s", u)
		}
	}

	invalid := []string{"", "a", "ab", strings.Repeat("a", 33), "user@name", "user name", "user$"}
	for _, u := range invalid {
		if validUsername(u) {
			t.Fatalf("expected invalid username: %s", u)
		}
	}
}

func TestRegistrationAndDuplicateRejection(t *testing.T) {
	_, addr, cleanup := startTestServer(t)
	defer cleanup()

	// Connect Alice
	aliceConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer aliceConn.Close()

	if _, err := fmt.Fprintf(aliceConn, "alice\t127.0.0.1:4001\tpubkeyA\tidentA\n"); err != nil {
		t.Fatal(err)
	}
	aliceReader := bufio.NewReader(aliceConn)
	// Alice should receive the broadcast users packet
	line, err := aliceReader.ReadString('\n')
	if err != nil {
		t.Fatalf("alice failed to receive broadcast: %v", err)
	}
	var pkt Packet
	if err := json.Unmarshal([]byte(line), &pkt); err != nil || pkt.Type != "users" {
		t.Fatalf("expected users packet, got %s", line)
	}

	// Connect second client claiming "alice"
	duplicateConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer duplicateConn.Close()

	if _, err := fmt.Fprintf(duplicateConn, "alice\t127.0.0.1:4002\tpubkeyA2\tidentA2\n"); err != nil {
		t.Fatal(err)
	}
	dupReader := bufio.NewReader(duplicateConn)
	dupLine, err := dupReader.ReadString('\n')
	if err != nil {
		t.Fatalf("duplicate connection failed to read response: %v", err)
	}
	var dupPkt Packet
	if err := json.Unmarshal([]byte(dupLine), &dupPkt); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if dupPkt.Type != "error" || !strings.Contains(dupPkt.Payload, "already taken") {
		t.Fatalf("expected error packet for duplicate username, got %+v", dupPkt)
	}
}

func TestDeliverRouting(t *testing.T) {
	_, addr, cleanup := startTestServer(t)
	defer cleanup()

	// Connect Alice
	aliceConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer aliceConn.Close()
	if _, err := fmt.Fprintf(aliceConn, "alice\t127.0.0.1:4001\tpubkeyA\tidentA\n"); err != nil {
		t.Fatal(err)
	}
	aliceReader := bufio.NewReader(aliceConn)
	_, _ = aliceReader.ReadString('\n') // consume broadcast

	// Connect Bob
	bobConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer bobConn.Close()
	if _, err := fmt.Fprintf(bobConn, "bob\t127.0.0.1:4002\tpubkeyB\tidentB\n"); err != nil {
		t.Fatal(err)
	}
	bobReader := bufio.NewReader(bobConn)
	_, _ = bobReader.ReadString('\n')   // consume bob's broadcast
	_, _ = aliceReader.ReadString('\n') // consume alice's update broadcast

	// Alice sends deliver packet for Bob
	deliverPkt := Packet{
		Version:      protocolVersion,
		ID:           "deliv-1",
		Type:         "deliver",
		To:           "bob",
		Payload:      "opaque-ciphertext-for-bob",
		OriginalType: "send",
		CircuitID:    "circ-123",
	}
	data, _ := json.Marshal(deliverPkt)
	if _, err := aliceConn.Write(append(data, '\n')); err != nil {
		t.Fatal(err)
	}

	// Bob should receive an opaque delivery envelope. The server never turns a
	// client-supplied subtype into an observable transport packet type.
	_ = bobConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	bobLine, err := bobReader.ReadString('\n')
	if err != nil {
		t.Fatalf("bob failed to receive delivered packet: %v", err)
	}
	var rcvPkt Packet
	if err := json.Unmarshal([]byte(bobLine), &rcvPkt); err != nil {
		t.Fatal(err)
	}
	if rcvPkt.Type != "deliver" || rcvPkt.Payload != "opaque-ciphertext-for-bob" {
		t.Fatalf("unexpected packet received by bob: %+v", rcvPkt)
	}
}

func TestHeartbeatClosesStaleConnection(t *testing.T) {
	ser, srvAddr, cleanup := startTestServer(t)
	defer cleanup()

	// Start heartbeat listener
	hbLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hbLn.Close()
	go ser.heartbeat_listener(hbLn)

	// Connect Alice primary
	aliceConn, err := net.Dial("tcp", srvAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer aliceConn.Close()
	if _, err := fmt.Fprintf(aliceConn, "alice\t127.0.0.1:4001\tpubkeyA\tidentA\n"); err != nil {
		t.Fatal(err)
	}

	// Connect Alice heartbeat
	hbConn, err := net.Dial("tcp", hbLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	regPkt := Packet{
		Version: protocolVersion,
		ID:      "hb-reg",
		Type:    "heartbeat",
		Payload: "alice",
	}
	regBytes, _ := json.Marshal(regPkt)
	if _, err := hbConn.Write(append(regBytes, '\n')); err != nil {
		t.Fatal(err)
	}

	// Wait for heartbeat registration
	time.Sleep(50 * time.Millisecond)
	ser.state_mu.RLock()
	if _, ok := ser.connections["alice"]; !ok {
		ser.state_mu.RUnlock()
		t.Fatal("alice not found in connections")
	}
	ser.state_mu.RUnlock()

	// Close heartbeat connection (simulating client drop)
	_ = hbConn.Close()

	// Wait for cleanup
	time.Sleep(100 * time.Millisecond)

	ser.state_mu.RLock()
	_, exists := ser.connections["alice"]
	ser.state_mu.RUnlock()

	if exists {
		t.Fatal("stale alice connection was not removed after heartbeat drop")
	}
}
