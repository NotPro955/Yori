package main

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func readDelivery(t *testing.T, ws *websocket.Conn) Packet {
	t.Helper()
	_ = ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		var packet Packet
		if err := ws.ReadJSON(&packet); err != nil {
			t.Fatalf("failed to read delivery: %v", err)
		}
		if packet.Type == "deliver" {
			return packet
		}
	}
}

func TestWebSocketRegistrationAndDelivery(t *testing.T) {
	ser, addr, cleanup := startTestServer(t)
	defer cleanup()

	// Ensure HTTP listener is started
	u := url.URL{Scheme: "ws", Host: addr, Path: "/ws"}

	// Connect Alice via WebSocket
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	wsAlice, respAlice, err := dialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("failed to connect alice via WS: %v", err)
	}
	defer wsAlice.Close()
	if respAlice.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("unexpected status code: %d", respAlice.StatusCode)
	}

	// Alice registers
	regAlice := wsRegisterPayload{
		Type:           "register",
		Username:       "alice",
		RelayPublicKey: "relay-public-key-alice",
	}
	if err := wsAlice.WriteJSON(regAlice); err != nil {
		t.Fatalf("alice failed to send registration: %v", err)
	}

	// Alice should receive initial users packet
	var pktAlice Packet
	if err := wsAlice.ReadJSON(&pktAlice); err != nil {
		t.Fatalf("alice failed to read initial users packet: %v", err)
	}
	if pktAlice.Type != "users" {
		t.Fatalf("expected users packet, got %s", pktAlice.Type)
	}

	// Connect Bob via WebSocket
	wsBob, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("failed to connect bob via WS: %v", err)
	}
	defer wsBob.Close()

	regBob := wsRegisterPayload{
		Type:     "register",
		Username: "bob",
	}
	if err := wsBob.WriteJSON(regBob); err != nil {
		t.Fatalf("bob failed to send registration: %v", err)
	}

	// Bob receives initial users packet containing Alice
	var pktBob Packet
	if err := wsBob.ReadJSON(&pktBob); err != nil {
		t.Fatalf("bob failed to read initial users packet: %v", err)
	}
	if pktBob.Type != "users" {
		t.Fatalf("expected users packet, got %s", pktBob.Type)
	}

	// The server distributes only Alice's relay public key. Her identity and
	// externally exchanged pre-session key must never appear in peer discovery.
	foundAlice := false
	for _, u := range pktBob.Users {
		if u.Username == "alice" && u.PublicKey == "relay-public-key-alice" && u.PreSessionPub == "" && u.Identity == "" {
			foundAlice = true
			break
		}
	}
	if !foundAlice {
		t.Fatalf("bob users list did not contain alice without key material: %+v", pktBob.Users)
	}

	// Alice sends deliver packet to Bob
	delivPkt := Packet{
		Version: protocolVersion,
		ID:      "msg-ws-1",
		Type:    "deliver",
		To:      "bob",
		Payload: "opaque-test-payload",
	}
	if err := wsAlice.WriteJSON(delivPkt); err != nil {
		t.Fatalf("alice failed to send deliver: %v", err)
	}

	// Bob reads delivered packet (skipping any broadcast users packet)
	var rcvBob Packet
	_ = wsBob.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		if err := wsBob.ReadJSON(&rcvBob); err != nil {
			t.Fatalf("bob failed to read delivered packet: %v", err)
		}
		if rcvBob.Type == "deliver" {
			break
		}
	}
	if rcvBob.Payload != "opaque-test-payload" {
		t.Fatalf("bob received unexpected payload: %+v", rcvBob)
	}
	_ = ser
}

// TestWebSocketFourPeerRelayChain demonstrates the server's role in an onion
// route: it forwards opaque payloads hop-by-hop and never needs to inspect
// their contents. Browser clients perform the actual layer encryption.
func TestWebSocketFourPeerRelayChain(t *testing.T) {
	_, addr, cleanup := startTestServer(t)
	defer cleanup()

	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	u := url.URL{Scheme: "ws", Host: addr, Path: "/ws"}

	connect := func(username string) *websocket.Conn {
		t.Helper()
		ws, _, err := dialer.Dial(u.String(), nil)
		if err != nil {
			t.Fatalf("connect %s: %v", username, err)
		}
		t.Cleanup(func() { _ = ws.Close() })
		if err := ws.WriteJSON(wsRegisterPayload{Type: "register", Username: username}); err != nil {
			t.Fatalf("register %s: %v", username, err)
		}
		return ws
	}

	alice := connect("alice")
	john := connect("john")
	dave := connect("dave")
	notpro := connect("notpro")

	forward := func(from *websocket.Conn, to string, payload string) {
		t.Helper()
		if err := from.WriteJSON(Packet{Version: protocolVersion, ID: "demo-" + to, Type: "deliver", To: to, Payload: payload}); err != nil {
			t.Fatalf("send to %s: %v", to, err)
		}
	}

	const opaqueLayer = "opaque-onion-layer"
	forward(alice, "john", opaqueLayer)
	if packet := readDelivery(t, john); packet.Payload != opaqueLayer {
		t.Fatalf("john received wrong payload: %+v", packet)
	}
	t.Log("alice -> john: opaque layer forwarded")

	forward(john, "dave", opaqueLayer)
	if packet := readDelivery(t, dave); packet.Payload != opaqueLayer {
		t.Fatalf("dave received wrong payload: %+v", packet)
	}
	t.Log("john -> dave: opaque layer forwarded")

	forward(dave, "notpro", opaqueLayer)
	if packet := readDelivery(t, notpro); packet.Payload != opaqueLayer {
		t.Fatalf("notpro received wrong payload: %+v", packet)
	}
	t.Log("dave -> notpro: opaque layer forwarded")
}
