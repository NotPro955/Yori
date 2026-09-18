package main

import (
	"bufio"
	"crypto/ecdh"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

func startPeerListener(state *clientState, server net.Conn) (string, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return "", err
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handlePeerConnection(conn, state, server)
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	host := "127.0.0.1"
	if serverHost, _, err := net.SplitHostPort(server.RemoteAddr().String()); err == nil && serverHost != "127.0.0.1" && serverHost != "::1" {
		connection, err := net.Dial("udp", net.JoinHostPort(serverHost, "9"))
		if err == nil {
			if local, ok := connection.LocalAddr().(*net.UDPAddr); ok {
				host = local.IP.String()
			}
			connection.Close()
		}
	}
	return net.JoinHostPort(host, fmt.Sprint(port)), nil
}

func handlePeerConnection(conn net.Conn, state *clientState, server net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		return
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	var packet Packet
	if err := json.Unmarshal([]byte(line), &packet); err != nil || packet.Type != "onion" {
		return
	}
	if err := validatePacket(packet); err != nil {
		return
	}
	envelope, err := decryptOnionLayer(state, packet.Payload)
	if err != nil {
		fmt.Println("onion decrypt error:", err)
		return
	}
	if envelope.Version != protocolVersion || envelope.CircuitID == "" || envelope.TTL == 0 {
		return
	}
	envelope.TTL--
	delay, err := crand.Int(crand.Reader, big.NewInt(451))
	if err != nil {
		return
	}
	time.Sleep(time.Duration(delay.Int64()+50) * time.Millisecond)
	if envelope.TTL == 0 && envelope.Next != state.serverAddr {
		fmt.Println("[relay] onion packet dropped: TTL expired")
		return
	}
	if envelope.Next == state.serverAddr {
		if envelope.To == "" || envelope.Payload == "" {
			fmt.Println("[relay] delivery error: missing destination or payload")
			return
		}
		if err := send_packet(server, Packet{Type: "deliver", To: envelope.To, Payload: envelope.Payload, PublicKey: envelope.PublicKey, OriginalType: envelope.Type, CircuitID: envelope.CircuitID}); err != nil {
			fmt.Println("server delivery error:", err)
		}
		return
	}
	if err := directSend(envelope.Next, state.username, Packet{Type: "onion", Payload: envelope.Payload}); err != nil {
		fmt.Println("peer forwarding error:", err)
	}
}

func directSendToUser(state *clientState, username string, packet Packet) error {
	for attempt := 0; attempt < 2; attempt++ {
		state.mu.RLock()
		peers := make(map[string]Peer, len(state.peers))
		for name, peer := range state.peers {
			peers[name] = peer
		}
		serverAddr := state.serverAddr
		state.mu.RUnlock()
		route := chooseRoute(peers, state.username, username)
		if len(route) > 0 {
			onion, circuitID, err := buildOnion(route, serverAddr, username, packet.Type, packet.Payload, packet.PublicKey)
			if err != nil {
				return err
			}
			hopNames := make([]string, len(route))
			for i, p := range route {
				hopNames[i] = p.Username
			}
			shortID := circuitID
			if len(shortID) > 8 {
				shortID = shortID[:8]
			}
			fmt.Printf("Circuit established\nRoute: %s → %s → %s\nCircuit ID: %s\n",
				state.username, strings.Join(hopNames, " → "), username, shortID)
			return directSend(route[0].Address, state.username, Packet{Type: "onion", Payload: onion})
		}
		if attempt == 0 {
			select {
			case <-state.peerUpdates:
			case <-time.After(2 * time.Second):
			}
		}
	}
	// Fallback: no onion route available (fewer than 2 relay peers online).
	// Deliver directly through the server connection. Less private but functional.
	state.mu.RLock()
	serverConn := state.serverConn
	state.mu.RUnlock()
	if serverConn != nil {
		fmt.Println("[warn] not enough relay peers for onion routing; delivering directly through server")
		return send_packet(serverConn, Packet{
			Type:         "deliver",
			To:           username,
			Payload:      packet.Payload,
			PublicKey:    packet.PublicKey,
			OriginalType: packet.Type,
		})
	}
	return fmt.Errorf("no fellow peer address is available")
}

func chooseRoute(peers map[string]Peer, sender, recipient string) []Peer {
	candidates := make([]Peer, 0, len(peers))
	for name, peer := range peers {
		if name != sender && name != recipient && peer.Address != "" && peer.PublicKey != "" {
			candidates = append(candidates, peer)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	secureShuffle(candidates)
	routeLength := 2
	if len(candidates) > 5 {
		routeLength = 5
	}
	if routeLength > len(candidates) {
		routeLength = len(candidates)
	}
	if routeLength < 2 {
		return nil
	}
	return candidates[:routeLength]
}

func buildOnion(route []Peer, serverAddr, recipient, packetType, payload, publicKey string) (string, string, error) {
	next := serverAddr
	inner := payload
	circuitID, err := randomID()
	if err != nil {
		return "", "", err
	}
	for index := len(route) - 1; index >= 0; index-- {
		envelope := onionEnvelope{Version: protocolVersion, CircuitID: circuitID, TTL: uint8(len(route) - index), Next: next, Payload: inner}
		if next == serverAddr {
			envelope.To = recipient
			envelope.Type = packetType
			envelope.PublicKey = publicKey
		}
		envelopeBytes, err := json.Marshal(envelope)
		if err != nil {
			return "", "", err
		}
		inner, err = encryptOnionLayer(route[index].PublicKey, envelopeBytes)
		if err != nil {
			return "", "", err
		}
		next = route[index].Address
	}
	return inner, circuitID, nil
}

func secureShuffle(peers []Peer) {
	for index := len(peers) - 1; index > 0; index-- {
		value, err := crand.Int(crand.Reader, big.NewInt(int64(index+1)))
		if err != nil {
			return
		}
		other := int(value.Int64())
		peers[index], peers[other] = peers[other], peers[index]
	}
}

func directSend(address, username string, packet Packet) error {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintln(conn, username); err != nil {
		return err
	}
	if err := preparePacket(&packet); err != nil {
		return err
	}
	data, err := json.Marshal(packet)
	if err != nil {
		return err
	}
	_, err = conn.Write(append(data, '\n'))
	return err
}

func relayPublicKey(state *clientState) (string, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.relayKey == nil {
		key, err := ecdh.X25519().GenerateKey(crand.Reader)
		if err != nil {
			return "", err
		}
		state.relayKey = key
	}
	return base64.RawStdEncoding.EncodeToString(state.relayKey.PublicKey().Bytes()), nil
}
