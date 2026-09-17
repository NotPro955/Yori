package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"net"
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
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		return
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		var packet Packet
		if err := json.Unmarshal([]byte(line), &packet); err != nil {
			continue
		}
		if packet.Hops <= 0 {
			packet.OriginalType = packet.Type
			packet.Type = "deliver"
			packet.Next = ""
			if err := send_packet(server, packet); err != nil {
				fmt.Println("server delivery error:", err)
			}
			return
		}
		if err := forwardToPeer(state, packet); err != nil {
			fmt.Println("peer forwarding error:", err)
		}
	}
}

func directSendToUser(state *clientState, username string, packet Packet) error {
	for attempt := 0; attempt < 2; attempt++ {
		state.mu.RLock()
		candidates := make([]Peer, 0, len(state.peers))
		for _, peer := range state.peers {
			if peer.Address != "" && peer.Username != username && peer.Username != state.username {
				candidates = append(candidates, peer)
			}
		}
		state.mu.RUnlock()
		if len(candidates) > 0 {
			nextAddress := candidates[mrand.Intn(len(candidates))].Address
			packet.Next = nextAddress
			return directSend(nextAddress, state.username, packet)
		}
		if attempt == 0 {
			select {
			case <-state.peerUpdates:
			case <-time.After(2 * time.Second):
			}
		}
	}
	return fmt.Errorf("no fellow peer address is available")
}

func forwardToPeer(state *clientState, packet Packet) error {
	state.mu.RLock()
	peers := make([]Peer, 0, len(state.peers))
	for _, peer := range state.peers {
		if peer.Address != "" && peer.Address != packet.Next && peer.Username != packet.To && peer.Username != state.username {
			peers = append(peers, peer)
		}
	}
	state.mu.RUnlock()
	if len(peers) == 0 {
		return fmt.Errorf("no peer available for next hop")
	}
	peer := peers[0]
	packet.Hops--
	packet.Next = peer.Address
	return directSend(peer.Address, state.username, packet)
}

func directSend(address, username string, packet Packet) error {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := fmt.Fprintln(conn, username); err != nil {
		return err
	}
	data, err := json.Marshal(packet)
	if err != nil {
		return err
	}
	_, err = conn.Write(append(data, '\n'))
	return err
}
