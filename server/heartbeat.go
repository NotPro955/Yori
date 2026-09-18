package main

import (
	"bufio"
	"encoding/json"
	"net"
	"strings"
	"time"
)

func heartbeat(ser *Server) {
	ln, err := net.Listen("tcp", ":9500")
	if err != nil {
		panic(err)
	}
	ser.heartbeat_listener(ln)
}

func (ser *Server) heartbeat_listener(ln net.Listener) {
	for {
		client, err := ln.Accept()

		if err != nil {
			return
		}
		reader := bufio.NewScanner(client)
		reader.Buffer(make([]byte, 256), maxPacketBytes)
		_ = client.SetReadDeadline(time.Now().Add(15 * time.Second))
		if !reader.Scan() {
			client.Close()
			continue
		}
		var registration Packet
		if err := json.Unmarshal(reader.Bytes(), &registration); err != nil || validatePacket(registration) != nil || registration.Type != "heartbeat" || registration.Payload == "" {
			client.Close()
			continue
		}
		username := strings.TrimSpace(registration.Payload)
		ser.state_mu.Lock()
		ser.heartbeats[client.RemoteAddr()] = username
		ser.state_mu.Unlock()

		go heartbeat_connection(ser, client, reader, username)
	}

}

func heartbeat_connection(ser *Server, client net.Conn, reader *bufio.Scanner, username string) {
	defer client.Close()
	defer func() {
		ser.state_mu.Lock()
		delete(ser.heartbeats, client.RemoteAddr())
		conn, exists := ser.connections[username]
		ser.state_mu.Unlock()
		if exists && conn != nil {
			_ = conn.Close()
		}
	}()
	for {
		_ = client.SetReadDeadline(time.Now().Add(15 * time.Second))
		if !reader.Scan() {
			break
		}
		var packet Packet
		if json.Unmarshal(reader.Bytes(), &packet) != nil || validatePacket(packet) != nil || packet.Type != "heartbeat" {
			break
		}
	}
	if reader.Err() != nil {
		return
	}
}
