package main

import (
	"bufio"
	"encoding/json"
	mrand "math/rand"
	"net"
	"strings"
	"sync"
)

type Packet struct {
	Type         string `json:"type"`
	To           string `json:"to,omitempty"`
	Payload      string `json:"payload,omitempty"`
	PublicKey    string `json:"public_key,omitempty"`
	OriginalType string `json:"original_type,omitempty"`
	Users        []Peer `json:"users,omitempty"`
}

type Peer struct {
	Username  string `json:"username"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
}

type Server struct {
	server_addr string
	listener    net.Listener
	clients     map[net.Addr]string
	connections map[string]net.Conn
	peerAddrs   map[string]string
	peerKeys    map[string]string
	heartbeats  map[net.Addr]string
	state_mu    sync.RWMutex
}

func NewServer(server_addr string) {
	ln, err := net.Listen("tcp", server_addr)
	if err != nil {
		panic(err)
	}

	ser := &Server{
		server_addr: server_addr,
		listener:    ln,
		clients:     make(map[net.Addr]string),
		connections: make(map[string]net.Conn),
		peerAddrs:   make(map[string]string),
		peerKeys:    make(map[string]string),
		heartbeats:  make(map[net.Addr]string),
	}
	go heartbeat(ser)
	go server_cli(ser)
	ser.accept()
}

func (ser *Server) accept() {
	for {
		client, err := ser.listener.Accept()
		if err != nil {
			continue
		}
		ser.state_mu.Lock()
		ser.clients[client.RemoteAddr()] = "unknown"
		ser.state_mu.Unlock()

		go client_msg(ser, client)
	}
}

func client_msg(ser *Server, client net.Conn) {
	reader := bufio.NewReader(client)
	registration, err := reader.ReadString('\n')
	if err != nil {
		client.Close()
		return
	}
	parts := strings.SplitN(strings.TrimSpace(registration), "\t", 3)
	username := parts[0]
	peerAddr := ""
	peerKey := ""
	if len(parts) == 2 {
		peerAddr = parts[1]
	} else if len(parts) == 3 {
		peerAddr = parts[1]
		peerKey = parts[2]
	}
	ser.state_mu.Lock()
	ser.clients[client.RemoteAddr()] = username
	ser.connections[username] = client
	ser.peerAddrs[username] = peerAddr
	ser.peerKeys[username] = peerKey
	ser.state_mu.Unlock()
	ser.broadcast_users()
	defer func() {
		ser.state_mu.Lock()
		delete(ser.clients, client.RemoteAddr())
		delete(ser.connections, username)
		delete(ser.peerAddrs, username)
		delete(ser.peerKeys, username)
		ser.state_mu.Unlock()
		ser.broadcast_users()
	}()

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.TrimSpace(line) == "quit" {
			client.Close()
			break
		}

		var packet Packet
		if err := json.Unmarshal([]byte(line), &packet); err != nil {
			println("[server raw] invalid packet from", client.RemoteAddr().String(), ":", strings.TrimSpace(line))
			continue
		}
		println("[server packet] from", username, "to server payload", packet.Payload)
		switch packet.Type {
		case "users":
			write_packet(client, Packet{Type: "users", Users: ser.user_list(username)})
		case "deliver":
			ser.deliver(client, username, packet)
		}
	}
}

func (ser *Server) deliver(sender net.Conn, current string, packet Packet) {
	if packet.To == "" || packet.Payload == "" {
		write_packet(sender, Packet{Type: "error", Payload: "invalid message route"})
		return
	}

	ser.state_mu.RLock()
	peerConn, ok := ser.connections[packet.To]
	if !ok || peerConn == nil {
		ser.state_mu.RUnlock()
		write_packet(sender, Packet{Type: "waiting", To: packet.To, Payload: "waiting for peer"})
		return
	}
	ser.state_mu.RUnlock()
	deliveryType := packet.OriginalType
	if deliveryType == "" {
		deliveryType = packet.Type
	}
	if deliveryType == "send" {
		deliveryType = "message"
	}
	if err := write_packet(peerConn, Packet{Type: deliveryType, Payload: packet.Payload, PublicKey: packet.PublicKey}); err != nil {
		write_packet(sender, Packet{Type: "error", Payload: "delivery failed"})
	}
}

func (ser *Server) user_list(exclude string) []Peer {
	ser.state_mu.RLock()
	defer ser.state_mu.RUnlock()
	users := make([]Peer, 0, len(ser.clients))
	for _, username := range ser.clients {
		if username != "unknown" && username != exclude && ser.peerAddrs[username] != "" && ser.peerKeys[username] != "" {
			users = append(users, Peer{Username: username, Address: ser.peerAddrs[username], PublicKey: ser.peerKeys[username]})
		}
	}
	mrand.Shuffle(len(users), func(i, j int) { users[i], users[j] = users[j], users[i] })
	if len(users) > 3 {
		users = users[:3]
	}
	return users
}

func (ser *Server) broadcast_users() {
	ser.state_mu.RLock()
	connections := make(map[string]net.Conn, len(ser.connections))
	for username, connection := range ser.connections {
		connections[username] = connection
	}
	ser.state_mu.RUnlock()

	for username, connection := range connections {
		_ = write_packet(connection, Packet{Type: "users", Users: ser.user_list(username)})
	}
}

func write_packet(client net.Conn, packet Packet) error {
	data, err := json.Marshal(packet)
	if err != nil {
		return err
	}
	serverWriteMu.Lock()
	defer serverWriteMu.Unlock()
	println("[server packet] from server to", client.RemoteAddr().String(), "payload", packet.Payload)
	_, err = client.Write(append(data, '\n'))
	return err
}

var serverWriteMu sync.Mutex

func main() {
	NewServer(":9000")
}
