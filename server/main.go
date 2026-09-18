package main

import (
	"bufio"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	protocolVersion  uint8 = 1
	maxPacketBytes         = 64 * 1024
	maxPayloadBytes        = 48 * 1024
	maxUsernameBytes       = 32
	maxTTL                 = 8
	defaultTTL             = 5
)

type Packet struct {
	Version      uint8  `json:"version"`
	ID           string `json:"id"`
	CircuitID    string `json:"circuit_id,omitempty"`
	TTL          uint8  `json:"ttl,omitempty"`
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
	Identity  string `json:"identity"`
}

type Server struct {
	server_addr string
	listener    net.Listener
	clients     map[net.Addr]string
	connections map[string]net.Conn
	peerAddrs   map[string]string
	peerKeys    map[string]string
	identities  map[string]string
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
		identities:  make(map[string]string),
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
			return
		}
		ser.state_mu.Lock()
		ser.clients[client.RemoteAddr()] = "unknown"
		ser.state_mu.Unlock()

		go client_msg(ser, client)
	}
}

func client_msg(ser *Server, client net.Conn) {
	reader := bufio.NewReader(client)
	_ = client.SetReadDeadline(time.Now().Add(15 * time.Second))
	registration, err := reader.ReadString('\n')
	if err != nil {
		client.Close()
		return
	}
	parts := strings.SplitN(strings.TrimSpace(registration), "\t", 4)
	username := parts[0]
	if !validUsername(username) {
		_ = write_packet(client, Packet{Type: "error", Payload: "invalid username"})
		client.Close()
		return
	}
	peerAddr := ""
	peerKey := ""
	if len(parts) == 2 {
		peerAddr = parts[1]
	} else if len(parts) == 3 {
		peerAddr = parts[1]
		peerKey = parts[2]
	} else if len(parts) == 4 {
		peerAddr = parts[1]
		peerKey = parts[2]
		ser.state_mu.Lock()
		ser.identities[username] = parts[3]
		ser.state_mu.Unlock()
	}
	ser.state_mu.Lock()
	if _, exists := ser.connections[username]; exists {
		ser.state_mu.Unlock()
		_ = write_packet(client, Packet{Type: "error", Payload: "username already taken"})
		client.Close()
		return
	}
	ser.clients[client.RemoteAddr()] = username
	ser.connections[username] = client
	ser.peerAddrs[username] = peerAddr
	ser.peerKeys[username] = peerKey
	ser.state_mu.Unlock()
	println("[server] user registered:", username)
	ser.broadcast_users()
	defer func() {
		ser.state_mu.Lock()
		delete(ser.clients, client.RemoteAddr())
		delete(ser.connections, username)
		delete(ser.peerAddrs, username)
		delete(ser.peerKeys, username)
		delete(ser.identities, username)
		ser.state_mu.Unlock()
		println("[server] client disconnected:", username)
		ser.broadcast_users()
	}()

	for {
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Minute))
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
			println("[server] invalid packet")
			continue
		}
		if err := validatePacket(packet); err != nil {
			continue
		}
		println("[server] packet received from", username, "type", packet.Type)
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
			users = append(users, Peer{Username: username, Address: ser.peerAddrs[username], PublicKey: ser.peerKeys[username], Identity: ser.identities[username]})
		}
	}
	secureShuffle(users)
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
	if err := preparePacket(&packet); err != nil {
		return err
	}
	data, err := json.Marshal(packet)
	if err != nil {
		return err
	}
	serverWriteMu.Lock()
	defer serverWriteMu.Unlock()
	_ = client.SetWriteDeadline(time.Now().Add(15 * time.Second))
	println("[server] packet sent type", packet.Type)
	_, err = client.Write(append(data, '\n'))
	return err
}

func preparePacket(packet *Packet) error {
	if packet.Version == 0 {
		packet.Version = protocolVersion
	}
	if packet.Version != protocolVersion {
		return fmt.Errorf("unsupported protocol version")
	}
	if packet.ID == "" {
		id, err := randomID()
		if err != nil {
			return err
		}
		packet.ID = id
	}
	if packet.TTL == 0 {
		packet.TTL = defaultTTL
	}
	return validatePacket(*packet)
}

func validatePacket(packet Packet) error {
	if packet.Version != protocolVersion || packet.ID == "" || packet.Type == "" {
		return fmt.Errorf("invalid packet metadata")
	}
	if !validPacketType(packet.Type) {
		return fmt.Errorf("unknown packet type")
	}
	if packet.TTL > maxTTL || len(packet.Payload) > maxPayloadBytes || len(packet.To) > maxUsernameBytes {
		return fmt.Errorf("invalid packet limits")
	}
	return nil
}

func validPacketType(packetType string) bool {
	switch packetType {
	case "users", "waiting", "message", "session_offer", "session_reply", "onion", "deliver", "heartbeat", "error":
		return true
	default:
		return false
	}
}

func randomID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := crand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

var serverWriteMu sync.Mutex

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

func validUsername(username string) bool {
	if len(username) < 3 || len(username) > maxUsernameBytes {
		return false
	}
	for _, character := range username {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func main() {
	NewServer(":9000")
}
