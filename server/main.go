package main

import (
	"bufio"
	"encoding/json"
	"net"
	"strings"
	"sync"
)

type Packet struct {
	Type  string   `json:"type"`
	Users []string `json:"users,omitempty"`
}

type Server struct {
	server_addr string
	listener    net.Listener
	clients     map[net.Addr]string
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
	username, err := reader.ReadString('\n')
	if err != nil {
		client.Close()
		return
	}
	username = strings.TrimSpace(username)
	ser.state_mu.Lock()
	ser.clients[client.RemoteAddr()] = username
	ser.state_mu.Unlock()
	defer func() {
		ser.state_mu.Lock()
		delete(ser.clients, client.RemoteAddr())
		ser.state_mu.Unlock()
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
			continue
		}
		switch packet.Type {
		case "users":
			write_packet(client, Packet{Type: "users", Users: ser.user_list()})
		}
	}
}

func (ser *Server) user_list() []string {
	ser.state_mu.RLock()
	defer ser.state_mu.RUnlock()
	users := make([]string, 0, len(ser.clients))
	for _, username := range ser.clients {
		if username != "unknown" {
			users = append(users, username)
		}
	}
	return users
}

func write_packet(client net.Conn, packet Packet) error {
	data, err := json.Marshal(packet)
	if err != nil {
		return err
	}
	_, err = client.Write(append(data, '\n'))
	return err
}

func main() {
	NewServer(":9000")
}
