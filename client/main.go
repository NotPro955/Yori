package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

func main() {
	server, err := net.Dial("tcp", "localhost:9000")
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()

	terminal := bufio.NewReader(os.Stdin)
	fmt.Print("Username: ")
	username, err := terminal.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	username = strings.TrimSpace(username)
	if username == "" {
		log.Fatal("username cannot be empty")
	}
	go startHeartbeat("localhost:9500", username)

	if _, err := fmt.Fprintln(server, username); err != nil {
		log.Fatal(err)
	}
	server_reader := bufio.NewReader(server)

	fmt.Println("Connected as", username)
	fmt.Println("Commands: /users, /quit")
	for {
		fmt.Print("> ")
		message, err := terminal.ReadString('\n')
		if err != nil {
			return
		}
		if strings.TrimSpace(message) == "/quit" {
			fmt.Fprintln(server, "quit")
			return
		}
		if strings.TrimSpace(message) == "/users" {
			if err := send_packet(server, Packet{Type: "users"}); err != nil {
				log.Println("send error:", err)
				return
			}
			response, err := server_reader.ReadString('\n')
			if err != nil {
				log.Println("receive error:", err)
				return
			}
			var packet Packet
			if err := json.Unmarshal([]byte(response), &packet); err != nil {
				log.Println("invalid server response:", err)
				continue
			}
			fmt.Println("Online users:", strings.Join(packet.Users, ", "))
			continue
		}
		if _, err := fmt.Fprint(server, message); err != nil {
			log.Println("send error:", err)
			return
		}
	}
}

type Packet struct {
	Type  string   `json:"type"`
	Users []string `json:"users,omitempty"`
}

func send_packet(server net.Conn, packet Packet) error {
	data, err := json.Marshal(packet)
	if err != nil {
		return err
	}
	_, err = server.Write(append(data, '\n'))
	return err
}
