package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func server_cli(ser *Server) {
	reader := bufio.NewScanner(os.Stdin)
	fmt.Println("Server CLI: users | heartbeat | help | quit")
	for {
		fmt.Print("server> ")
		if !reader.Scan() {
			break
		}
		switch strings.TrimSpace(reader.Text()) {
		case "users":
			ser.print_users()
		case "heartbeat":
			ser.print_heartbeats()
		case "help":
			fmt.Println("users      list connected clients")
			fmt.Println("heartbeat  list active heartbeat clients")
			fmt.Println("quit       stop the server")
		case "quit":
			fmt.Println("stopping server")
			os.Exit(0)
		case "":
		default:
			fmt.Println("unknown command; use help")
		}
	}
	if err := reader.Err(); err != nil {
		fmt.Println("server CLI stopped:", err)
	}
}

func (ser *Server) print_users() {
	ser.state_mu.RLock()
	defer ser.state_mu.RUnlock()
	if len(ser.clients) == 0 {
		fmt.Println("users: none")
		return
	}
	fmt.Println("users:")
	for address, username := range ser.clients {
		fmt.Printf(" - %s (%s)\n", username, address)
	}
}

func (ser *Server) print_heartbeats() {
	ser.state_mu.RLock()
	defer ser.state_mu.RUnlock()
	if len(ser.heartbeats) == 0 {
		fmt.Println("heartbeat: none")
		return
	}
	fmt.Println("heartbeat:")
	for address, username := range ser.heartbeats {
		fmt.Printf(" - %s (%s)\n", username, address)
	}
}
