package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func server_cli(ser *Server) {
	reader := bufio.NewScanner(os.Stdin)
	fmt.Println("Server CLI: users | heartbeat | logs | help | quit")
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
		case "logs":
			ser.streamLogs(reader)
		case "help":
			fmt.Println("users      list connected clients")
			fmt.Println("heartbeat  list active heartbeat clients")
			fmt.Println("logs       view server logs live (type 'q' to exit)")
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

// streamLogs prints all buffered log entries, then streams new ones live.
// Type 'q' and press Enter to return to the normal server prompt.
func (ser *Server) streamLogs(scanner *bufio.Scanner) {
	// Print everything captured so far.
	ser.logMu.Lock()
	for _, entry := range ser.logBuf {
		fmt.Println(entry)
	}
	// Subscribe for new entries.
	sub := make(chan string, 64)
	ser.logSubs = append(ser.logSubs, sub)
	ser.logMu.Unlock()

	fmt.Println("--- live logs (type 'q' + Enter to exit) ---")

	done := make(chan struct{})

	// Goroutine: print incoming log entries until done.
	go func() {
		for {
			select {
			case entry := <-sub:
				fmt.Println(entry)
			case <-done:
				return
			}
		}
	}()

	// Block on stdin; exit when user types 'q'.
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "q" {
			break
		}
	}

	close(done)

	// Unsubscribe.
	ser.logMu.Lock()
	for i, s := range ser.logSubs {
		if s == sub {
			ser.logSubs = append(ser.logSubs[:i], ser.logSubs[i+1:]...)
			break
		}
	}
	ser.logMu.Unlock()

	fmt.Println("--- exited logs ---")
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
		peerAddress := ser.peerAddrs[username]
		if peerAddress == "" {
			peerAddress = address.String()
		}
		fmt.Printf(" - %s (%s)\n", username, peerAddress)
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
