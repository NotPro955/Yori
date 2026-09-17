package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	mrand "math/rand"
	"net"
	"strings"
)

func chat_session(terminal *bufio.Reader, server net.Conn, state *clientState, username, recipient string, key []byte) bool {
	fmt.Println("Chatting with", recipient, "(type /back to return)")
	for {
		fmt.Print("Message: ")
		body, err := terminal.ReadString('\n')
		if err != nil {
			return false
		}
		body = strings.TrimSpace(body)
		if body == "/back" {
			return true
		}
		if body == "/quit" {
			fmt.Fprintln(server, "quit")
			return false
		}
		if body == "" {
			continue
		}

		envelope, err := json.Marshal(chatEnvelope{Sender: username, Body: body})
		if err != nil {
			log.Println("message encoding error:", err)
			continue
		}
		ciphertext, err := encryptBytes(key, envelope)
		if err != nil {
			log.Println("encrypt error:", err)
			continue
		}
		hops := mrand.Intn(3) + 3
		if err := directSendToUser(state, recipient, Packet{Type: "send", To: recipient, Payload: ciphertext, Hops: hops}); err != nil {
			log.Println("direct send error:", err)
			return false
		}
		fmt.Println("sent via", hops, "hops")
	}
}
